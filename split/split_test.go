package split

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

func TestSplitLinkDeliversInBothDirections(t *testing.T) {
	localDeliveries := make(chan SendRequest, 1)
	remoteDeliveries := make(chan SendRequest, 1)
	server, client := startTestSplitPair(t, func(_ context.Context, req SendRequest) error {
		localDeliveries <- req
		return nil
	}, func(_ context.Context, req SendRequest) error {
		remoteDeliveries <- req
		return nil
	})

	req := SendRequest{From: "sender@example.test", Recipient: "recipient@example.test", Data: []byte("message")}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Send(ctx, req); err != nil {
		t.Fatalf("client Send() error = %v", err)
	}
	assertSendRequest(t, receiveSendRequest(t, localDeliveries), req)

	if err := server.Send(ctx, req); err != nil {
		t.Fatalf("server Send() error = %v", err)
	}
	assertSendRequest(t, receiveSendRequest(t, remoteDeliveries), req)
}

func TestSplitLinkWithoutClientDeliveryHandlerReturnsError(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	server, _ := startTestSplitPair(t, func(context.Context, SendRequest) error { return nil }, nil, logger)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := server.Send(ctx, SendRequest{
		From:      "sender@example.test",
		Recipient: "recipient@example.test",
		Data:      []byte("message"),
	})
	if err == nil || !strings.Contains(err.Error(), "no delivery handler") {
		t.Fatalf("server Send() error = %v, want no delivery handler", err)
	}
	if got := logs.String(); !strings.Contains(got, `msg="split SendMail sent"`) || !strings.Contains(got, `msg="split SendMail failed"`) || !strings.Contains(got, "stream=1") {
		t.Fatalf("split SendMail logs missing sent/failure stream details: %s", got)
	}
}

func TestSplitSendLogsAcknowledgement(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	_, client := startTestSplitPair(t, func(context.Context, SendRequest) error { return nil }, nil, logger)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req := SendRequest{From: "sender@example.test", Recipient: "recipient@example.test", Data: []byte("message")}
	if err := client.Send(ctx, req); err != nil {
		t.Fatalf("client Send() error = %v", err)
	}
	if got := logs.String(); !strings.Contains(got, `msg="split SendMail sent"`) || !strings.Contains(got, `msg="split SendMail acknowledged"`) || !strings.Contains(got, "stream=1") || !strings.Contains(got, "to=recipient@example.test") {
		t.Fatalf("split SendMail logs missing sent/acknowledged stream details: %s", got)
	}
}

func TestSplitAuthenticate(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	server, _ := startTestSplitPairWithCallbacks(t,
		func(context.Context, SendRequest) error { return nil },
		func(context.Context, SendRequest) error { return nil },
		nil,
		func(_ context.Context, username, password string) (bool, error) {
			return username == "alice@example.test" && password == "secret", nil
		},
		logger,
	)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ok, err := server.Authenticate(ctx, "alice@example.test", "secret")
	if err != nil || !ok {
		t.Fatalf("Authenticate(valid) = %t, %v; want true, nil; logs: %s", ok, err, logs.String())
	}
	if ok, err := server.Authenticate(ctx, "alice@example.test", "wrong"); ok || !errors.Is(err, ErrAuthRejected) {
		t.Fatalf("Authenticate(invalid) = %t, %v; want false, ErrAuthRejected", ok, err)
	}
}

func TestSplitAuthenticateWithoutConnection(t *testing.T) {
	if ok, err := (&Server{}).Authenticate(context.Background(), "alice@example.test", "secret"); ok || err == nil {
		t.Fatalf("Authenticate() without connection = %t, %v; want false and an error", ok, err)
	}
}

func TestSplitSubmitDispatchesAndPropagatesHandlerError(t *testing.T) {
	requests := make(chan SendRequest, 2)
	handlerErr := error(nil)
	server, _ := startTestSplitPairWithCallbacks(t,
		func(context.Context, SendRequest) error { return nil },
		func(context.Context, SendRequest) error { return nil },
		func(_ context.Context, req SendRequest) error {
			requests <- req
			return handlerErr
		},
		nil,
	)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req := SendRequest{From: "alice@example.test", Recipient: "bob@outside.test", Data: []byte("Subject: test\r\n\r\nbody")}

	if err := server.Submit(ctx, req); err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	assertSendRequest(t, receiveSendRequest(t, requests), req)

	handlerErr = errors.New("submission failed")
	if err := server.Submit(ctx, req); err == nil || !strings.Contains(err.Error(), handlerErr.Error()) {
		t.Fatalf("Submit() error = %v, want %q", err, handlerErr)
	}
	assertSendRequest(t, receiveSendRequest(t, requests), req)
}

func TestSplitSubmitWithoutConnection(t *testing.T) {
	err := (&Server{}).Submit(context.Background(), SendRequest{Recipient: "bob@outside.test"})
	if err == nil {
		t.Fatal("Submit() without connection succeeded, want an error")
	}
}

func startTestSplitPair(t *testing.T, serverDeliver, clientDeliver func(context.Context, SendRequest) error, loggers ...*slog.Logger) (*Server, *Client) {
	return startTestSplitPairWithCallbacks(t, serverDeliver, clientDeliver, nil, nil, loggers...)
}

func startTestSplitPairWithCallbacks(t *testing.T, serverDeliver, clientDeliver func(context.Context, SendRequest) error, clientSubmit func(context.Context, SendRequest) error, clientAuthenticate func(context.Context, string, string) (bool, error), loggers ...*slog.Logger) (*Server, *Client) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}

	certificate := testSplitCertificate(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if len(loggers) > 0 {
		logger = loggers[0]
	}
	ready := make(chan struct{}, 1)
	serverConnected := make(chan struct{}, 1)
	server := &Server{
		Addr:        addr,
		TLSConfig:   &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12},
		Logger:      logger,
		OnReady:     func() { ready <- struct{}{} },
		OnConnected: func() { serverConnected <- struct{}{} },
		Deliver:     serverDeliver,
	}
	ctx, cancel := context.WithCancel(context.Background())
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.ListenAndServe(ctx) }()
	select {
	case <-ready:
	case err := <-serverDone:
		cancel()
		t.Fatalf("split server stopped before ready: %v", err)
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("timed out waiting for split server")
	}

	connected := make(chan struct{}, 1)
	client := &Client{
		Addr:         addr,
		TLSConfig:    &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
		Logger:       logger,
		Deliver:      clientDeliver,
		Submit:       clientSubmit,
		Authenticate: clientAuthenticate,
		OnConnected: func() {
			connected <- struct{}{}
		},
	}
	client.Start(ctx)
	select {
	case <-serverConnected:
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("timed out waiting for split client connection")
	}
	select {
	case <-connected:
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("timed out waiting for split server connection")
	}

	t.Cleanup(func() {
		cancel()
		clientDone := make(chan struct{})
		go func() {
			client.Wait()
			close(clientDone)
		}()
		select {
		case <-clientDone:
		case <-time.After(5 * time.Second):
			t.Error("split client did not stop")
		}
		select {
		case err := <-serverDone:
			if err != nil {
				t.Errorf("split server stopped with error: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("split server did not stop")
		}
	})
	return server, client
}

func testSplitCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "split-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	privateDER := x509.MarshalPKCS1PrivateKey(privateKey)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privateDER})
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func receiveSendRequest(t *testing.T, requests <-chan SendRequest) SendRequest {
	t.Helper()
	select {
	case req := <-requests:
		return req
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for delivered message")
		return SendRequest{}
	}
}

func assertSendRequest(t *testing.T, got, want SendRequest) {
	t.Helper()
	if got.From != want.From || got.Recipient != want.Recipient || !bytes.Equal(got.Data, want.Data) {
		t.Fatalf("delivered request = %#v, want %#v", got, want)
	}
}
