package split

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"log/slog"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSplitTLSHandshakeExplainsRejectedServerCertificate(t *testing.T) {
	serverCA := newSplitTestCA(t, "server-ca")
	clientCA := newSplitTestCA(t, "untrusted-ca")
	serverCertificate := issueSplitTestCertificate(t, serverCA, "split-server", []string{"split.example.test"}, x509.ExtKeyUsageServerAuth)
	serverTLS := &tls.Config{Certificates: []tls.Certificate{serverCertificate}, MinVersion: tls.VersionTLS12}
	logs := &lockedTestBuffer{}
	server := startTLSTestServer(t, serverTLS, slog.New(slog.NewTextHandler(logs, nil)), "")

	client := &Client{
		Addr: server.addr,
		TLSConfig: &tls.Config{
			RootCAs:    clientCA.pool,
			ServerName: "split.example.test",
			MinVersion: tls.VersionTLS12,
		},
		Logger: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
	}
	_, _, err := client.dialAndHandshake(context.Background())
	if err == nil {
		t.Fatal("dialAndHandshake() succeeded with an untrusted server certificate")
	}
	if !strings.Contains(err.Error(), "not signed by a trusted CA") || !strings.Contains(err.Error(), "split_ca_cert_file") {
		t.Fatalf("client TLS error lacks actionable trust guidance: %v", err)
	}
	log := waitForTestLog(t, logs, "split TLS handshake failed")
	if !strings.Contains(log, "peer rejected this server's certificate") || !strings.Contains(log, `server_certificate_subject="CN=split-server"`) {
		t.Fatalf("server TLS log lacks peer explanation or server certificate details: %s", log)
	}
}

func TestSplitTLSHandshakeExplainsRejectedClientCertificate(t *testing.T) {
	serverCA := newSplitTestCA(t, "server-ca")
	untrustedCA := newSplitTestCA(t, "server-ca")
	serverCertificate := issueSplitTestCertificate(t, serverCA, "split-server", []string{"split.example.test"}, x509.ExtKeyUsageServerAuth)
	clientCertificate := issueSplitTestCertificate(t, untrustedCA, "untrusted-client", nil, x509.ExtKeyUsageClientAuth)
	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{serverCertificate},
		ClientCAs:    serverCA.pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}
	logs := &lockedTestBuffer{}
	server := startTLSTestServer(t, serverTLS, slog.New(slog.NewTextHandler(logs, nil)), "")

	client := &Client{
		Addr: server.addr,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{clientCertificate},
			RootCAs:      serverCA.pool,
			ServerName:   "split.example.test",
			MinVersion:   tls.VersionTLS12,
		},
		Logger: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
	}
	_, _, err := client.dialAndHandshake(context.Background())
	if err == nil {
		t.Fatal("dialAndHandshake() succeeded with an untrusted client certificate")
	}
	log := waitForTestLog(t, logs, "split TLS handshake failed")
	if !strings.Contains(log, "client's certificate failed verification") || !strings.Contains(log, `client_certificate_subject="CN=untrusted-client"`) {
		t.Fatalf("server TLS log lacks client-certificate diagnosis or peer details: %s", log)
	}
}

func TestSplitTLSClientExplainsHostnameMismatch(t *testing.T) {
	serverCA := newSplitTestCA(t, "server-ca")
	serverCertificate := issueSplitTestCertificate(t, serverCA, "split-server", []string{"split.example.test"}, x509.ExtKeyUsageServerAuth)
	server := startTLSTestServer(t,
		&tls.Config{Certificates: []tls.Certificate{serverCertificate}, MinVersion: tls.VersionTLS12},
		slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)), "")

	client := &Client{
		Addr: server.addr,
		TLSConfig: &tls.Config{
			RootCAs:    serverCA.pool,
			ServerName: "wrong.example.test",
			MinVersion: tls.VersionTLS12,
		},
		Logger: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
	}
	_, _, err := client.dialAndHandshake(context.Background())
	if err == nil {
		t.Fatal("dialAndHandshake() succeeded with a mismatched server hostname")
	}
	if !strings.Contains(err.Error(), `split_connect host "wrong.example.test"`) || !strings.Contains(err.Error(), "split.example.test") {
		t.Fatalf("client TLS error lacks hostname and certificate DNS names: %v", err)
	}
}

func TestSplitTLSClientCanIgnoreServerName(t *testing.T) {
	ca := newSplitTestCA(t, "server-ca")
	serverCertificate := issueSplitTestCertificate(t, ca, "split-server", []string{"split.example.test"}, x509.ExtKeyUsageServerAuth)
	server := startTLSTestServer(t,
		&tls.Config{Certificates: []tls.Certificate{serverCertificate}, MinVersion: tls.VersionTLS12},
		slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)), "")

	client := &Client{
		Addr: server.addr,
		TLSConfig: &tls.Config{
			RootCAs:    ca.pool,
			ServerName: "wrong.example.test",
			MinVersion: tls.VersionTLS12,
		},
		IgnoreServerName: true,
		Logger:           slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
	}
	conn, _, err := client.dialAndHandshake(context.Background())
	if err != nil {
		t.Fatalf("dialAndHandshake() with IgnoreServerName failed: %v", err)
	}
	defer conn.Close()
}

func TestSplitTLSClientIgnoringServerNameStillVerifiesTrust(t *testing.T) {
	serverCA := newSplitTestCA(t, "server-ca")
	untrustedCA := newSplitTestCA(t, "untrusted-ca")
	serverCertificate := issueSplitTestCertificate(t, serverCA, "split-server", []string{"split.example.test"}, x509.ExtKeyUsageServerAuth)
	server := startTLSTestServer(t,
		&tls.Config{Certificates: []tls.Certificate{serverCertificate}, MinVersion: tls.VersionTLS12},
		slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)), "")

	client := &Client{
		Addr: server.addr,
		TLSConfig: &tls.Config{
			RootCAs:    untrustedCA.pool,
			ServerName: "wrong.example.test",
			MinVersion: tls.VersionTLS12,
		},
		IgnoreServerName: true,
		Logger:           slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
	}
	_, _, err := client.dialAndHandshake(context.Background())
	if err == nil {
		t.Fatal("dialAndHandshake() succeeded with an untrusted server certificate")
	}
	if !strings.Contains(err.Error(), "not signed by a trusted CA") || !strings.Contains(err.Error(), "split_ca_cert_file") {
		t.Fatalf("client TLS error lacks actionable trust guidance: %v", err)
	}
}

func TestSplitExpectedClientDNCheckedAfterTLSHandshake(t *testing.T) {
	ca := newSplitTestCA(t, "split-ca")
	serverCertificate := issueSplitTestCertificate(t, ca, "split-server", []string{"split.example.test"}, x509.ExtKeyUsageServerAuth)
	clientCertificate := issueSplitTestCertificate(t, ca, "split-client", nil, x509.ExtKeyUsageClientAuth)
	connected := make(chan struct{}, 1)
	server := startTLSTestServer(t, &tls.Config{
		Certificates: []tls.Certificate{serverCertificate},
		ClientCAs:    ca.pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)), clientCertificate.Leaf.Subject.String(), func() {
		connected <- struct{}{}
	})

	client := &Client{
		Addr: server.addr,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{clientCertificate},
			RootCAs:      ca.pool,
			ServerName:   "split.example.test",
			MinVersion:   tls.VersionTLS12,
		},
		Logger: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
	}
	conn, _, err := client.dialAndHandshake(context.Background())
	if err != nil {
		t.Fatalf("dialAndHandshake() with matching client DN failed: %v", err)
	}
	defer conn.Close()
	select {
	case <-connected:
	case <-time.After(5 * time.Second):
		t.Fatal("server did not accept the client certificate DN")
	}
}

type splitTestCA struct {
	cert *x509.Certificate
	key  *rsa.PrivateKey
	pool *x509.CertPool
}

func newSplitTestCA(t *testing.T, commonName string) splitTestCA {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return splitTestCA{cert: cert, key: key, pool: pool}
}

func issueSplitTestCertificate(t *testing.T, ca splitTestCA, commonName string, dnsNames []string, usage x509.ExtKeyUsage) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: commonName},
		DNSNames:     dnsNames,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

type splitTLSTestServer struct {
	addr string
}

func startTLSTestServer(t *testing.T, config *tls.Config, logger *slog.Logger, expectedClientDN string, onConnected ...func()) splitTLSTestServer {
	t.Helper()
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.Addr().String()
	if err := probe.Close(); err != nil {
		t.Fatal(err)
	}
	ready := make(chan struct{}, 1)
	var connected func()
	if len(onConnected) > 0 {
		connected = onConnected[0]
	}
	server := &Server{
		Addr:             addr,
		TLSConfig:        config,
		Logger:           logger,
		OnReady:          func() { ready <- struct{}{} },
		OnConnected:      connected,
		ExpectedClientDN: expectedClientDN,
		Deliver:          func(context.Context, SendRequest) error { return nil },
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.ListenAndServe(ctx) }()
	select {
	case <-ready:
	case err := <-done:
		cancel()
		t.Fatalf("split TLS test server failed to start: %v", err)
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("timed out waiting for split TLS test server")
	}
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("split TLS test server stopped with error: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("split TLS test server did not stop")
		}
	})
	return splitTLSTestServer{addr: addr}
}

type lockedTestBuffer struct {
	mu sync.Mutex
	bytes.Buffer
}

func (b *lockedTestBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.Write(p)
}

func (b *lockedTestBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.String()
}

func waitForTestLog(t *testing.T, logs *lockedTestBuffer, needle string) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if log := logs.String(); strings.Contains(log, needle) {
			return log
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for log %q; got: %s", needle, logs.String())
	return ""
}
