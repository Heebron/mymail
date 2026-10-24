package smtp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"mymail/auth"
	"mymail/maildir"
)

func TestParseSMTPPathAcceptsESMTPParameters(t *testing.T) {
	address, ok := parseSMTPPath("FROM:<kenpratt@comcast.net> BODY=8BITMIME", "FROM:")
	if !ok || address != "kenpratt@comcast.net" {
		t.Fatalf("parseSMTPPath() = %q, %t; want kenpratt@comcast.net, true", address, ok)
	}
}

func TestSMTPAuthenticationResponseDelayIsBounded(t *testing.T) {
	limiter := auth.NewLimiter(auth.Config{
		MaxAttemptsPerConnection: 5,
		MaxFailuresPerIP:         10,
		MaxFailuresPerAccount:    10,
		BackoffBase:              100 * time.Millisecond,
		BackoffMax:               time.Second,
		ResponseDelayMax:         10 * time.Millisecond,
		FailureWindow:            time.Minute,
	})
	server := &Server{
		Authenticate: func(string, string) bool { return false },
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	credentials := base64.StdEncoding.EncodeToString([]byte("\x00alice@example.test\x00wrong"))
	var response string
	start := time.Now()
	err := server.authenticate(
		"PLAIN "+credentials,
		bufio.NewReader(strings.NewReader("")),
		func(format string, args ...any) error {
			response = fmt.Sprintf(format, args...)
			return nil
		},
		new(bool),
		"192.0.2.40:2525",
		limiter.NewConnection("192.0.2.40:2525"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed < 5*time.Millisecond || elapsed >= 80*time.Millisecond {
		t.Fatalf("authentication response delay = %v, want at least 5ms and below 80ms", elapsed)
	}
	if response != "535 5.7.8 authentication credentials invalid" {
		t.Fatalf("authentication response = %q", response)
	}
}

func TestSMTPDeliveryReachesResolvedInbox(t *testing.T) {
	store, err := maildir.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	server := &Server{
		Hostname: "mail.example.test",
		Store:    store,
		Resolve: func(address string) (string, bool) {
			return "kpratt", strings.EqualFold(address, "kpratt@leopard.thepratts.info")
		},
		Authenticate: func(username, password string) bool {
			return username == "kpratt" && password == "changeit"
		},
		Logger: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo})),
	}
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	go server.handle(context.Background(), serverConn)

	reader := bufio.NewReader(clientConn)
	readLine := func() string {
		t.Helper()
		line, readErr := reader.ReadString('\n')
		if readErr != nil {
			t.Fatal(readErr)
		}
		return strings.TrimRight(line, "\r\n")
	}
	write := func(line string) {
		t.Helper()
		if _, writeErr := io.WriteString(clientConn, line+"\r\n"); writeErr != nil {
			t.Fatal(writeErr)
		}
	}

	if got := readLine(); !strings.HasPrefix(got, "220 ") {
		t.Fatalf("greeting = %q", got)
	}
	write("EHLO localhost")
	for i := 0; i < 5; i++ {
		readLine()
	}
	credentials := base64.StdEncoding.EncodeToString([]byte("\x00kpratt\x00changeit"))
	write("AUTH PLAIN " + credentials)
	if got := readLine(); !strings.HasPrefix(got, "235 ") {
		t.Fatalf("AUTH response = %q", got)
	}
	write("MAIL FROM:<kenpratt@comcast.net> BODY=8BITMIME")
	if got := readLine(); !strings.HasPrefix(got, "250 ") {
		t.Fatalf("MAIL response = %q", got)
	}
	write("RCPT TO:<kpratt@leopard.thepratts.info>")
	if got := readLine(); !strings.HasPrefix(got, "250 ") {
		t.Fatalf("RCPT response = %q", got)
	}
	write("DATA")
	if got := readLine(); !strings.HasPrefix(got, "354 ") {
		t.Fatalf("DATA response = %q", got)
	}
	write("From: kenpratt@comcast.net\r\nTo: kpratt@leopard.thepratts.info\r\nSubject: delivery test\r\n\r\nhello")
	write(".")
	if got := readLine(); !strings.HasPrefix(got, "250 ") {
		t.Fatalf("delivery response = %q", got)
	}

	messages, err := store.List("kpratt")
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 1 {
		t.Fatalf("inbox messages = %d, want 1", len(messages))
	}
	output := logs.String()
	for _, expected := range []string{
		`msg="SMTP action"`,
		`command=AUTH`,
		`msg="SMTP authentication"`,
		`username=kpratt`,
		`success=true`,
		`msg="SMTP message received"`,
		`from=kenpratt@comcast.net`,
		`to=[kpratt@leopard.thepratts.info]`,
		`subject="delivery test"`,
		`msg="SMTP message processed"`,
		`decision=accept`,
		`msg="SMTP local delivery completed"`,
		`msg="SMTP delivery completed"`,
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("SMTP logs missing %q: %s", expected, output)
		}
	}
	if strings.Contains(output, "changeit") || strings.Contains(output, credentials) || strings.Contains(output, "hello") {
		t.Fatalf("SMTP logs exposed sensitive message data: %s", output)
	}
}

func TestSMTPDeliveryForwardsUnknownDomainToMX(t *testing.T) {
	store, err := maildir.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	server := &Server{
		Hostname: "mail.local.test",
		Store:    store,
		Resolve: func(address string) (string, bool) {
			return "alice", strings.EqualFold(address, "alice@local.test")
		},
		LocalDomain: func(domain string) bool { return strings.EqualFold(domain, "local.test") },
		Authenticate: func(username, password string) bool {
			return username == "relay" && password == "secret"
		},
		LookupMX: func(_ context.Context, domain string) ([]*net.MX, error) {
			if domain != "remote.test" {
				t.Fatalf("MX lookup domain = %q", domain)
			}
			return []*net.MX{{Host: "mx.remote.test", Pref: 10}}, nil
		},
		Logger: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo})),
	}
	inboundServer, inboundClient := net.Pipe()
	defer inboundClient.Close()
	relayServer, relayClient := net.Pipe()
	defer relayServer.Close()
	server.DialSMTP = func(_ context.Context, address string) (net.Conn, error) {
		if address != "mx.remote.test:25" {
			t.Fatalf("MX dial address = %q", address)
		}
		return relayServer, nil
	}
	relayErrors := make(chan error, 1)
	var relayed bytes.Buffer
	go func() {
		reader := bufio.NewReader(relayClient)
		writer := bufio.NewWriter(relayClient)
		writeResponse := func(response string) error {
			if _, err := io.WriteString(writer, response+"\r\n"); err != nil {
				return err
			}
			return writer.Flush()
		}
		if err := writeResponse("220 mx.remote.test ESMTP"); err != nil {
			relayErrors <- err
			return
		}
		for _, response := range []string{"250 mx.remote.test", "250 sender ok", "250 recipient ok", "354 continue"} {
			if _, err := reader.ReadString('\n'); err != nil {
				relayErrors <- err
				return
			}
			if err := writeResponse(response); err != nil {
				relayErrors <- err
				return
			}
		}
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				relayErrors <- err
				return
			}
			if line == ".\r\n" {
				break
			}
			relayed.WriteString(line)
		}
		if err := writeResponse("250 queued"); err != nil {
			relayErrors <- err
			return
		}
		if _, err := reader.ReadString('\n'); err != nil {
			relayErrors <- err
			return
		}
		relayErrors <- nil
	}()
	go server.handle(context.Background(), inboundServer)

	reader := bufio.NewReader(inboundClient)
	readLine := func() string {
		t.Helper()
		line, readErr := reader.ReadString('\n')
		if readErr != nil {
			t.Fatal(readErr)
		}
		return strings.TrimRight(line, "\r\n")
	}
	writeLine := func(line string) {
		t.Helper()
		if _, writeErr := io.WriteString(inboundClient, line+"\r\n"); writeErr != nil {
			t.Fatal(writeErr)
		}
	}
	if got := readLine(); !strings.HasPrefix(got, "220 ") {
		t.Fatalf("greeting = %q", got)
	}
	writeLine("EHLO sender.test")
	for i := 0; i < 5; i++ {
		readLine()
	}
	credentials := base64.StdEncoding.EncodeToString([]byte("\x00relay\x00secret"))
	writeLine("AUTH PLAIN " + credentials)
	if got := readLine(); !strings.HasPrefix(got, "235 ") {
		t.Fatalf("AUTH response = %q", got)
	}
	writeLine("MAIL FROM:<sender@sender.test>")
	if got := readLine(); !strings.HasPrefix(got, "250 ") {
		t.Fatalf("MAIL response = %q", got)
	}
	writeLine("RCPT TO:<recipient@remote.test>")
	if got := readLine(); !strings.HasPrefix(got, "250 ") {
		t.Fatalf("RCPT response = %q", got)
	}
	writeLine("DATA")
	if got := readLine(); !strings.HasPrefix(got, "354 ") {
		t.Fatalf("DATA response = %q", got)
	}
	writeLine("From: sender@sender.test\r\nTo: recipient@remote.test\r\nSubject: relay test\r\n\r\n.dot-stuffed")
	writeLine(".")
	if got := readLine(); !strings.HasPrefix(got, "250 ") {
		t.Fatalf("delivery response = %q", got)
	}
	if err := <-relayErrors; err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(relayed.String(), "..dot-stuffed\r\n") || !strings.Contains(relayed.String(), "Subject: relay test") {
		t.Fatalf("relayed message = %q", relayed.String())
	}
	output := logs.String()
	for _, expected := range []string{`route=forward`, `msg="SMTP forwarding attempt"`, `msg="SMTP forwarding completed"`} {
		if !strings.Contains(output, expected) {
			t.Fatalf("forwarding logs missing %q: %s", expected, output)
		}
	}
}

func TestSMTPRejectsUnauthenticatedExternalRecipient(t *testing.T) {
	store, err := maildir.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	lookupCalled := false
	server := &Server{
		Hostname: "mail.local.test",
		Store:    store,
		Resolve:  func(string) (string, bool) { return "", false },
		LocalDomain: func(domain string) bool {
			return strings.EqualFold(domain, "local.test")
		},
		LookupMX: func(context.Context, string) ([]*net.MX, error) {
			lookupCalled = true
			return nil, nil
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	go server.handle(context.Background(), serverConn)

	reader := bufio.NewReader(clientConn)
	readLine := func() string {
		t.Helper()
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimRight(line, "\r\n")
	}
	writeLine := func(line string) {
		t.Helper()
		if _, err := io.WriteString(clientConn, line+"\r\n"); err != nil {
			t.Fatal(err)
		}
	}

	if got := readLine(); !strings.HasPrefix(got, "220 ") {
		t.Fatalf("greeting = %q", got)
	}
	writeLine("MAIL FROM:<sender@sender.test>")
	if got := readLine(); !strings.HasPrefix(got, "250 ") {
		t.Fatalf("MAIL response = %q", got)
	}
	writeLine("RCPT TO:<recipient@remote.test>")
	if got := readLine(); !strings.HasPrefix(got, "530 ") {
		t.Fatalf("unauthenticated external recipient response = %q", got)
	}
	if lookupCalled {
		t.Fatal("MX lookup performed for unauthenticated external recipient")
	}
}

func TestSMTPRejectsUnknownUserOnLocalDomain(t *testing.T) {
	store, err := maildir.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{
		Hostname:    "mail.local.test",
		Store:       store,
		Resolve:     func(string) (string, bool) { return "", false },
		LocalDomain: func(domain string) bool { return domain == "local.test" },
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	go server.handle(context.Background(), serverConn)
	reader := bufio.NewReader(clientConn)
	readLine := func() string {
		t.Helper()
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimRight(line, "\r\n")
	}
	writeLine := func(line string) { _, _ = io.WriteString(clientConn, line+"\r\n") }
	readLine()
	writeLine("MAIL FROM:<sender@remote.test>")
	readLine()
	writeLine("RCPT TO:<missing@local.test>")
	if got := readLine(); !strings.HasPrefix(got, "550 ") {
		t.Fatalf("unknown local recipient response = %q", got)
	}
}

func TestSMTPStartTLS(t *testing.T) {
	store, err := maildir.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{
		Hostname:        "mail.example.test",
		StartTLSConfig:  testTLSConfig(t),
		RequireSTARTTLS: true,
		Store:           store,
		Resolve:         func(string) (string, bool) { return "", false },
		Authenticate: func(username, password string) bool {
			return username == "kpratt" && password == "changeit"
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	go server.handle(context.Background(), serverConn)

	reader := bufio.NewReader(clientConn)
	readLine := func() string {
		t.Helper()
		line, readErr := reader.ReadString('\n')
		if readErr != nil {
			t.Fatal(readErr)
		}
		return strings.TrimRight(line, "\r\n")
	}
	writeLine := func(line string) {
		t.Helper()
		if _, writeErr := io.WriteString(clientConn, line+"\r\n"); writeErr != nil {
			t.Fatal(writeErr)
		}
	}

	if greeting := readLine(); !strings.HasPrefix(greeting, "220 ") {
		t.Fatalf("greeting = %q", greeting)
	}
	writeLine("EHLO localhost")
	capabilities := make([]string, 0, 6)
	for len(capabilities) == 0 || strings.HasPrefix(capabilities[len(capabilities)-1], "250-") {
		capabilities = append(capabilities, readLine())
	}
	if !containsLine(capabilities, "250-STARTTLS") {
		t.Fatalf("plaintext capabilities = %#v", capabilities)
	}
	if containsLine(capabilities, "250-AUTH PLAIN LOGIN") {
		t.Fatalf("plaintext capabilities advertise AUTH: %#v", capabilities)
	}
	writeLine("AUTH PLAIN " + base64.StdEncoding.EncodeToString([]byte("\x00kpratt\x00changeit")))
	if response := readLine(); !strings.HasPrefix(response, "530 ") {
		t.Fatalf("plaintext AUTH response = %q", response)
	}
	writeLine("MAIL FROM:<sender@example.test>")
	if response := readLine(); !strings.HasPrefix(response, "530 ") {
		t.Fatalf("plaintext MAIL response = %q", response)
	}
	writeLine("STARTTLS")
	if response := readLine(); !strings.HasPrefix(response, "220 ") {
		t.Fatalf("STARTTLS response = %q", response)
	}

	tlsClient := tls.Client(clientConn, &tls.Config{InsecureSkipVerify: true, ServerName: "mail.example.test"}) // Test certificate is intentionally self-signed.
	if err := tlsClient.Handshake(); err != nil {
		t.Fatal(err)
	}
	defer tlsClient.Close()
	reader = bufio.NewReader(tlsClient)
	writeTLSLine := func(line string) {
		t.Helper()
		if _, writeErr := io.WriteString(tlsClient, line+"\r\n"); writeErr != nil {
			t.Fatal(writeErr)
		}
	}
	writeTLSLine("EHLO localhost")
	secureCapabilities := make([]string, 0, 5)
	for len(secureCapabilities) == 0 || strings.HasPrefix(secureCapabilities[len(secureCapabilities)-1], "250-") {
		secureCapabilities = append(secureCapabilities, readLine())
	}
	if containsLine(secureCapabilities, "250-STARTTLS") {
		t.Fatalf("TLS capabilities still advertise STARTTLS: %#v", secureCapabilities)
	}
	credentials := base64.StdEncoding.EncodeToString([]byte("\x00kpratt\x00changeit"))
	writeTLSLine("AUTH PLAIN " + credentials)
	if response := readLine(); !strings.HasPrefix(response, "235 ") {
		t.Fatalf("TLS AUTH response = %q", response)
	}
}

func containsLine(lines []string, want string) bool {
	for _, line := range lines {
		if line == want {
			return true
		}
	}
	return false
}

func testTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	server := httptest.NewTLSServer(nil)
	config := server.TLS.Clone()
	server.Close()
	return config
}
