package main

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"net/http/httptest"
	"net/mail"
	"net/smtp"
	"os"
	"strings"
	"testing"
)

func testAddress(t *testing.T) string {
	t.Helper()
	address := os.Getenv("MYMAIL_TEST_ADDRESS")
	if address == "" {
		t.Fatal("MYMAIL_TEST_ADDRESS must be set before running tests")
	}
	return address
}

func testTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	server := httptest.NewTLSServer(nil)
	tlsConfig := server.TLS.Clone()
	server.Close()
	return tlsConfig
}

func TestBuildMessage(t *testing.T) {
	address := testAddress(t)
	from, err := mail.ParseAddress(address)
	if err != nil {
		t.Fatal(err)
	}
	to, err := mail.ParseAddress("bob@example.test")
	if err != nil {
		t.Fatal(err)
	}

	message, err := buildMessage(from, to, "Test subject", "hello from mymail-send")
	if err != nil {
		t.Fatal(err)
	}
	content := string(message)
	for _, want := range []string{
		"From: " + address + "\r\n",
		"To: bob@example.test\r\n",
		"Subject: Test subject\r\n",
		"Content-Type: text/plain; charset=UTF-8\r\n",
		"\r\nhello from mymail-send\r\n",
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("message = %q, missing %q", content, want)
		}
	}
}

func TestBuildMessageWithRecipients(t *testing.T) {
	from, _ := mail.ParseAddress(testAddress(t))
	to, _ := mail.ParseAddress("bob@example.test")
	cc, _ := mail.ParseAddress("carol@example.test")

	message, err := buildMessageWithRecipients(from, []*mail.Address{to}, []*mail.Address{cc}, "Test subject", "body")
	if err != nil {
		t.Fatal(err)
	}
	content := string(message)
	for _, want := range []string{
		"To: bob@example.test\r\n",
		"Cc: carol@example.test\r\n",
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("message = %q, missing %q", content, want)
		}
	}
	if strings.Contains(content, "Bcc:") {
		t.Fatalf("message unexpectedly contains Bcc header: %q", content)
	}
}

func TestParseAddressesSupportsLists(t *testing.T) {
	addresses, err := parseAddresses([]string{"bob@example.test, Carol <carol@example.test>", "dave@example.test"}, "to")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(addresses), 3; got != want {
		t.Fatalf("parsed %d addresses, want %d", got, want)
	}
}

func TestBuildMessageRejectsHeaderInjection(t *testing.T) {
	from, _ := mail.ParseAddress(testAddress(t))
	to, _ := mail.ParseAddress("bob@example.test")
	if _, err := buildMessage(from, to, "bad\r\nBcc: attacker@example.test", "body"); err == nil {
		t.Fatal("buildMessage accepted a subject containing a newline")
	}
}

func TestParseAddressRejectsInvalidAddress(t *testing.T) {
	if _, err := parseAddress("not-an-address", "to"); err == nil {
		t.Fatal("parseAddress accepted an invalid address")
	}
}

func startMockSMTPServer(t *testing.T, withSTARTTLS bool, tlsConfig *tls.Config) (string, chan string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	received := make(chan string, 10)

	go func() {
		defer listener.Close()
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)
		writeLine := func(c net.Conn, s string) {
			_, _ = io.WriteString(c, s+"\r\n")
		}

		writeLine(conn, "220 mock.smtp.test ESMTP Service Ready")
		tlsActive := false

		for {
			line, rErr := reader.ReadString('\n')
			if rErr != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			upper := strings.ToUpper(line)

			if strings.HasPrefix(upper, "EHLO") || strings.HasPrefix(upper, "HELO") {
				if withSTARTTLS && !tlsActive {
					writeLine(conn, "250-mock.smtp.test")
					writeLine(conn, "250-STARTTLS")
					writeLine(conn, "250 8BITMIME")
				} else {
					writeLine(conn, "250-mock.smtp.test")
					writeLine(conn, "250-AUTH PLAIN LOGIN")
					writeLine(conn, "250 8BITMIME")
				}
			} else if upper == "STARTTLS" && withSTARTTLS && !tlsActive {
				writeLine(conn, "220 2.0.0 Ready to start TLS")
				tlsConn := tls.Server(conn, tlsConfig)
				if hErr := tlsConn.Handshake(); hErr != nil {
					return
				}
				conn = tlsConn
				reader = bufio.NewReader(conn)
				tlsActive = true
			} else if strings.HasPrefix(upper, "AUTH PLAIN") {
				writeLine(conn, "235 2.7.0 Authentication successful")
			} else if upper == "AUTH LOGIN" {
				writeLine(conn, "334 VXNlcm5hbWU6") // Username:
				uLine, _ := reader.ReadString('\n')
				_ = uLine
				writeLine(conn, "334 UGFzc3dvcmQ6") // Password:
				pLine, _ := reader.ReadString('\n')
				_ = pLine
				writeLine(conn, "235 2.7.0 Authentication successful")
			} else if strings.HasPrefix(upper, "MAIL FROM:") {
				writeLine(conn, "250 2.1.0 Sender OK")
			} else if strings.HasPrefix(upper, "RCPT TO:") {
				writeLine(conn, "250 2.1.5 Recipient OK")
			} else if upper == "DATA" {
				writeLine(conn, "354 Start mail input; end with <CRLF>.<CRLF>")
				var msg strings.Builder
				for {
					dLine, dErr := reader.ReadString('\n')
					if dErr != nil {
						return
					}
					if dLine == ".\r\n" || dLine == ".\n" {
						break
					}
					msg.WriteString(dLine)
				}
				received <- msg.String()
				writeLine(conn, "250 2.0.0 Message accepted for delivery")
			} else if upper == "QUIT" {
				writeLine(conn, "221 2.0.0 Service closing transmission channel")
				return
			} else {
				writeLine(conn, "500 5.5.1 Command unrecognized")
			}
		}
	}()

	return listener.Addr().String(), received
}

func TestSendMessageSTARTTLS(t *testing.T) {
	tlsCfg := testTLSConfig(t)
	addr, received := startMockSMTPServer(t, true, tlsCfg)

	sender := testAddress(t)
	opts := sendOptions{
		server:       addr,
		from:         sender,
		to:           []string{"recipient@example.test"},
		subject:      "STARTTLS Test",
		body:         "Hello over STARTTLS",
		username:     "testuser",
		password:     "secret",
		startTLS:     true,
		insecureTLS:  true,
		insecureAuth: false,
	}

	if err := sendMessage(opts); err != nil {
		t.Fatalf("sendMessage with STARTTLS failed: %v", err)
	}

	select {
	case msg := <-received:
		if !strings.Contains(msg, "Hello over STARTTLS") {
			t.Fatalf("unexpected message content: %s", msg)
		}
	default:
		t.Fatal("no message received by mock SMTP server")
	}
}

func TestSendMessageUnencryptedAuthRejection(t *testing.T) {
	// For localhost (127.0.0.1), clientAuth allows it by default as localhost.
	// Test clientAuth directly with a non-localhost host name.
	auth := newClientAuth("", "user", "pass", "smtp.remote.test", false)
	serverInfo := &smtp.ServerInfo{
		Name: "smtp.remote.test",
		TLS:  false,
		Auth: []string{"PLAIN"},
	}
	_, _, err := auth.Start(serverInfo)
	if err == nil || !strings.Contains(err.Error(), "unencrypted connection") {
		t.Fatalf("expected unencrypted connection error, got: %v", err)
	}

	// Now with allowInsecure = true
	insecureAuth := newClientAuth("", "user", "pass", "smtp.remote.test", true)
	proto, resp, err := insecureAuth.Start(serverInfo)
	if err != nil {
		t.Fatalf("expected insecure auth to succeed, got: %v", err)
	}
	if proto != "PLAIN" {
		t.Fatalf("proto = %q, want PLAIN", proto)
	}
	expectedResp := []byte("\x00user\x00pass")
	if string(resp) != string(expectedResp) {
		t.Fatalf("resp = %q, want %q", resp, expectedResp)
	}
}

func TestSendMessageLoginAuth(t *testing.T) {
	auth := newClientAuth("", "user", "pass", "smtp.remote.test", true)
	serverInfo := &smtp.ServerInfo{
		Name: "smtp.remote.test",
		TLS:  true,
		Auth: []string{"LOGIN"},
	}
	proto, resp, err := auth.Start(serverInfo)
	if err != nil {
		t.Fatalf("auth.Start failed: %v", err)
	}
	if proto != "LOGIN" {
		t.Fatalf("proto = %q, want LOGIN", proto)
	}
	if resp != nil {
		t.Fatalf("expected initial resp to be nil for LOGIN, got: %q", resp)
	}

	challenge1, err := auth.Next([]byte("VXNlcm5hbWU6"), true)
	if err != nil {
		t.Fatalf("auth.Next username challenge failed: %v", err)
	}
	if string(challenge1) != "user" {
		t.Fatalf("challenge1 = %q, want 'user'", string(challenge1))
	}

	challenge2, err := auth.Next([]byte("UGFzc3dvcmQ6"), true)
	if err != nil {
		t.Fatalf("auth.Next password challenge failed: %v", err)
	}
	if string(challenge2) != "pass" {
		t.Fatalf("challenge2 = %q, want 'pass'", string(challenge2))
	}

	end, err := auth.Next(nil, false)
	if err != nil {
		t.Fatalf("auth.Next final failed: %v", err)
	}
	if end != nil {
		t.Fatalf("expected nil final response, got: %v", end)
	}
}

func TestSendMessageImplicitTLS(t *testing.T) {
	tlsCfg := testTLSConfig(t)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	received := make(chan string, 1)
	go func() {
		conn, aErr := listener.Accept()
		if aErr != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		writeLine := func(s string) { _, _ = io.WriteString(conn, s+"\r\n") }
		writeLine("220 mock.smtp.test SMTPS Ready")
		for {
			line, rErr := reader.ReadString('\n')
			if rErr != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			upper := strings.ToUpper(line)
			if strings.HasPrefix(upper, "EHLO") {
				writeLine("250-mock.smtp.test\r\n250 AUTH PLAIN")
			} else if strings.HasPrefix(upper, "AUTH PLAIN") {
				writeLine("235 2.7.0 Authentication successful")
			} else if strings.HasPrefix(upper, "MAIL FROM:") {
				writeLine("250 2.1.0 Sender OK")
			} else if strings.HasPrefix(upper, "RCPT TO:") {
				writeLine("250 2.1.5 Recipient OK")
			} else if upper == "DATA" {
				writeLine("354 Start mail input; end with <CRLF>.<CRLF>")
				var msg strings.Builder
				for {
					dLine, _ := reader.ReadString('\n')
					if dLine == ".\r\n" || dLine == ".\n" {
						break
					}
					msg.WriteString(dLine)
				}
				received <- msg.String()
				writeLine("250 2.0.0 OK")
			} else if upper == "QUIT" {
				writeLine("221 2.0.0 Bye")
				return
			}
		}
	}()

	opts := sendOptions{
		server:      listener.Addr().String(),
		from:        testAddress(t),
		to:          []string{"test@example.test"},
		subject:     "Implicit TLS Test",
		body:        "Message over direct TLS",
		username:    "user",
		password:    "pass",
		implicitTLS: true,
		insecureTLS: true,
	}

	if err := sendMessage(opts); err != nil {
		t.Fatalf("sendMessage with implicit TLS failed: %v", err)
	}

	select {
	case msg := <-received:
		if !strings.Contains(msg, "Message over direct TLS") {
			t.Fatalf("unexpected received message: %s", msg)
		}
	default:
		t.Fatal("no message received over SMTPS")
	}
}
