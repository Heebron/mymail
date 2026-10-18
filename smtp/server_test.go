package smtp

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"log/slog"
	"net"
	"net/http/httptest"
	"strings"
	"testing"

	"mymail/maildir"
)

func TestParseSMTPPathAcceptsESMTPParameters(t *testing.T) {
	address, ok := parseSMTPPath("FROM:<kenpratt@comcast.net> BODY=8BITMIME", "FROM:")
	if !ok || address != "kenpratt@comcast.net" {
		t.Fatalf("parseSMTPPath() = %q, %t; want kenpratt@comcast.net, true", address, ok)
	}
}

func TestSMTPDeliveryReachesResolvedInbox(t *testing.T) {
	store, err := maildir.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{
		Hostname: "mail.example.test",
		Store:    store,
		Resolve: func(address string) (string, bool) {
			return "kpratt", strings.EqualFold(address, "kpratt@leopard.thepratts.info")
		},
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
}

func TestListenSupportsPlainAndTLS(t *testing.T) {
	tests := []struct {
		name   string
		config func(*testing.T) *tls.Config
	}{
		{name: "plain", config: func(*testing.T) *tls.Config { return nil }},
		{name: "TLS", config: testTLSConfig},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			listener, err := listen("127.0.0.1:0", test.config(t))
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
		})
	}
}

func testTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	server := httptest.NewTLSServer(nil)
	config := server.TLS.Clone()
	server.Close()
	return config
}
