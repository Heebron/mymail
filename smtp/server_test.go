package smtp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"mymail/auth"
	"mymail/dkim"
	"mymail/maildir"
	"mymail/plugins"
)

type folderProcessor struct {
	folder string
}

type countingProcessor struct {
	calls int
}

type mailboxProcessor struct {
	mailboxes []string
}

type failingProcessor struct {
	err error
}

func TestDeliverLocalStoresMailAndRejectsUnknownMailbox(t *testing.T) {
	store, err := maildir.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	splitCalls := 0
	server := &Server{
		Store: store,
		Resolve: func(address string) (string, bool) {
			return "alice", strings.EqualFold(address, "alice@example.test")
		},
		SplitForward: func(context.Context, string, string, []byte, func(context.Context, string, string, []byte) error) error {
			splitCalls++
			return nil
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	data := []byte("Subject: split delivery\r\n\r\nbody")
	if err := server.DeliverLocal(context.Background(), "sender@example.test", "alice@example.test", data); err != nil {
		t.Fatal(err)
	}
	messages, err := store.List("alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 1 {
		t.Fatalf("stored messages = %d, want 1", len(messages))
	}
	if splitCalls != 0 {
		t.Fatalf("SplitForward called %d times for local delivery, want 0", splitCalls)
	}
	if err := server.DeliverLocal(context.Background(), "sender@example.test", "missing@example.test", data); err == nil {
		t.Fatal("DeliverLocal() for unknown mailbox succeeded, want error")
	}
}

func TestRelayBypassesSplitForward(t *testing.T) {
	splitCalls := 0
	server := &Server{
		Hostname: "mail.example.test",
		SplitForward: func(context.Context, string, string, []byte, func(context.Context, string, string, []byte) error) error {
			splitCalls++
			return nil
		},
		LookupMX: func(context.Context, string) ([]*net.MX, error) {
			return nil, fmt.Errorf("MX lookup unavailable")
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	err := server.Relay(context.Background(), "sender@example.test", "recipient@example.test", []byte("message"))
	if err == nil {
		t.Fatal("Relay() succeeded with failing MX lookup, want error")
	}
	if splitCalls != 0 {
		t.Fatalf("SplitForward called %d times, want 0", splitCalls)
	}
}

func TestDialSMTPRelayNetwork(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			_ = connection.Close()
		}
	}()

	for _, network := range []string{"tcp4", ""} {
		server := &Server{RelayNetwork: network}
		connection, err := server.dialSMTP(context.Background(), listener.Addr().String())
		if err != nil {
			t.Errorf("dialSMTP(%q) error = %v, want successful IPv4 connection", network, err)
			continue
		}
		_ = connection.Close()
	}

	server := &Server{RelayNetwork: "tcp6"}
	connection, err := server.dialSMTP(context.Background(), listener.Addr().String())
	if err == nil {
		_ = connection.Close()
		t.Fatal("dialSMTP(tcp6) unexpectedly connected to an IPv4 listener")
	}
}

func TestSignDKIMReturnsSignedOrOriginalMessage(t *testing.T) {
	original := []byte("Subject: test\r\n\r\nbody")
	signed := []byte("DKIM-Signature: test\r\nSubject: test\r\n\r\nbody")
	server := &Server{
		DKIMSigner: func([]byte) ([]byte, error) { return signed, nil },
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if got := server.SignDKIM("sender@example.test", "recipient@remote.test", original); !bytes.Equal(got, signed) {
		t.Fatalf("SignDKIM() = %q, want signed message %q", got, signed)
	}
	server.DKIMSigner = func([]byte) ([]byte, error) { return nil, fmt.Errorf("signing failed") }
	if got := server.SignDKIM("sender@example.test", "recipient@remote.test", original); !bytes.Equal(got, original) {
		t.Fatalf("SignDKIM() after signer error = %q, want original message %q", got, original)
	}
	server.DKIMSigner = nil
	if got := server.SignDKIM("sender@example.test", "recipient@remote.test", original); !bytes.Equal(got, original) {
		t.Fatalf("SignDKIM() without signer = %q, want original message %q", got, original)
	}
}

func TestRelayDoesNotSignDKIM(t *testing.T) {
	var relayLogs bytes.Buffer
	relayServer, relayClient := net.Pipe()
	defer relayClient.Close()
	if err := relayServer.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	relayedData := make(chan string, 1)
	relayErrors := make(chan error, 1)
	go func() {
		defer relayServer.Close()
		reader := bufio.NewReader(relayServer)
		writeLine := func(line string) error {
			_, err := io.WriteString(relayServer, line+"\r\n")
			return err
		}
		readExpected := func(want string) error {
			line, err := reader.ReadString('\n')
			if err != nil {
				return err
			}
			if strings.TrimRight(line, "\r\n") != want {
				return fmt.Errorf("SMTP command = %q, want %q", strings.TrimRight(line, "\r\n"), want)
			}
			return nil
		}
		if err := writeLine("220 mx.remote.test ESMTP"); err != nil {
			relayErrors <- err
			return
		}
		for _, exchange := range []struct{ command, response string }{
			{"EHLO mail.example.test", "250 mx.remote.test"},
			{"MAIL FROM:<sender@example.test>", "250 sender ok"},
			{"RCPT TO:<recipient@remote.test>", "250 recipient ok"},
			{"DATA", "354 continue"},
		} {
			if err := readExpected(exchange.command); err != nil {
				relayErrors <- err
				return
			}
			if err := writeLine(exchange.response); err != nil {
				relayErrors <- err
				return
			}
		}
		var data strings.Builder
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				relayErrors <- err
				return
			}
			if line == ".\r\n" {
				break
			}
			data.WriteString(line)
		}
		if err := writeLine("250 2.6.0 <queue-id@example.test> Queued mail for delivery"); err != nil {
			relayErrors <- err
			return
		}
		if err := readExpected("QUIT"); err != nil {
			relayErrors <- err
			return
		}
		relayedData <- data.String()
		relayErrors <- nil
	}()

	signerCalls := 0
	server := &Server{
		Hostname: "mail.example.test",
		LookupMX: func(context.Context, string) ([]*net.MX, error) {
			return []*net.MX{{Host: "mx.remote.test", Pref: 10}}, nil
		},
		DialSMTP: func(context.Context, string) (net.Conn, error) { return relayClient, nil },
		DKIMSigner: func(data []byte) ([]byte, error) {
			signerCalls++
			return append([]byte("DKIM-Signature: unexpected\r\n"), data...), nil
		},
		Logger: slog.New(slog.NewTextHandler(&relayLogs, nil)),
	}
	message := []byte("Message-ID: <relay-test@example.test>\r\nSubject: relay test\r\n\r\nbody\r\n")
	if err := server.Relay(context.Background(), "sender@example.test", "recipient@remote.test", message); err != nil {
		t.Fatalf("Relay() error = %v", err)
	}
	if err := <-relayErrors; err != nil {
		t.Fatal(err)
	}
	if signerCalls != 0 {
		t.Fatalf("DKIM signer called %d times by Relay(), want 0", signerCalls)
	}
	got := <-relayedData
	if strings.Contains(got, "DKIM-Signature:") {
		t.Fatalf("relayed message was DKIM-signed: %q", got)
	}
	if !strings.Contains(got, "Subject: relay test") {
		t.Fatalf("relayed message missing original content: %q", got)
	}
	if got := relayLogs.String(); !strings.Contains(got, "message_id=<relay-test@example.test>") || !strings.Contains(got, `response="250 2.6.0 <queue-id@example.test> Queued mail for delivery"`) {
		t.Fatalf("relay logs missing message ID or final MX response: %s", got)
	}
}

func TestForwardingSenderDomainWarning(t *testing.T) {
	tests := []struct {
		name        string
		sender      string
		message     string
		wantWarning bool
		wantHeader  string
		wantDomain  string
	}{
		{name: "local envelope and header", sender: "sender@example.test", message: "From: sender@example.test\r\n\r\nbody", wantWarning: false},
		{name: "foreign envelope", sender: "sender@comcast.net", message: "From: sender@example.test\r\n\r\nbody", wantWarning: true, wantHeader: "sender@example.test", wantDomain: "comcast.net"},
		{name: "foreign header", sender: "sender@example.test", message: "From: sender@comcast.net\r\n\r\nbody", wantWarning: true, wantHeader: "sender@comcast.net", wantDomain: "comcast.net"},
		{name: "invalid header falls back to envelope", sender: "sender@comcast.net", message: "From: not-an-address\r\n\r\nbody", wantWarning: true, wantDomain: "comcast.net"},
		{name: "null sender", sender: "", message: "From: sender@comcast.net\r\n\r\nbody", wantWarning: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logs bytes.Buffer
			server := &Server{
				LocalDomain: func(domain string) bool { return domain == "example.test" },
				SplitForward: func(context.Context, string, string, []byte, func(context.Context, string, string, []byte) error) error {
					return nil
				},
				Logger: slog.New(slog.NewTextHandler(&logs, nil)),
			}
			err := server.deliverProcessed(context.Background(), transaction{
				from:    tt.sender,
				forward: []string{"recipient@remote.test"},
			}, nil, []byte(tt.message))
			if err != nil {
				t.Fatalf("deliverProcessed() error = %v", err)
			}
			got := logs.String()
			warning := strings.Contains(got, "SMTP forwarding sender domain is not local")
			if warning != tt.wantWarning {
				t.Fatalf("warning logged = %t, want %t; logs: %s", warning, tt.wantWarning, got)
			}
			if tt.wantWarning {
				if !strings.Contains(got, "domain="+tt.wantDomain) {
					t.Errorf("warning missing domain %q: %s", tt.wantDomain, got)
				}
				if tt.wantHeader != "" && !strings.Contains(got, "header_from="+tt.wantHeader) {
					t.Errorf("warning missing header From %q: %s", tt.wantHeader, got)
				}
			}
		})
	}
}

func TestSMTPStoresLocalMailboxWhenSplitForwardConfigured(t *testing.T) {
	store, err := maildir.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	splitCalls := 0
	server := &Server{
		Hostname: "mail.example.test",
		Store:    store,
		Resolve: func(address string) (string, bool) {
			return "alice", strings.EqualFold(address, "alice@example.test")
		},
		SplitForward: func(context.Context, string, string, []byte, func(context.Context, string, string, []byte) error) error {
			splitCalls++
			return nil
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	if err := clientConn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
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
	readReply := func() string {
		line := readLine()
		for len(line) > 3 && line[3] == '-' {
			line = readLine()
		}
		return line
	}
	write := func(command string) {
		t.Helper()
		if _, err := io.WriteString(clientConn, command+"\r\n"); err != nil {
			t.Fatal(err)
		}
	}
	if got := readReply(); !strings.HasPrefix(got, "220 ") {
		t.Fatalf("greeting = %q", got)
	}
	write("EHLO localhost")
	if got := readReply(); !strings.HasPrefix(got, "250 ") {
		t.Fatalf("EHLO response = %q", got)
	}
	write("MAIL FROM:<sender@example.test>")
	if got := readReply(); !strings.HasPrefix(got, "250 ") {
		t.Fatalf("MAIL response = %q", got)
	}
	write("RCPT TO:<alice@example.test>")
	if got := readReply(); !strings.HasPrefix(got, "250 ") {
		t.Fatalf("RCPT response = %q", got)
	}
	write("DATA")
	if got := readReply(); !strings.HasPrefix(got, "354 ") {
		t.Fatalf("DATA response = %q", got)
	}
	if _, err := io.WriteString(clientConn, "From: sender@example.test\r\nTo: alice@example.test\r\nSubject: split local\r\n\r\nbody\r\n.\r\n"); err != nil {
		t.Fatal(err)
	}
	if got := readReply(); !strings.HasPrefix(got, "250 ") {
		t.Fatalf("delivery response = %q", got)
	}
	write("QUIT")
	if got := readReply(); !strings.HasPrefix(got, "221 ") {
		t.Fatalf("QUIT response = %q", got)
	}
	messages, err := store.List("alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 1 {
		t.Fatalf("stored messages = %d, want 1", len(messages))
	}
	if splitCalls != 0 {
		t.Fatalf("SplitForward called %d times for local SMTP delivery, want 0", splitCalls)
	}
}

func (p *countingProcessor) Name() string { return "counting" }

func (p *countingProcessor) Initialize(context.Context, map[string]string) error { return nil }

func (p *countingProcessor) Process(context.Context, *plugins.Message) (plugins.Result, error) {
	p.calls++
	return plugins.Result{Decision: plugins.Accept}, nil
}

func (p *mailboxProcessor) Name() string { return "mailbox" }

func (p *mailboxProcessor) Initialize(context.Context, map[string]string) error { return nil }

func (p *mailboxProcessor) Process(_ context.Context, message *plugins.Message) (plugins.Result, error) {
	p.mailboxes = append(p.mailboxes, message.Mailbox)
	message.Data = []byte("X-Mailbox: " + message.Mailbox + "\r\n\r\nbody")
	return plugins.Result{Decision: plugins.Accept}, nil
}

func (p *failingProcessor) Name() string { return "broken" }

func (p *failingProcessor) Initialize(context.Context, map[string]string) error { return nil }

func (p *failingProcessor) Process(_ context.Context, message *plugins.Message) (plugins.Result, error) {
	message.Data = []byte("plugin replacement")
	message.Folder = "Broken"
	return plugins.Result{}, p.err
}

func TestPluginMessageIncludesAbsoluteUserMaildir(t *testing.T) {
	root := t.TempDir()
	store, err := maildir.New(root)
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{Store: store}
	message := server.pluginMessage(transaction{mailboxes: []string{"alice"}}, []byte("message"), "192.0.2.1:25")
	want := filepath.Join(root, "alice", "Maildir")
	if message.Maildir != want {
		t.Fatalf("plugin Maildir = %q, want %q", message.Maildir, want)
	}
	if message.Mailbox != "alice" {
		t.Fatalf("plugin Mailbox = %q, want alice", message.Mailbox)
	}
	if !filepath.IsAbs(message.Maildir) {
		t.Fatalf("plugin Maildir = %q, want absolute path", message.Maildir)
	}
}

func TestSMTPProcessesEachLocalMailboxSeparately(t *testing.T) {
	store, err := maildir.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	processor := &mailboxProcessor{}
	processors := plugins.New()
	if err := processors.Add(processor); err != nil {
		t.Fatal(err)
	}
	if failures := processors.Initialize(context.Background()); len(failures) != 0 {
		t.Fatalf("initialization failures = %#v", failures)
	}
	server := &Server{Store: store, Processors: processors}
	tx := transaction{
		from:       "sender@example.test",
		recipients: []string{"alice@example.test", "bob@example.test"},
		mailboxes:  []string{"alice", "bob"},
	}
	data := []byte("Subject: original\r\n\r\nbody")
	deliveries, result := server.processLocalRecipients(context.Background(), tx, data, "192.0.2.1:25")
	if result.Decision != plugins.Accept {
		t.Fatalf("processing result = %#v, want accept", result)
	}
	if got, want := strings.Join(processor.mailboxes, ","), "alice,bob"; got != want {
		t.Fatalf("processed mailboxes = %q, want %q", got, want)
	}
	if len(deliveries) != 2 {
		t.Fatalf("deliveries = %d, want 2", len(deliveries))
	}
	if got, want := string(data), "Subject: original\r\n\r\nbody"; got != want {
		t.Fatalf("original data = %q, want %q", got, want)
	}
	if err := server.deliverProcessed(context.Background(), tx, deliveries, data); err != nil {
		t.Fatal(err)
	}
	for _, mailbox := range []string{"alice", "bob"} {
		messages, listErr := store.List(mailbox)
		if listErr != nil {
			t.Fatal(listErr)
		}
		if len(messages) != 1 {
			t.Fatalf("%s messages = %d, want 1", mailbox, len(messages))
		}
		got, readErr := store.Read(messages[0])
		if readErr != nil {
			t.Fatal(readErr)
		}
		want := []byte("X-Mailbox: " + mailbox + "\r\n\r\nbody")
		if !bytes.Equal(got, want) {
			t.Fatalf("%s message = %q, want %q", mailbox, got, want)
		}
	}
}

func (p *folderProcessor) Name() string { return "folder" }

func (p *folderProcessor) Initialize(context.Context, map[string]string) error { return nil }

func (p *folderProcessor) Process(context.Context, *plugins.Message) (plugins.Result, error) {
	return plugins.Result{Decision: plugins.Accept, Folder: p.folder}, nil
}

func TestParseSMTPPathAcceptsESMTPParameters(t *testing.T) {
	testSender := os.Getenv("MYMAIL_TEST_SENDER")
	if testSender == "" {
		t.Fatal("MYMAIL_TEST_SENDER must be set before running tests")
	}
	address, ok := parseSMTPPath("FROM:<"+testSender+"> BODY=8BITMIME", "FROM:")
	if !ok || address != testSender {
		t.Fatalf("parseSMTPPath() = %q, %t; want %s, true", address, ok, testSender)
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
	testSender := os.Getenv("MYMAIL_TEST_SENDER")
	if testSender == "" {
		t.Fatal("MYMAIL_TEST_SENDER must be set before running tests")
	}
	testUsername := os.Getenv("MYMAIL_TEST_USERNAME")
	if testUsername == "" {
		t.Fatal("MYMAIL_TEST_USERNAME must be set before running tests")
	}
	testAddress := os.Getenv("MYMAIL_TEST_ADDRESS")
	if testAddress == "" {
		t.Fatal("MYMAIL_TEST_ADDRESS must be set before running tests")
	}
	store, err := maildir.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	processors := plugins.New()
	processor := &countingProcessor{}
	if err := processors.Add(processor); err != nil {
		t.Fatal(err)
	}
	if failures := processors.Initialize(context.Background()); len(failures) != 0 {
		t.Fatalf("processor initialization failures = %#v", failures)
	}
	server := &Server{
		Hostname:   "mail.example.test",
		Store:      store,
		Processors: processors,
		Resolve: func(address string) (string, bool) {
			return testUsername, strings.EqualFold(address, testAddress)
		},
		Authenticate: func(username, password string) bool {
			return username == testUsername && password == "changeit"
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
	credentials := base64.StdEncoding.EncodeToString([]byte("\x00" + testUsername + "\x00changeit"))
	write("AUTH PLAIN " + credentials)
	if got := readLine(); !strings.HasPrefix(got, "235 ") {
		t.Fatalf("AUTH response = %q", got)
	}
	write("MAIL FROM:<" + testSender + "> BODY=8BITMIME")
	if got := readLine(); !strings.HasPrefix(got, "250 ") {
		t.Fatalf("MAIL response = %q", got)
	}
	write("RCPT TO:<" + testAddress + ">")
	if got := readLine(); !strings.HasPrefix(got, "250 ") {
		t.Fatalf("RCPT response = %q", got)
	}
	write("DATA")
	if got := readLine(); !strings.HasPrefix(got, "354 ") {
		t.Fatalf("DATA response = %q", got)
	}
	write("From: " + testSender + "\r\nTo: " + testAddress + "\r\nSubject: delivery test\r\n\r\nhello")
	write(".")
	if got := readLine(); !strings.HasPrefix(got, "250 ") {
		t.Fatalf("delivery response = %q", got)
	}

	messages, err := store.List(testUsername)
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 1 {
		t.Fatalf("inbox messages = %d, want 1", len(messages))
	}
	if processor.calls != 1 {
		t.Fatalf("local message invoked %d processors, want 1", processor.calls)
	}
	output := logs.String()
	for _, expected := range []string{
		`msg="SMTP action"`,
		`command=AUTH`,
		`msg="SMTP authentication"`,
		`username=` + testUsername,
		`success=true`,
		`msg="SMTP message received"`,
		`from=` + testSender,
		`to=[` + testAddress + `]`,
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

func TestPluginDeliveryCreatesMissingFolder(t *testing.T) {
	store, err := maildir.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	processors := plugins.New()
	if err := processors.Add(&folderProcessor{folder: "PluginArchive"}); err != nil {
		t.Fatal(err)
	}
	if failures := processors.Initialize(context.Background()); len(failures) != 0 {
		t.Fatalf("initialization failures = %#v", failures)
	}
	message := &plugins.Message{Data: []byte("Subject: plugin folder\r\n\r\nbody")}
	result := processors.Process(context.Background(), message)
	if result.Decision != plugins.Accept || message.Folder != "PluginArchive" {
		t.Fatalf("plugin result = %#v, message = %#v", result, message)
	}

	server := &Server{Store: store}
	if err := server.deliver(context.Background(), transaction{mailboxes: []string{"alice"}}, message); err != nil {
		t.Fatal(err)
	}
	folders, err := store.ListMailboxes("alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(folders) != 1 || folders[0] != "PluginArchive" {
		t.Fatalf("folders = %#v, want [PluginArchive]", folders)
	}
	messages, err := store.List("alice/PluginArchive")
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 1 {
		t.Fatalf("plugin folder messages = %d, want 1", len(messages))
	}
}

func TestSMTPPluginErrorLogsAndDeliversOriginalMessage(t *testing.T) {
	store, err := maildir.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	processors := plugins.New()
	processor := &failingProcessor{err: fmt.Errorf("service unavailable")}
	if err := processors.Add(processor); err != nil {
		t.Fatal(err)
	}
	if failures := processors.Initialize(context.Background()); len(failures) != 0 {
		t.Fatalf("processor initialization failures = %#v", failures)
	}
	server := &Server{
		Hostname:   "mail.example.test",
		Store:      store,
		Processors: processors,
		Resolve: func(address string) (string, bool) {
			return "alice", strings.EqualFold(address, "alice@mail.example.test")
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
	write("MAIL FROM:<sender@example.test>")
	if got := readLine(); !strings.HasPrefix(got, "250 ") {
		t.Fatalf("MAIL response = %q", got)
	}
	write("RCPT TO:<alice@mail.example.test>")
	if got := readLine(); !strings.HasPrefix(got, "250 ") {
		t.Fatalf("RCPT response = %q", got)
	}
	write("DATA")
	if got := readLine(); !strings.HasPrefix(got, "354 ") {
		t.Fatalf("DATA response = %q", got)
	}
	original := "From: sender@example.test\r\nTo: alice@mail.example.test\r\nSubject: unchanged\r\n\r\nbody\r\n"
	if _, err := io.WriteString(clientConn, original+".\r\n"); err != nil {
		t.Fatal(err)
	}
	if got := readLine(); !strings.HasPrefix(got, "250 ") {
		t.Fatalf("delivery response = %q", got)
	}

	messages, err := store.List("alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 1 {
		t.Fatalf("inbox messages = %d, want 1", len(messages))
	}
	got, err := store.Read(messages[0])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte(original)) {
		t.Fatalf("stored message = %q, want %q", got, original)
	}
	output := logs.String()
	for _, expected := range []string{`msg="SMTP plugin failed"`, `error="processor broken failed: service unavailable"`, `msg="SMTP delivery completed"`} {
		if !strings.Contains(output, expected) {
			t.Fatalf("SMTP logs missing %q: %s", expected, output)
		}
	}
}

func TestSMTPDeliveryForwardsUnknownDomainToMX(t *testing.T) {
	store, err := maildir.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	processors := plugins.New()
	processor := &countingProcessor{}
	if err := processors.Add(processor); err != nil {
		t.Fatal(err)
	}
	if failures := processors.Initialize(context.Background()); len(failures) != 0 {
		t.Fatalf("processor initialization failures = %#v", failures)
	}
	server := &Server{
		Hostname:   "mail.local.test",
		Store:      store,
		Processors: processors,
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
	if processor.calls != 0 {
		t.Fatalf("forward-only message invoked %d processors, want 0", processor.calls)
	}
	output := logs.String()
	for _, expected := range []string{`route=forward`, `msg="SMTP forwarding attempt"`, `msg="SMTP forwarding completed"`} {
		if !strings.Contains(output, expected) {
			t.Fatalf("forwarding logs missing %q: %s", expected, output)
		}
	}
}

func TestSMTPForwardingWithDKIM(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	privDER := x509.MarshalPKCS1PrivateKey(privKey)
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privDER,
	})
	pubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDER,
	})

	signer, err := dkim.NewSigner("sender.test", "default", string(privPEM), string(pubPEM))
	if err != nil {
		t.Fatal(err)
	}

	store, err := maildir.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	relayServer, relayClient := net.Pipe()
	defer relayClient.Close()
	inboundServer, inboundClient := net.Pipe()
	defer inboundClient.Close()

	var logs bytes.Buffer
	server := &Server{
		Hostname: "mail.sender.test",
		Store:    store,
		Resolve:  func(string) (string, bool) { return "", false },
		LocalDomain: func(domain string) bool {
			return strings.EqualFold(domain, "sender.test")
		},
		LookupMX: func(context.Context, string) ([]*net.MX, error) {
			return []*net.MX{{Host: "mx.remote.test", Pref: 10}}, nil
		},
		DialSMTP: func(context.Context, string) (net.Conn, error) {
			return relayClient, nil
		},
		DKIMSigner: signer.Sign,
		Authenticate: func(username, password string) bool {
			return username == "relay" && password == "secret"
		},
		Logger: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo})),
	}

	var relayed bytes.Buffer
	relayErrors := make(chan error, 1)
	go func() {
		defer relayServer.Close()
		reader := bufio.NewReader(relayServer)
		writeResponse := func(line string) error {
			_, writeErr := io.WriteString(relayServer, line+"\r\n")
			return writeErr
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
	writeLine("From: sender@sender.test\r\nTo: recipient@remote.test\r\nSubject: relay with dkim\r\n\r\nHello remote recipient")
	writeLine(".")
	if got := readLine(); !strings.HasPrefix(got, "250 ") {
		t.Fatalf("delivery response = %q", got)
	}
	if err := <-relayErrors; err != nil {
		t.Fatal(err)
	}

	relayedData := relayed.Bytes()
	if !bytes.Contains(relayedData, []byte("DKIM-Signature:")) {
		t.Fatalf("relayed message missing DKIM-Signature header: %s", string(relayedData))
	}
	if !bytes.Contains(relayedData, []byte("d=sender.test")) {
		t.Fatalf("relayed message missing domain tag in DKIM-Signature: %s", string(relayedData))
	}

	if err := dkim.Verify(relayedData, signer.PublicKey()); err != nil {
		t.Fatalf("relayed message failed DKIM verification: %v", err)
	}

	if !strings.Contains(logs.String(), `msg="SMTP DKIM signature added"`) {
		t.Fatalf("logs missing DKIM signature log: %s", logs.String())
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
	testUsername := os.Getenv("MYMAIL_TEST_USERNAME")
	if testUsername == "" {
		t.Fatal("MYMAIL_TEST_USERNAME must be set before running tests")
	}
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
			return username == testUsername && password == "changeit"
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
	writeLine("AUTH PLAIN " + base64.StdEncoding.EncodeToString([]byte("\x00"+testUsername+"\x00changeit")))
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
	credentials := base64.StdEncoding.EncodeToString([]byte("\x00" + testUsername + "\x00changeit"))
	writeTLSLine("AUTH PLAIN " + credentials)
	if response := readLine(); !strings.HasPrefix(response, "235 ") {
		t.Fatalf("TLS AUTH response = %q", response)
	}
}

func TestSMTPSpamdTrainingDelivery(t *testing.T) {
	spamdListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer spamdListener.Close()

	spamdErrors := make(chan error, 1)
	go func() {
		conn, acceptErr := spamdListener.Accept()
		if acceptErr != nil {
			spamdErrors <- acceptErr
			return
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)
		reqLine, _ := reader.ReadString('\n')
		if got, want := strings.TrimSpace(reqLine), "TELL SPAMC/1.5"; got != want {
			spamdErrors <- fmt.Errorf("request line = %q, want %q", got, want)
			return
		}
		headers := make(map[string]string)
		for {
			line, _ := reader.ReadString('\n')
			line = strings.TrimRight(line, "\r\n")
			if line == "" {
				break
			}
			name, val, ok := strings.Cut(line, ":")
			if ok {
				headers[strings.ToLower(name)] = strings.TrimSpace(val)
			}
		}
		if got, want := headers["message-class"], "spam"; got != want {
			spamdErrors <- fmt.Errorf("Message-class = %q, want %q", got, want)
			return
		}
		if got, want := headers["user"], "kpratt"; got != want {
			spamdErrors <- fmt.Errorf("User = %q, want %q", got, want)
			return
		}
		length, _ := strconv.Atoi(headers["content-length"])
		body := make([]byte, length)
		_, _ = io.ReadFull(reader, body)
		if !strings.Contains(string(body), "Subject: Casino") {
			spamdErrors <- fmt.Errorf("trained body missing casino subject: %s", string(body))
			return
		}
		_, writeErr := fmt.Fprintf(conn, "SPAMD/1.1 0 EX_OK\r\nDidSet: local\r\n\r\n")
		spamdErrors <- writeErr
	}()

	store, err := maildir.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Ensure("kpratt"); err != nil {
		t.Fatal(err)
	}

	processors := plugins.New()
	spamdPlugin := plugins.NewSpamdClient(spamdListener.Addr().String())
	if err := processors.Add(spamdPlugin); err != nil {
		t.Fatal(err)
	}
	if failures := processors.Initialize(context.Background()); len(failures) != 0 {
		t.Fatalf("processor initialization failures = %#v", failures)
	}

	server := &Server{
		Hostname:   "thepratts.info",
		Store:      store,
		Processors: processors,
		Resolve: func(address string) (string, bool) {
			if strings.EqualFold(address, "spam-kpratt@thepratts.info") {
				return "kpratt", true
			}
			return "", false
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	go server.handle(context.Background(), serverConn)

	reader := bufio.NewReader(clientConn)
	readLine := func() string {
		line, readErr := reader.ReadString('\n')
		if readErr != nil {
			t.Fatal(readErr)
		}
		return strings.TrimRight(line, "\r\n")
	}
	write := func(line string) {
		if _, writeErr := io.WriteString(clientConn, line+"\r\n"); writeErr != nil {
			t.Fatal(writeErr)
		}
	}

	readLine() // greeting
	write("EHLO localhost")
	for {
		line := readLine()
		if strings.HasPrefix(line, "250 ") {
			break
		}
	}
	write("MAIL FROM:<kenpratt@comcast.net>")
	if got := readLine(); !strings.HasPrefix(got, "250 ") {
		t.Fatalf("MAIL response = %q", got)
	}
	write("RCPT TO:<spam-kpratt@thepratts.info>")
	if got := readLine(); !strings.HasPrefix(got, "250 ") {
		t.Fatalf("RCPT response = %q", got)
	}
	write("DATA")
	if got := readLine(); !strings.HasPrefix(got, "354 ") {
		t.Fatalf("DATA response = %q", got)
	}
	forwardedEmail := "From: spammer@example.com\r\nSubject: Casino\r\n\r\nwin cash"
	outer := fmt.Sprintf("From: kenpratt@comcast.net\r\nTo: spam-kpratt@thepratts.info\r\nSubject: Fwd: Casino\r\nContent-Type: multipart/mixed; boundary=XYZ\r\n\r\n--XYZ\r\nContent-Type: message/rfc822\r\n\r\n%s\r\n--XYZ--", forwardedEmail)
	write(outer)
	write(".")
	if got := readLine(); !strings.HasPrefix(got, "250 ") {
		t.Fatalf("delivery response = %q", got)
	}

	if err := <-spamdErrors; err != nil {
		t.Fatal(err)
	}

	messages, err := store.List("kpratt")
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 1 {
		t.Fatalf("inbox messages = %d, want 1", len(messages))
	}
	deliveredData, err := os.ReadFile(messages[0].Path)
	if err != nil {
		t.Fatal(err)
	}
	deliveredText := string(deliveredData)
	if !strings.Contains(deliveredText, "SpamAssassin training output: SPAM") {
		t.Fatalf("delivered message missing training output subject: %s", deliveredText)
	}
	if !strings.Contains(deliveredText, "DidSet: local") {
		t.Fatalf("delivered message missing DidSet header info: %s", deliveredText)
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
