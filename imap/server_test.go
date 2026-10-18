package imap

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

	"mymail/maildir"
)

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

func TestHandleAuthenticatePlain(t *testing.T) {
	store, err := maildir.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	server := &Server{
		Hostname: "mail.example.test",
		Store:    store,
		Resolve: func(username string) (string, bool) {
			return "kpratt", strings.EqualFold(username, "kpratt")
		},
		Authenticate: func(username, password string) bool {
			return username == "kpratt" && password == "changeit"
		},
		Logger: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo})),
	}
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go server.handle(ctx, serverConn)

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
		if _, writeErr := fmt.Fprintf(clientConn, "%s\r\n", line); writeErr != nil {
			t.Fatal(writeErr)
		}
	}

	if greeting := readLine(); greeting != "* OK mail.example.test MyMail IMAP4rev1 ready" {
		t.Fatalf("greeting = %q", greeting)
	}
	writeLine("a001 AUTHENTICATE PLAIN")
	if challenge := readLine(); challenge != "+ " {
		t.Fatalf("challenge = %q", challenge)
	}
	response := base64.StdEncoding.EncodeToString([]byte("\x00kpratt\x00changeit"))
	writeLine(response)
	if result := readLine(); !strings.HasPrefix(result, "a001 OK") {
		t.Fatalf("authentication result = %q", result)
	}
	if !strings.Contains(logs.String(), "command=AUTHENTICATE") {
		t.Fatalf("authentication action was not logged: %q", logs.String())
	}
	if strings.Contains(logs.String(), response) || strings.Contains(logs.String(), "changeit") {
		t.Fatalf("authentication secret was logged: %q", logs.String())
	}
}

func TestIMAPActionLoggingRedactsCredentials(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo}))

	logger.Info("IMAP action", "remote_addr", "127.0.0.1:12345", "tag", "a001", "command", "LOGIN", "arguments", imapLogArguments("LOGIN", []string{"kpratt", "changeit"}), "username", "", "mailbox", "", "authenticated", false, "selected", false, "readonly", false)
	logger.Info("IMAP action", "remote_addr", "127.0.0.1:12345", "tag", "a002", "command", "AUTHENTICATE", "arguments", imapLogArguments("AUTHENTICATE", []string{"PLAIN", "AGtwcmF0dABjaGFuZ2VpdA=="}), "username", "", "mailbox", "", "authenticated", false, "selected", false, "readonly", false)

	output := logs.String()
	if !strings.Contains(output, "command=LOGIN") || !strings.Contains(output, "command=AUTHENTICATE") {
		t.Fatalf("action logs = %q", output)
	}
	for _, secret := range []string{"changeit", "AGtwcmF0dABjaGFuZ2VpdA=="} {
		if strings.Contains(output, secret) {
			t.Fatalf("action logs contain secret %q: %q", secret, output)
		}
	}
	if !strings.Contains(output, "arguments=\"[kpratt [REDACTED]]\"") {
		t.Fatalf("LOGIN arguments were not redacted: %q", output)
	}
	if !strings.Contains(output, "arguments=\"[PLAIN [REDACTED]]\"") {
		t.Fatalf("AUTHENTICATE arguments were not redacted: %q", output)
	}
}

func TestHandleAppendLiteral(t *testing.T) {
	store, err := maildir.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{
		Hostname: "mail.example.test",
		Store:    store,
		Resolve: func(username string) (string, bool) {
			return "kpratt", strings.EqualFold(username, "kpratt")
		},
		Authenticate: func(username, password string) bool {
			return username == "kpratt" && password == "changeit"
		},
		Logger: slog.Default(),
	}
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go server.handle(ctx, serverConn)

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
		if _, writeErr := fmt.Fprintf(clientConn, "%s\r\n", line); writeErr != nil {
			t.Fatal(writeErr)
		}
	}

	if greeting := readLine(); !strings.HasPrefix(greeting, "* OK") {
		t.Fatalf("greeting = %q", greeting)
	}
	writeLine("a001 LOGIN kpratt changeit")
	if result := readLine(); !strings.HasPrefix(result, "a001 OK") {
		t.Fatalf("login result = %q", result)
	}
	message := []byte("From: sender@example.test\r\nSubject: copied\r\n\r\nhello\r\n")
	writeLine(fmt.Sprintf("a002 APPEND INBOX (\\Seen) \"18-Oct-2026 09:51:00 +0000\" {%d}", len(message)))
	if response := readLine(); response != "+ Ready for literal data" {
		t.Fatalf("literal response = %q", response)
	}
	if _, err := clientConn.Write(message); err != nil {
		t.Fatal(err)
	}
	if result := readLine(); result != "a002 OK [APPENDUID 1 1] APPEND completed" {
		t.Fatalf("append result = %q", result)
	}
	secondMessage := []byte("From: second@example.test\r\nSubject: copied second\r\n\r\nsecond body\r\n")
	writeLine(fmt.Sprintf("a003 APPEND INBOX {%d}", len(secondMessage)))
	if response := readLine(); response != "+ Ready for literal data" {
		t.Fatalf("second literal response = %q", response)
	}
	if _, err := clientConn.Write(secondMessage); err != nil {
		t.Fatal(err)
	}
	if result := readLine(); result != "a003 OK [APPENDUID 1 2] APPEND completed" {
		t.Fatalf("second append result = %q", result)
	}
	writeLine("")
	writeLine("a004 NOOP")
	if result := readLine(); result != "a004 OK NOOP completed" {
		t.Fatalf("post-append NOOP result = %q", result)
	}

	messages, err := store.List("kpratt")
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 2 {
		t.Fatalf("stored messages = %d, want 2", len(messages))
	}
	data, err := store.Read(messages[0])
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(message) {
		t.Fatalf("stored message = %q, want %q", data, message)
	}
	if !messages[0].Flags['S'] {
		t.Fatalf("stored message flags = %#v, want Seen", messages[0].Flags)
	}
	secondData, err := store.Read(messages[1])
	if err != nil {
		t.Fatal(err)
	}
	if string(secondData) != string(secondMessage) {
		t.Fatalf("second stored message = %q, want %q", secondData, secondMessage)
	}
}

func TestHandleAppendVisibleThroughUIDRefresh(t *testing.T) {
	store, err := maildir.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{
		Hostname: "mail.example.test",
		Store:    store,
		Resolve: func(username string) (string, bool) {
			return "kpratt", strings.EqualFold(username, "kpratt")
		},
		Authenticate: func(username, password string) bool {
			return username == "kpratt" && password == "changeit"
		},
		Logger: slog.Default(),
	}
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go server.handle(ctx, serverConn)

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
		if _, writeErr := fmt.Fprintf(clientConn, "%s\r\n", line); writeErr != nil {
			t.Fatal(writeErr)
		}
	}

	if greeting := readLine(); !strings.HasPrefix(greeting, "* OK") {
		t.Fatalf("greeting = %q", greeting)
	}
	writeLine("a001 LOGIN kpratt changeit")
	if result := readLine(); !strings.HasPrefix(result, "a001 OK") {
		t.Fatalf("login result = %q", result)
	}
	writeLine("a002 SELECT INBOX")
	for index := 0; index < 5; index++ {
		readLine()
	}

	message := []byte("From: sender@example.test\r\nSubject: copied\r\n\r\nhello\r\n")
	writeLine(fmt.Sprintf("a003 APPEND INBOX {%d}", len(message)))
	if response := readLine(); response != "+ Ready for literal data" {
		t.Fatalf("literal response = %q", response)
	}
	if _, err := clientConn.Write(message); err != nil {
		t.Fatal(err)
	}
	if response := readLine(); response != "* 1 EXISTS" {
		t.Fatalf("append exists response = %q", response)
	}
	if result := readLine(); !strings.HasPrefix(result, "a003 OK") {
		t.Fatalf("append result = %q", result)
	}

	writeLine("a004 UID SEARCH ALL")
	if result := readLine(); result != "* SEARCH 1" {
		t.Fatalf("UID search result = %q", result)
	}
	if result := readLine(); !strings.HasPrefix(result, "a004 OK") {
		t.Fatalf("UID search completion = %q", result)
	}

	writeLine("a005 UID FETCH 1:* (UID BODY.PEEK[])")
	fetch := readLine()
	if !strings.Contains(fetch, "UID 1") {
		t.Fatalf("UID fetch result = %q", fetch)
	}
	fetched := make([]byte, len(message))
	if _, err := io.ReadFull(reader, fetched); err != nil {
		t.Fatal(err)
	}
	if string(fetched) != string(message) {
		t.Fatalf("fetched message = %q, want %q", fetched, message)
	}
	if closing := readLine(); closing != ")" {
		t.Fatalf("UID fetch closing response = %q", closing)
	}
	if result := readLine(); !strings.HasPrefix(result, "a005 OK") {
		t.Fatalf("UID fetch completion = %q", result)
	}

	writeLine("a006 UID STORE 1 +FLAGS (\\Seen)")
	if result := readLine(); result != "* 1 FETCH (UID 1 FLAGS (\\Seen))" {
		t.Fatalf("UID STORE set response = %q", result)
	}
	if result := readLine(); !strings.HasPrefix(result, "a006 OK STORE") {
		t.Fatalf("UID STORE set completion = %q", result)
	}

	writeLine("a007 UID STORE 1 -FLAGS (\\Seen)")
	if result := readLine(); result != "* 1 FETCH (UID 1 FLAGS ())" {
		t.Fatalf("UID STORE clear response = %q", result)
	}
	if result := readLine(); !strings.HasPrefix(result, "a007 OK STORE") {
		t.Fatalf("UID STORE clear completion = %q", result)
	}
	messages, err := store.List("kpratt")
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 1 || messages[0].Flags['S'] {
		t.Fatalf("stored flags after UID STORE = %#v, want unread", messages)
	}
}

func TestCopyAndUIDExpunge(t *testing.T) {
	store, err := maildir.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Deliver("kpratt", []byte("Subject: first\r\n\r\nfirst\r\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Deliver("kpratt", []byte("Subject: second\r\n\r\nsecond\r\n")); err != nil {
		t.Fatal(err)
	}
	messages, err := store.List("kpratt")
	if err != nil {
		t.Fatal(err)
	}
	deleted := messages[0]
	deleted.Flags['D'] = true
	if _, err := store.SetFlags("kpratt", deleted, deleted.Flags); err != nil {
		t.Fatal(err)
	}

	server := &Server{Store: store}
	state := &session{mailbox: "kpratt", selected: true}
	var responses []string
	write := func(format string, args ...any) error {
		responses = append(responses, fmt.Sprintf(format, args...))
		return nil
	}
	server.copy("a001", []string{"2", "INBOX"}, state, write, true)
	if len(responses) != 1 || !strings.Contains(responses[0], "COPYUID 1 2 3") {
		t.Fatalf("copy responses = %#v", responses)
	}
	responses = nil
	server.expungeUID("a002", []string{"1:*"}, state, write)
	if len(responses) != 2 || responses[0] != "* 1 EXPUNGE" || responses[1] != "a002 OK UID EXPUNGE completed" {
		t.Fatalf("expunge responses = %#v", responses)
	}
	remaining, err := store.List("kpratt")
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 2 {
		t.Fatalf("remaining messages = %d, want 2", len(remaining))
	}
}

func TestCreateListAndSelectFolder(t *testing.T) {
	store, err := maildir.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{
		Hostname: "mail.example.test",
		Store:    store,
		Resolve: func(username string) (string, bool) {
			return "kpratt", strings.EqualFold(username, "kpratt")
		},
		Authenticate: func(username, password string) bool {
			return username == "kpratt" && password == "changeit"
		},
		Logger: slog.Default(),
	}
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go server.handle(ctx, serverConn)

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
		if _, writeErr := fmt.Fprintf(clientConn, "%s\r\n", line); writeErr != nil {
			t.Fatal(writeErr)
		}
	}

	readLine()
	writeLine("a001 LOGIN kpratt changeit")
	if result := readLine(); !strings.HasPrefix(result, "a001 OK") {
		t.Fatalf("login result = %q", result)
	}
	writeLine("a002 CREATE Projects")
	if result := readLine(); result != "a002 OK CREATE completed" {
		t.Fatalf("create result = %q", result)
	}
	writeLine("a003 LIST \"\" \"*\"")
	listLines := []string{readLine(), readLine(), readLine()}
	if !strings.Contains(strings.Join(listLines, "\n"), `"Projects"`) {
		t.Fatalf("list result = %#v", listLines)
	}
	writeLine("a004 SELECT Projects")
	selectLines := []string{readLine(), readLine(), readLine(), readLine(), readLine()}
	if result := selectLines[len(selectLines)-1]; result != "a004 OK [READ-WRITE] SELECT completed" {
		t.Fatalf("select result = %#v", selectLines)
	}
}
