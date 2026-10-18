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
	"os"
	"strings"
	"testing"
	"time"

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

func TestIdleReportsNewMessages(t *testing.T) {
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
		Logger: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
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
		if _, writeErr := fmt.Fprintf(clientConn, "%s\r\n", line); writeErr != nil {
			t.Fatal(writeErr)
		}
	}

	if greeting := readLine(); !strings.HasPrefix(greeting, "* OK") {
		t.Fatalf("greeting = %q", greeting)
	}
	writeLine("a001 LOGIN kpratt changeit")
	if result := readLine(); !strings.HasPrefix(result, "a001 OK") || !strings.Contains(result, " IDLE ") {
		t.Fatalf("login result = %q", result)
	}
	writeLine("a002 SELECT INBOX")
	for i := 0; i < 5; i++ {
		readLine()
	}
	writeLine("a003 IDLE")
	if result := readLine(); result != "+ idling" {
		t.Fatalf("idle result = %q", result)
	}
	if _, err := store.Deliver("kpratt", []byte("Subject: idle\r\n\r\nmessage\r\n")); err != nil {
		t.Fatal(err)
	}
	if messages, err := store.List("kpratt"); err != nil || len(messages) != 1 {
		t.Fatalf("delivered messages = %d, error = %v", len(messages), err)
	}
	if err := clientConn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	line, readErr := reader.ReadString('\n')
	if readErr != nil || strings.TrimRight(line, "\r\n") != "* 1 EXISTS" {
		t.Fatalf("idle update = %q, error = %v, logs = %q", strings.TrimRight(line, "\r\n"), readErr, logs.String())
	}
	if recent := readLine(); recent != "* 1 RECENT" {
		t.Fatalf("idle recent update = %q", recent)
	}
	messages, listErr := store.List("kpratt")
	if listErr != nil || len(messages) != 1 || messages[0].Flags['S'] {
		t.Fatalf("delivered message flags = %#v, error = %v; want unread", messages, listErr)
	}
	if err := clientConn.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	writeLine("DONE")
	if result := readLine(); result != "a003 OK IDLE terminated" {
		t.Fatalf("idle completion = %q", result)
	}
	if _, err := store.Deliver("kpratt", []byte("Subject: idle before command\r\n\r\nmessage\r\n")); err != nil {
		t.Fatal(err)
	}
	writeLine("a004 IDLE")
	if result := readLine(); result != "+ idling" {
		t.Fatalf("second idle result = %q", result)
	}
	if exists := readLine(); exists != "* 2 EXISTS" {
		t.Fatalf("idle catch-up exists = %q", exists)
	}
	if recent := readLine(); recent != "* 2 RECENT" {
		t.Fatalf("idle catch-up recent = %q", recent)
	}
	writeLine("DONE")
	if result := readLine(); result != "a004 OK IDLE terminated" {
		t.Fatalf("second idle completion = %q", result)
	}
}

func TestIdleReportsFlagChanges(t *testing.T) {
	store, err := maildir.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Deliver("alice", []byte("Subject: flag change\r\n\r\nmessage\r\n")); err != nil {
		t.Fatal(err)
	}
	before, err := store.List("alice")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetFlags("alice", before[0], map[byte]bool{'S': true}); err != nil {
		t.Fatal(err)
	}
	after, err := store.List("alice")
	if err != nil {
		t.Fatal(err)
	}
	var responses []string
	err = writeIdleChanges(func(format string, args ...any) error {
		responses = append(responses, fmt.Sprintf(format, args...))
		return nil
	}, idleMessagesByUID(before), after)
	if err != nil {
		t.Fatal(err)
	}
	if len(responses) != 1 || responses[0] != fmt.Sprintf("* 1 FETCH (UID %d FLAGS (\\Seen))", before[0].UID) {
		t.Fatalf("idle flag responses = %#v", responses)
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
	if _, err := store.Deliver("kpratt", []byte("From: second@example.test\r\nSubject: delivered\r\n\r\nsecond\r\n")); err != nil {
		t.Fatal(err)
	}
	writeLine("a004b UID SEARCH UID 2:*")
	if result := readLine(); result != "* SEARCH 2" {
		t.Fatalf("UID range search result = %q", result)
	}
	if result := readLine(); !strings.HasPrefix(result, "a004b OK") {
		t.Fatalf("UID range search completion = %q", result)
	}

	writeLine("a005 UID FETCH 1 (UID BODY.PEEK[])")
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
	if len(messages) != 2 || messages[0].Flags['S'] {
		t.Fatalf("stored messages after UID STORE = %#v, want two messages with the first unread", messages)
	}
}

func TestUIDFetchKeepsUIDForNewMessageWhenDateOrderChanges(t *testing.T) {
	store, err := maildir.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.Deliver("alice", []byte("Subject: first\r\n\r\nfirst\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.List("alice"); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Hour)
	if err := os.Chtimes(first.Path, future, future); err != nil {
		t.Fatal(err)
	}
	second, err := store.Deliver("alice", []byte("Subject: second\r\n\r\nsecond\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{Store: store}
	state := &session{authenticated: true, selected: true, mailbox: "alice"}
	var output bytes.Buffer
	writer := bufio.NewWriter(&output)
	server.fetch("a001", []string{"2", "(UID BODY.PEEK[])"}, state, writer, true)
	if got := output.String(); !strings.Contains(got, "second") || strings.Contains(got, "first") {
		t.Fatalf("UID 2 fetch = %q; want the newly delivered message %q", got, second.Filename)
	}
}

func TestUIDFetchReturnsRequestedBodySections(t *testing.T) {
	store, err := maildir.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Deliver("alice", []byte("From: sender@example.test\r\nTo: alice@example.test\r\nSubject: section test\r\n\r\nmessage body\r\n")); err != nil {
		t.Fatal(err)
	}
	server := &Server{Store: store}
	state := &session{authenticated: true, selected: true, mailbox: "alice"}
	var output bytes.Buffer
	writer := bufio.NewWriter(&output)
	server.fetch("a001", []string{"1", "(UID BODY.PEEK[HEADER.FIELDS (FROM SUBJECT)] BODY.PEEK[TEXT])"}, state, writer, true)
	got := output.String()
	if !strings.Contains(got, "BODY[HEADER.FIELDS (FROM SUBJECT)]") || strings.Contains(got, "BODY.PEEK[") || !strings.Contains(got, "From: sender@example.test\r\n") || !strings.Contains(got, "Subject: section test\r\n") {
		t.Fatalf("header fetch response = %q", got)
	}
	if strings.Contains(got, "To: alice@example.test\r\n") {
		t.Fatalf("header fetch returned an unrequested field: %q", got)
	}
	if !strings.Contains(got, "BODY[TEXT]") || !strings.Contains(got, "message body\r\n") {
		t.Fatalf("text fetch response = %q", got)
	}
	messages, err := store.List("alice")
	if err != nil || len(messages) != 1 || messages[0].Flags['S'] {
		t.Fatalf("PEEK fetch changed message flags = %#v, error = %v; want unread", messages, err)
	}
}

func TestUIDFetchReturnsEvolutionMessageMetadata(t *testing.T) {
	store, err := maildir.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("From: sender@example.test\r\nTo: alice@example.test\r\nDate: Sun, 18 Oct 2026 15:19:34 +0000\r\nSubject: Evolution metadata\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\nmessage body\r\n")
	if _, err := store.Deliver("alice", message); err != nil {
		t.Fatal(err)
	}
	server := &Server{Store: store}
	state := &session{authenticated: true, selected: true, mailbox: "alice"}
	var output bytes.Buffer
	writer := bufio.NewWriter(&output)
	server.fetch("a001", []string{"1", "(UID RFC822.SIZE FLAGS INTERNALDATE BODYSTRUCTURE ENVELOPE BODY.PEEK[HEADER.FIELDS (FROM SUBJECT CONTENT-TYPE)])"}, state, writer, true)
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}
	got := output.String()
	for _, field := range []string{"RFC822.SIZE", "FLAGS", "INTERNALDATE", "BODYSTRUCTURE", "ENVELOPE", "BODY[HEADER.FIELDS (FROM SUBJECT CONTENT-TYPE)]"} {
		if !strings.Contains(got, field) {
			t.Fatalf("Evolution fetch response = %q; missing %s", got, field)
		}
	}
}

func TestHeaderFetchKeepsMessageUnread(t *testing.T) {
	store, err := maildir.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Deliver("alice", []byte("From: sender@example.test\r\nSubject: unread test\r\n\r\nmessage body\r\n")); err != nil {
		t.Fatal(err)
	}
	server := &Server{Store: store}
	state := &session{authenticated: true, selected: true, mailbox: "alice"}
	var output bytes.Buffer
	writer := bufio.NewWriter(&output)
	server.fetch("a001", []string{"1", "(UID BODY[HEADER.FIELDS (FROM SUBJECT)])"}, state, writer, true)
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "FLAGS (\\Recent)") {
		t.Fatalf("new message fetch flags = %q; want \\Recent", output.String())
	}
	messages, err := store.List("alice")
	if err != nil || len(messages) != 1 || messages[0].Flags['S'] {
		t.Fatalf("header fetch changed message flags = %#v, error = %v; want unread", messages, err)
	}
	output.Reset()
	server.fetch("a002", []string{"1", "(UID BODY[])"}, state, writer, true)
	messages, err = store.List("alice")
	if err != nil || len(messages) != 1 || !messages[0].Flags['S'] {
		t.Fatalf("full body fetch flags = %#v, error = %v; want Seen", messages, err)
	}
	if strings.Contains(output.String(), "\\Recent") {
		t.Fatalf("seen message fetch still reported \\Recent: %q", output.String())
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

func TestCopyToSlashQualifiedFolder(t *testing.T) {
	store, err := maildir.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Deliver("kpratt", []byte("Subject: source\r\n\r\nbody\r\n")); err != nil {
		t.Fatal(err)
	}
	if err := store.Ensure("kpratt/BitcoinLayer"); err != nil {
		t.Fatal(err)
	}

	server := &Server{Store: store}
	state := &session{rootMailbox: "kpratt", mailbox: "kpratt", selected: true}
	var responses []string
	write := func(format string, args ...any) error {
		responses = append(responses, fmt.Sprintf(format, args...))
		return nil
	}
	server.copy("a001", []string{"1", "INBOX/BitcoinLayer"}, state, write, false)
	if len(responses) != 1 || responses[0] != "a001 OK COPY completed" {
		t.Fatalf("copy responses = %#v", responses)
	}
	messages, err := store.List("kpratt/BitcoinLayer")
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 1 {
		t.Fatalf("destination messages = %d, want 1", len(messages))
	}
}

func TestNestedInboxFolderMailboxResolution(t *testing.T) {
	mailbox, ok := resolveMailbox("kpratt", "INBOX/Projects/2026")
	if !ok || mailbox != "kpratt/Projects.2026" {
		t.Fatalf("resolved mailbox = %q, %v; want kpratt/Projects.2026, true", mailbox, ok)
	}
	if _, ok := resolveMailbox("kpratt", "INBOX/Projects//2026"); ok {
		t.Fatal("empty nested folder component was accepted")
	}
}

func TestListAdvertisesInboxChildFolder(t *testing.T) {
	store, err := maildir.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Ensure("kpratt/Cigna"); err != nil {
		t.Fatal(err)
	}

	server := &Server{Store: store}
	state := &session{rootMailbox: "kpratt", authenticated: true}
	var response bytes.Buffer
	writer := bufio.NewWriter(&response)
	server.listMailboxes("a001", []string{"", "*"}, state, writer, "LIST")

	if !strings.Contains(response.String(), `"INBOX.Cigna"`) {
		t.Fatalf("LIST response = %q, want INBOX.Cigna", response.String())
	}
}

func TestStatusQuotesMailboxWithSpaces(t *testing.T) {
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
	writeLine(`a002 CREATE "Folder With Space"`)
	if result := readLine(); result != "a002 OK CREATE completed" {
		t.Fatalf("create result = %q", result)
	}
	writeLine(`a003 STATUS "Folder With Space" (MESSAGES UNSEEN)`)
	status := readLine()
	if status != `* STATUS "Folder With Space" (MESSAGES 0 RECENT 0 UNSEEN 0 UIDNEXT 1 UIDVALIDITY 1)` {
		t.Fatalf("status result = %q", status)
	}
	if result := readLine(); result != "a003 OK STATUS completed" {
		t.Fatalf("status completion = %q", result)
	}
}

func TestSelectReportsRecentMessages(t *testing.T) {
	store, err := maildir.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Deliver("alice", []byte("Subject: recent\r\n\r\nmessage\r\n")); err != nil {
		t.Fatal(err)
	}
	server := &Server{
		Hostname: "mail.example.test",
		Store:    store,
		Resolve: func(username string) (string, bool) {
			return "alice", strings.EqualFold(username, "alice")
		},
		Authenticate: func(username, password string) bool {
			return username == "alice" && password == "secret"
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
	writeLine("a001 LOGIN alice secret")
	if result := readLine(); !strings.HasPrefix(result, "a001 OK") {
		t.Fatalf("login result = %q", result)
	}
	writeLine("a002 SELECT INBOX")
	readLine()
	if recent := readLine(); recent != "* 1 RECENT" {
		t.Fatalf("recent response = %q, want %q", recent, "* 1 RECENT")
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
	if !strings.Contains(strings.Join(listLines, "\n"), `"INBOX.Projects"`) {
		t.Fatalf("list result = %#v", listLines)
	}
	writeLine("a004 SELECT Projects")
	selectLines := []string{readLine(), readLine(), readLine(), readLine(), readLine()}
	if result := selectLines[len(selectLines)-1]; result != "a004 OK [READ-WRITE] SELECT completed" {
		t.Fatalf("select result = %#v", selectLines)
	}
	writeLine("a005 CREATE INBOX/Projects/2026")
	if result := readLine(); result != "a005 OK CREATE completed" {
		t.Fatalf("nested create result = %q", result)
	}
	writeLine("a006 SELECT INBOX/Projects/2026")
	selectLines = []string{readLine(), readLine(), readLine(), readLine(), readLine()}
	if result := selectLines[len(selectLines)-1]; result != "a006 OK [READ-WRITE] SELECT completed" {
		t.Fatalf("nested select result = %#v", selectLines)
	}
	writeLine("a007 RENAME INBOX/Projects/2026 INBOX/Archive/2026")
	if result := readLine(); result != "a007 OK RENAME completed" {
		t.Fatalf("rename result = %q", result)
	}
	writeLine("a008 SELECT INBOX/Archive/2026")
	selectLines = []string{readLine(), readLine(), readLine(), readLine(), readLine()}
	if result := selectLines[len(selectLines)-1]; result != "a008 OK [READ-WRITE] SELECT completed" {
		t.Fatalf("renamed select result = %#v", selectLines)
	}
	writeLine("a009 RENAME Archive/2026 INBOX/Archive/2026")
	if result := readLine(); result != "a009 OK RENAME completed" {
		t.Fatalf("equivalent rename result = %q", result)
	}
	writeLine("a010 DELETE INBOX/Archive")
	if result := readLine(); result != "a010 OK DELETE completed" {
		t.Fatalf("delete result = %q", result)
	}
	if folders, err := store.ListMailboxes("kpratt"); err != nil || len(folders) != 1 || folders[0] != "Projects" {
		t.Fatalf("remaining folders after delete = %#v, error = %v", folders, err)
	}
	writeLine("a011 DELETE Projects")
	if result := readLine(); result != "a011 OK DELETE completed" {
		t.Fatalf("second delete result = %q", result)
	}
	if folders, err := store.ListMailboxes("kpratt"); err != nil || len(folders) != 0 {
		t.Fatalf("remaining folders after second delete = %#v, error = %v", folders, err)
	}
}
