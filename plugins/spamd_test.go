package plugins

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
)

func TestSpamdClientProcessesMessage(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	serverErrors := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverErrors <- acceptErr
			return
		}
		defer connection.Close()

		reader := bufio.NewReader(connection)
		requestLine, readErr := reader.ReadString('\n')
		if readErr != nil {
			serverErrors <- readErr
			return
		}
		if got, want := strings.TrimSpace(requestLine), "PROCESS SPAMC/1.5"; got != want {
			serverErrors <- fmt.Errorf("request line = %q, want %q", got, want)
			return
		}

		headers := make(map[string]string)
		for {
			line, headerErr := reader.ReadString('\n')
			if headerErr != nil {
				serverErrors <- headerErr
				return
			}
			line = strings.TrimRight(line, "\r\n")
			if line == "" {
				break
			}
			name, value, ok := strings.Cut(line, ":")
			if !ok {
				serverErrors <- fmt.Errorf("malformed request header %q", line)
				return
			}
			headers[strings.ToLower(name)] = strings.TrimSpace(value)
		}

		if got, want := headers["user"], "alice"; got != want {
			serverErrors <- fmt.Errorf("User header = %q, want %q", got, want)
			return
		}
		length, parseErr := strconv.Atoi(headers["content-length"])
		if parseErr != nil {
			serverErrors <- fmt.Errorf("Content-length = %q: %w", headers["content-length"], parseErr)
			return
		}
		body := make([]byte, length)
		if _, readErr = io.ReadFull(reader, body); readErr != nil {
			serverErrors <- readErr
			return
		}
		if got, want := string(body), "Subject: hello\r\n\r\nmessage"; got != want {
			serverErrors <- fmt.Errorf("message body = %q, want %q", got, want)
			return
		}

		responseBody := []byte("X-Spam-Status: Yes, score=7.5 required=5.0\r\nSubject: hello\r\n\r\nmessage")
		_, writeErr := fmt.Fprintf(connection, "SPAMD/1.1 0 EX_OK\r\nSpam: True ; 7.5 / 5.0\r\nContent-length: %d\r\n\r\n%s", len(responseBody), responseBody)
		serverErrors <- writeErr
	}()

	client := NewSpamdClient(listener.Addr().String())
	if err := client.Initialize(context.Background(), map[string]string{"user": "mymail"}); err != nil {
		t.Fatal(err)
	}
	message := &Message{Data: []byte("Subject: hello\r\n\r\nmessage"), Mailbox: "alice"}
	result, err := client.Process(context.Background(), message)
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision != Accept {
		t.Fatalf("result = %#v, want accepted", result)
	}
	if got, want := string(message.Data), "X-Spam-Status: Yes, score=7.5 required=5.0\r\nSubject: hello\r\n\r\nmessage"; got != want {
		t.Fatalf("message data = %q, want %q", got, want)
	}
	if err := <-serverErrors; err != nil {
		t.Fatal(err)
	}
}

func TestSpamdClientPreservesMessageOnDaemonError(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	serverErrors := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverErrors <- acceptErr
			return
		}
		defer connection.Close()
		_, writeErr := io.WriteString(connection, "SPAMD/1.5 76 EX_PROTOCOL\r\n\r\n")
		serverErrors <- writeErr
	}()

	client := NewSpamdClient(listener.Addr().String())
	message := &Message{Data: []byte("Subject: unchanged\r\n\r\nbody")}
	_, err = client.Process(context.Background(), message)
	if err == nil || !strings.Contains(err.Error(), "spamd returned status 76") {
		t.Fatalf("Process error = %v, want spamd status error", err)
	}
	if got, want := string(message.Data), "Subject: unchanged\r\n\r\nbody"; got != want {
		t.Fatalf("message data = %q, want %q", got, want)
	}
	if err := <-serverErrors; err != nil {
		t.Fatal(err)
	}
}

func TestSpamdClientRejectsMailboxWithNewline(t *testing.T) {
	client := NewSpamdClient("127.0.0.1:1")
	message := &Message{Data: []byte("message"), Mailbox: "alice\nUser: attacker"}
	_, err := client.Process(context.Background(), message)
	if err == nil || !strings.Contains(err.Error(), "spamd user contains a newline") {
		t.Fatalf("Process error = %v, want mailbox validation error", err)
	}
}

func TestSpamdClientTrainsSpamAttachedMessage(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	forwardedEmail := "From: badguy@example.com\r\nTo: kpratt@thepratts.info\r\nSubject: Buy cheap watches\r\n\r\nClick here!"
	outerMessage := fmt.Sprintf("From: kenpratt@comcast.net\r\nTo: spam-kpratt@thepratts.info\r\nSubject: Fwd: Buy cheap watches\r\nContent-Type: multipart/mixed; boundary=\"BOUNDARY\"\r\n\r\n--BOUNDARY\r\nContent-Type: text/plain\r\n\r\nForwarding spam\r\n--BOUNDARY\r\nContent-Type: message/rfc822\r\n\r\n%s\r\n--BOUNDARY--", forwardedEmail)

	serverErrors := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverErrors <- acceptErr
			return
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)
		reqLine, readErr := reader.ReadString('\n')
		if readErr != nil {
			serverErrors <- readErr
			return
		}
		if got, want := strings.TrimSpace(reqLine), "TELL SPAMC/1.5"; got != want {
			serverErrors <- fmt.Errorf("request line = %q, want %q", got, want)
			return
		}

		headers := make(map[string]string)
		for {
			line, hErr := reader.ReadString('\n')
			if hErr != nil {
				serverErrors <- hErr
				return
			}
			line = strings.TrimRight(line, "\r\n")
			if line == "" {
				break
			}
			name, val, ok := strings.Cut(line, ":")
			if !ok {
				serverErrors <- fmt.Errorf("malformed header %q", line)
				return
			}
			headers[strings.ToLower(name)] = strings.TrimSpace(val)
		}

		if got, want := headers["message-class"], "spam"; got != want {
			serverErrors <- fmt.Errorf("Message-class = %q, want %q", got, want)
			return
		}
		if got, want := headers["set"], "local"; got != want {
			serverErrors <- fmt.Errorf("Set = %q, want %q", got, want)
			return
		}
		if got, want := headers["user"], "kpratt"; got != want {
			serverErrors <- fmt.Errorf("User = %q, want %q", got, want)
			return
		}

		length, _ := strconv.Atoi(headers["content-length"])
		body := make([]byte, length)
		if _, readErr = io.ReadFull(reader, body); readErr != nil {
			serverErrors <- readErr
			return
		}
		if got, want := string(body), forwardedEmail; got != want {
			serverErrors <- fmt.Errorf("trained body = %q, want %q", got, want)
			return
		}

		_, writeErr := fmt.Fprintf(conn, "SPAMD/1.1 0 EX_OK\r\nDidSet: local\r\n\r\n")
		serverErrors <- writeErr
	}()

	client := NewSpamdClient(listener.Addr().String())
	message := &Message{
		Data:       []byte(outerMessage),
		Mailbox:    "kpratt",
		Recipients: []string{"spam-kpratt@thepratts.info"},
		From:       "kenpratt@comcast.net",
	}
	result, err := client.Process(context.Background(), message)
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision != Accept {
		t.Fatalf("Decision = %v, want Accept", result.Decision)
	}
	if message.Folder != "" {
		t.Fatalf("Folder = %q, want empty (inbox)", message.Folder)
	}
	report := string(message.Data)
	if !strings.Contains(report, "SpamAssassin training output: SPAM") {
		t.Fatalf("report missing expected subject: %s", report)
	}
	if !strings.Contains(report, "DidSet: local") {
		t.Fatalf("report missing DidSet: %s", report)
	}
	if !strings.Contains(report, "Subject: Buy cheap watches") {
		t.Fatalf("report missing forwarded subject: %s", report)
	}
	if err := <-serverErrors; err != nil {
		t.Fatal(err)
	}
}

func TestSpamdClientTrainsHamAttachedMessage(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	forwardedEmail := "From: friend@example.com\r\nTo: kpratt@thepratts.info\r\nSubject: Legitimate email\r\n\r\nHello Ken"
	outerMessage := fmt.Sprintf("From: kenpratt@comcast.net\r\nTo: ham-kpratt@thepratts.info\r\nSubject: Fwd: Legitimate email\r\nContent-Type: multipart/mixed; boundary=\"BOUNDARY\"\r\n\r\n--BOUNDARY\r\nContent-Type: message/rfc822\r\n\r\n%s\r\n--BOUNDARY--", forwardedEmail)

	serverErrors := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverErrors <- acceptErr
			return
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)
		reqLine, readErr := reader.ReadString('\n')
		if readErr != nil {
			serverErrors <- readErr
			return
		}
		if got, want := strings.TrimSpace(reqLine), "TELL SPAMC/1.5"; got != want {
			serverErrors <- fmt.Errorf("request line = %q, want %q", got, want)
			return
		}

		headers := make(map[string]string)
		for {
			line, hErr := reader.ReadString('\n')
			if hErr != nil {
				serverErrors <- hErr
				return
			}
			line = strings.TrimRight(line, "\r\n")
			if line == "" {
				break
			}
			name, val, ok := strings.Cut(line, ":")
			if !ok {
				serverErrors <- fmt.Errorf("malformed header %q", line)
				return
			}
			headers[strings.ToLower(name)] = strings.TrimSpace(val)
		}

		if got, want := headers["message-class"], "ham"; got != want {
			serverErrors <- fmt.Errorf("Message-class = %q, want %q", got, want)
			return
		}
		if got, want := headers["set"], "local"; got != want {
			serverErrors <- fmt.Errorf("Set = %q, want %q", got, want)
			return
		}

		length, _ := strconv.Atoi(headers["content-length"])
		body := make([]byte, length)
		if _, readErr = io.ReadFull(reader, body); readErr != nil {
			serverErrors <- readErr
			return
		}
		if got, want := string(body), forwardedEmail; got != want {
			serverErrors <- fmt.Errorf("trained body = %q, want %q", got, want)
			return
		}

		_, writeErr := fmt.Fprintf(conn, "SPAMD/1.1 0 EX_OK\r\nDidSet: local\r\n\r\n")
		serverErrors <- writeErr
	}()

	client := NewSpamdClient(listener.Addr().String())
	message := &Message{
		Data:       []byte(outerMessage),
		Mailbox:    "kpratt",
		Recipients: []string{"ham-kpratt@thepratts.info"},
		From:       "kenpratt@comcast.net",
	}
	result, err := client.Process(context.Background(), message)
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision != Accept {
		t.Fatalf("Decision = %v, want Accept", result.Decision)
	}
	report := string(message.Data)
	if !strings.Contains(report, "SpamAssassin training output: HAM") {
		t.Fatalf("report missing expected subject: %s", report)
	}
	if err := <-serverErrors; err != nil {
		t.Fatal(err)
	}
}

func TestSpamdClientTrainsMultipleAttachments(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	forwarded1 := "From: spam1@example.com\r\nTo: kpratt@thepratts.info\r\nSubject: Spam One\r\n\r\nBody 1"
	forwarded2 := "From: spam2@example.com\r\nTo: kpratt@thepratts.info\r\nSubject: Spam Two\r\n\r\nBody 2"
	outerMessage := fmt.Sprintf("From: kenpratt@comcast.net\r\nTo: spam-kpratt@thepratts.info\r\nSubject: Fwd: multiple\r\nContent-Type: multipart/mixed; boundary=\"B\"\r\n\r\n--B\r\nContent-Type: message/rfc822\r\n\r\n%s\r\n--B\r\nContent-Type: message/rfc822\r\n\r\n%s\r\n--B--", forwarded1, forwarded2)

	serverErrors := make(chan error, 2)
	go func() {
		for i := 0; i < 2; i++ {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				serverErrors <- acceptErr
				return
			}
			func(c net.Conn) {
				defer c.Close()
				reader := bufio.NewReader(c)
				reqLine, _ := reader.ReadString('\n')
				if got, want := strings.TrimSpace(reqLine), "TELL SPAMC/1.5"; got != want {
					serverErrors <- fmt.Errorf("request line = %q, want %q", got, want)
					return
				}
				for {
					line, _ := reader.ReadString('\n')
					if strings.TrimRight(line, "\r\n") == "" {
						break
					}
				}
				_, writeErr := fmt.Fprintf(c, "SPAMD/1.1 0 EX_OK\r\nDidSet: local\r\n\r\n")
				serverErrors <- writeErr
			}(conn)
		}
	}()

	client := NewSpamdClient(listener.Addr().String())
	message := &Message{
		Data:       []byte(outerMessage),
		Mailbox:    "kpratt",
		Recipients: []string{"spam-kpratt@thepratts.info"},
	}
	result, err := client.Process(context.Background(), message)
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision != Accept {
		t.Fatalf("Decision = %v, want Accept", result.Decision)
	}
	report := string(message.Data)
	if !strings.Contains(report, "Trained message count: 2") {
		t.Fatalf("report missing count 2: %s", report)
	}
	if !strings.Contains(report, "Subject: Spam One") || !strings.Contains(report, "Subject: Spam Two") {
		t.Fatalf("report missing subjects: %s", report)
	}
	for i := 0; i < 2; i++ {
		if err := <-serverErrors; err != nil {
			t.Fatal(err)
		}
	}
}

func TestSpamdClientTrainsInlineMessage(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	rawEmail := "From: spam-sender@example.com\r\nTo: alice@example.test\r\nSubject: Simple Spam\r\n\r\nSpam Content"

	serverErrors := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverErrors <- acceptErr
			return
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)
		reqLine, _ := reader.ReadString('\n')
		if got, want := strings.TrimSpace(reqLine), "TELL SPAMC/1.5"; got != want {
			serverErrors <- fmt.Errorf("request line = %q, want %q", got, want)
			return
		}
		for {
			line, _ := reader.ReadString('\n')
			if strings.TrimRight(line, "\r\n") == "" {
				break
			}
		}
		_, writeErr := fmt.Fprintf(conn, "SPAMD/1.1 0 EX_OK\r\nDidSet: local\r\n\r\n")
		serverErrors <- writeErr
	}()

	client := NewSpamdClient(listener.Addr().String())
	// Test From header prefix triggering training
	message := &Message{
		Data:       []byte(rawEmail),
		Mailbox:    "alice",
		Recipients: []string{"alice@example.test"},
	}
	result, err := client.Process(context.Background(), message)
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision != Accept {
		t.Fatalf("Decision = %v, want Accept", result.Decision)
	}
	if err := <-serverErrors; err != nil {
		t.Fatal(err)
	}
}
