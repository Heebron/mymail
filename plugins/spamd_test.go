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
