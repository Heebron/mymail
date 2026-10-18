// Command mymail-send sends a test message through an SMTP server.
package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/mail"
	"net/smtp"
	"os"
	"strings"
	"time"
)

const defaultSubject = "MyMail test message"

func main() {
	server := flag.String("server", "127.0.0.1:2525", "SMTP server address")
	from := flag.String("from", "", "sender address (required)")
	to := flag.String("to", "", "recipient address (required)")
	subject := flag.String("subject", defaultSubject, "message subject")
	body := flag.String("body", "This is a test message from mymail-send.", "plain-text message body")
	username := flag.String("username", "", "optional SMTP username")
	password := flag.String("password", "", "optional SMTP password")
	implicitTLS := flag.Bool("tls", false, "use an implicit TLS SMTP connection")
	insecure := flag.Bool("insecure-skip-verify", false, "skip TLS certificate verification")
	flag.Parse()

	if *from == "" || *to == "" {
		flag.Usage()
		fmt.Fprintln(os.Stderr, "-from and -to are required")
		os.Exit(2)
	}
	if (*username == "") != (*password == "") {
		fmt.Fprintln(os.Stderr, "-username and -password must be provided together")
		os.Exit(2)
	}

	if err := sendMessage(*server, *from, *to, *subject, *body, *username, *password, *implicitTLS, *insecure); err != nil {
		fmt.Fprintf(os.Stderr, "send message: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("message sent")
}

func sendMessage(server, from, to, subject, body, username, password string, implicitTLS, insecure bool) error {
	fromAddress, err := parseAddress(from, "from")
	if err != nil {
		return err
	}
	toAddress, err := parseAddress(to, "to")
	if err != nil {
		return err
	}
	message, err := buildMessage(fromAddress, toAddress, subject, body)
	if err != nil {
		return err
	}

	host, _, err := net.SplitHostPort(server)
	if err != nil {
		return fmt.Errorf("invalid SMTP server %q: %w", server, err)
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	var connection net.Conn
	if implicitTLS {
		connection, err = tls.DialWithDialer(dialer, "tcp", server, &tls.Config{
			MinVersion:         tls.VersionTLS12,
			ServerName:         host,
			InsecureSkipVerify: insecure, // Explicitly controlled by the command flag.
		})
	} else {
		connection, err = dialer.Dial("tcp", server)
	}
	if err != nil {
		return fmt.Errorf("connect to SMTP server: %w", err)
	}
	defer connection.Close()

	client, err := smtp.NewClient(connection, host)
	if err != nil {
		return fmt.Errorf("initialize SMTP client: %w", err)
	}
	defer client.Close()
	if username != "" {
		if err := client.Auth(smtp.PlainAuth("", username, password, host)); err != nil {
			return fmt.Errorf("authenticate with SMTP server: %w", err)
		}
	}
	if err := client.Mail(fromAddress.Address); err != nil {
		return fmt.Errorf("set sender: %w", err)
	}
	if err := client.Rcpt(toAddress.Address); err != nil {
		return fmt.Errorf("set recipient: %w", err)
	}
	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("start message: %w", err)
	}
	if _, err := writer.Write(message); err != nil {
		_ = writer.Close()
		return fmt.Errorf("write message: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("finish message: %w", err)
	}
	return nil
}

func parseAddress(value, label string) (*mail.Address, error) {
	address, err := mail.ParseAddress(strings.TrimSpace(value))
	if err != nil || address.Address == "" || strings.ContainsAny(address.Address, "\r\n") {
		if err == nil {
			err = errors.New("empty or invalid address")
		}
		return nil, fmt.Errorf("invalid %s address: %w", label, err)
	}
	return address, nil
}

func buildMessage(from, to *mail.Address, subject, body string) ([]byte, error) {
	if strings.ContainsAny(subject, "\r\n") {
		return nil, errors.New("subject must not contain CR or LF")
	}
	if strings.ContainsAny(body, "\x00") {
		return nil, errors.New("message body must not contain NUL")
	}
	message := fmt.Sprintf("From: %s\r\nTo: %s\r\nDate: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s\r\n", headerAddress(from), headerAddress(to), time.Now().UTC().Format(time.RFC1123Z), subject, body)
	return []byte(message), nil
}

func headerAddress(address *mail.Address) string {
	if address.Name == "" {
		return address.Address
	}
	return address.String()
}
