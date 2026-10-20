// Command mymail-send sends a test message through an SMTP server.
package main

import (
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
	server := flag.String("server", "127.0.0.1:587", "SMTP server address")
	from := flag.String("from", "", "sender address (required)")
	var to, cc, bcc addressListFlag
	flag.Var(&to, "to", "recipient address (required; repeatable or comma-separated)")
	flag.Var(&cc, "cc", "carbon-copy recipient (repeatable or comma-separated)")
	flag.Var(&bcc, "bcc", "blind carbon-copy recipient (repeatable or comma-separated)")
	subject := flag.String("subject", defaultSubject, "message subject")
	body := flag.String("body", "This is a test message from mymail-send.", "plain-text message body")
	username := flag.String("username", "", "optional SMTP username")
	password := flag.String("password", "", "optional SMTP password")
	flag.Parse()

	if *from == "" || len(to) == 0 {
		flag.Usage()
		fmt.Fprintln(os.Stderr, "-from and -to are required")
		os.Exit(2)
	}
	if (*username == "") != (*password == "") {
		fmt.Fprintln(os.Stderr, "-username and -password must be provided together")
		os.Exit(2)
	}

	if err := sendMessage(*server, *from, to, cc, bcc, *subject, *body, *username, *password); err != nil {
		fmt.Fprintf(os.Stderr, "send message: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("message sent")
}

func sendMessage(server, from string, to, cc, bcc []string, subject, body, username, password string) error {
	fromAddress, err := parseAddress(from, "from")
	if err != nil {
		return err
	}
	toAddresses, err := parseAddresses(to, "to")
	if err != nil {
		return err
	}
	ccAddresses, err := parseAddresses(cc, "cc")
	if err != nil {
		return err
	}
	bccAddresses, err := parseAddresses(bcc, "bcc")
	if err != nil {
		return err
	}
	message, err := buildMessageWithRecipients(fromAddress, toAddresses, ccAddresses, subject, body)
	if err != nil {
		return err
	}

	host, _, err := net.SplitHostPort(server)
	if err != nil {
		return fmt.Errorf("invalid SMTP server %q: %w", server, err)
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	connection, err := dialer.Dial("tcp", server)
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
	recipients := make([]*mail.Address, 0, len(toAddresses)+len(ccAddresses)+len(bccAddresses))
	recipients = append(recipients, toAddresses...)
	recipients = append(recipients, ccAddresses...)
	recipients = append(recipients, bccAddresses...)
	for _, address := range recipients {
		if err := client.Rcpt(address.Address); err != nil {
			return fmt.Errorf("set recipient %s: %w", address.Address, err)
		}
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

func parseAddresses(values []string, label string) ([]*mail.Address, error) {
	addresses := make([]*mail.Address, 0, len(values))
	for _, value := range values {
		parsed, err := mail.ParseAddressList(strings.TrimSpace(value))
		if err != nil || len(parsed) == 0 {
			if err == nil {
				err = errors.New("empty or invalid address")
			}
			return nil, fmt.Errorf("invalid %s address: %w", label, err)
		}
		for _, address := range parsed {
			if address.Address == "" || strings.ContainsAny(address.Address, "\r\n") {
				return nil, fmt.Errorf("invalid %s address: empty or invalid address", label)
			}
		}
		addresses = append(addresses, parsed...)
	}
	return addresses, nil
}

type addressListFlag []string

func (f *addressListFlag) String() string {
	return strings.Join(*f, ",")
}

func (f *addressListFlag) Set(value string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("address must not be empty")
	}
	*f = append(*f, value)
	return nil
}

func buildMessage(from, to *mail.Address, subject, body string) ([]byte, error) {
	return buildMessageWithRecipients(from, []*mail.Address{to}, nil, subject, body)
}

func buildMessageWithRecipients(from *mail.Address, to, cc []*mail.Address, subject, body string) ([]byte, error) {
	if strings.ContainsAny(subject, "\r\n") {
		return nil, errors.New("subject must not contain CR or LF")
	}
	if strings.ContainsAny(body, "\x00") {
		return nil, errors.New("message body must not contain NUL")
	}
	if len(to) == 0 {
		return nil, errors.New("at least one recipient is required")
	}
	var message strings.Builder
	fmt.Fprintf(&message, "From: %s\r\nTo: %s\r\n", headerAddress(from), headerAddresses(to))
	if len(cc) > 0 {
		message.WriteString("Cc: ")
		message.WriteString(headerAddresses(cc))
		message.WriteString("\r\n")
	}
	fmt.Fprintf(&message, "Date: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s\r\n", time.Now().UTC().Format(time.RFC1123Z), subject, body)
	return []byte(message.String()), nil
}

func headerAddresses(addresses []*mail.Address) string {
	values := make([]string, 0, len(addresses))
	for _, address := range addresses {
		values = append(values, headerAddress(address))
	}
	return strings.Join(values, ", ")
}

func headerAddress(address *mail.Address) string {
	if address.Name == "" {
		return address.Address
	}
	return address.String()
}
