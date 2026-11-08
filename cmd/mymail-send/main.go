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

type sendOptions struct {
	server          string
	from            string
	to              []string
	cc              []string
	bcc             []string
	subject         string
	body            string
	username        string
	password        string
	startTLS        bool
	requireSTARTTLS bool
	implicitTLS     bool
	insecureTLS     bool
	insecureAuth    bool
}

func main() {
	server := flag.String("server", "127.0.0.1:587", "SMTP server address (host:port or host)")
	from := flag.String("from", "", "sender address (required)")
	var to, cc, bcc addressListFlag
	flag.Var(&to, "to", "recipient address (required; repeatable or comma-separated)")
	flag.Var(&cc, "cc", "carbon-copy recipient (repeatable or comma-separated)")
	flag.Var(&bcc, "bcc", "blind carbon-copy recipient (repeatable or comma-separated)")
	subject := flag.String("subject", defaultSubject, "message subject")
	body := flag.String("body", "This is a test message from mymail-send.", "plain-text message body")
	username := flag.String("username", "", "optional SMTP username")
	password := flag.String("password", "", "optional SMTP password")

	startTLS := flag.Bool("starttls", true, "negotiate STARTTLS if supported by the server")
	requireSTARTTLS := flag.Bool("require-starttls", false, "require STARTTLS encryption")
	implicitTLS := flag.Bool("tls", false, "use implicit TLS (SMTPS) connection from the start")
	flag.BoolVar(implicitTLS, "smtps", false, "alias for -tls")
	insecureTLS := flag.Bool("insecure-tls", false, "skip TLS certificate verification")
	flag.BoolVar(insecureTLS, "insecure-skip-verify", false, "alias for -insecure-tls")
	flag.BoolVar(insecureTLS, "k", false, "alias for -insecure-tls")
	insecureAuth := flag.Bool("insecure-auth", false, "allow plaintext authentication over unencrypted connection")
	flag.BoolVar(insecureAuth, "allow-insecure-auth", false, "alias for -insecure-auth")
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

	opts := sendOptions{
		server:          *server,
		from:            *from,
		to:              to,
		cc:              cc,
		bcc:             bcc,
		subject:         *subject,
		body:            *body,
		username:        *username,
		password:        *password,
		startTLS:        *startTLS,
		requireSTARTTLS: *requireSTARTTLS,
		implicitTLS:     *implicitTLS,
		insecureTLS:     *insecureTLS,
		insecureAuth:    *insecureAuth,
	}

	if err := sendMessage(opts); err != nil {
		fmt.Fprintf(os.Stderr, "send message: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("message sent")
}

func sendMessage(opts sendOptions) error {
	fromAddress, err := parseAddress(opts.from, "from")
	if err != nil {
		return err
	}
	toAddresses, err := parseAddresses(opts.to, "to")
	if err != nil {
		return err
	}
	ccAddresses, err := parseAddresses(opts.cc, "cc")
	if err != nil {
		return err
	}
	bccAddresses, err := parseAddresses(opts.bcc, "bcc")
	if err != nil {
		return err
	}
	message, err := buildMessageWithRecipients(fromAddress, toAddresses, ccAddresses, opts.subject, opts.body)
	if err != nil {
		return err
	}

	server := opts.server
	host, port, err := net.SplitHostPort(server)
	if err != nil {
		if strings.Contains(err.Error(), "missing port") {
			host = server
			if opts.implicitTLS {
				port = "465"
			} else {
				port = "587"
			}
			server = net.JoinHostPort(host, port)
		} else {
			return fmt.Errorf("invalid SMTP server %q: %w", server, err)
		}
	}

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	var connection net.Conn
	if opts.implicitTLS {
		tlsConfig := &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: opts.insecureTLS,
		}
		connection, err = tls.DialWithDialer(dialer, "tcp", server, tlsConfig)
		if err != nil {
			return fmt.Errorf("connect to SMTP server with TLS: %w", err)
		}
	} else {
		connection, err = dialer.Dial("tcp", server)
		if err != nil {
			return fmt.Errorf("connect to SMTP server: %w", err)
		}
	}
	defer connection.Close()

	client, err := smtp.NewClient(connection, host)
	if err != nil {
		return fmt.Errorf("initialize SMTP client: %w", err)
	}
	defer client.Close()

	if !opts.implicitTLS && opts.startTLS {
		if hasSTARTTLS, _ := client.Extension("STARTTLS"); hasSTARTTLS {
			tlsConfig := &tls.Config{
				ServerName:         host,
				InsecureSkipVerify: opts.insecureTLS,
			}
			if err := client.StartTLS(tlsConfig); err != nil {
				return fmt.Errorf("starttls with SMTP server: %w", err)
			}
		} else if opts.requireSTARTTLS {
			return errors.New("server does not advertise STARTTLS, but STARTTLS is required")
		}
	}

	if opts.username != "" {
		auth := newClientAuth("", opts.username, opts.password, host, opts.insecureAuth)
		if err := client.Auth(auth); err != nil {
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
	_ = client.Quit()
	return nil
}

type clientAuth struct {
	identity, username, password string
	host                         string
	allowInsecure                bool
	selectedMech                 string
	step                         int
}

func newClientAuth(identity, username, password, host string, allowInsecure bool) smtp.Auth {
	return &clientAuth{
		identity:      identity,
		username:      username,
		password:      password,
		host:          host,
		allowInsecure: allowInsecure,
	}
}

func (a *clientAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	if !server.TLS && !isLocalhost(server.Name) && !a.allowInsecure {
		return "", nil, errors.New("unencrypted connection (use STARTTLS or pass -insecure-auth to permit cleartext credentials)")
	}
	if server.Name != a.host && !a.allowInsecure {
		return "", nil, errors.New("wrong host name")
	}

	supportsPlain := false
	supportsLogin := false
	for _, mech := range server.Auth {
		if strings.EqualFold(mech, "PLAIN") {
			supportsPlain = true
		} else if strings.EqualFold(mech, "LOGIN") {
			supportsLogin = true
		}
	}

	if supportsPlain || (!supportsLogin && len(server.Auth) == 0) {
		a.selectedMech = "PLAIN"
		resp := []byte(a.identity + "\x00" + a.username + "\x00" + a.password)
		return "PLAIN", resp, nil
	}

	if supportsLogin {
		a.selectedMech = "LOGIN"
		a.step = 0
		return "LOGIN", nil, nil
	}

	a.selectedMech = "PLAIN"
	resp := []byte(a.identity + "\x00" + a.username + "\x00" + a.password)
	return "PLAIN", resp, nil
}

func (a *clientAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	if a.selectedMech == "LOGIN" {
		a.step++
		if a.step == 1 {
			return []byte(a.username), nil
		}
		if a.step == 2 {
			return []byte(a.password), nil
		}
		return nil, errors.New("unexpected server challenge in LOGIN auth")
	}
	return nil, errors.New("unexpected server challenge")
}

func isLocalhost(name string) bool {
	return name == "localhost" || name == "127.0.0.1" || name == "::1"
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
