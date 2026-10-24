// Package smtp implements the receiving SMTP service.
package smtp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/mail"
	"sort"
	"strconv"
	"strings"
	"time"

	"mymail/auth"
	"mymail/maildir"
	"mymail/plugins"
)

const maxMessageBytes = 50 << 20

type Resolver func(address string) (mailbox string, ok bool)
type DomainResolver func(domain string) bool
type MXLookup func(context.Context, string) ([]*net.MX, error)
type SMTPDialer func(context.Context, string) (net.Conn, error)
type Authenticator func(username, password string) bool

type Server struct {
	Addr            string
	StartTLSConfig  *tls.Config
	RequireSTARTTLS bool
	Hostname        string
	Store           *maildir.Store
	Processors      *plugins.Chain
	Resolve         Resolver
	LocalDomain     DomainResolver
	LookupMX        MXLookup
	DialSMTP        SMTPDialer
	Authenticate    Authenticator
	AuthLimiter     *auth.Limiter
	Logger          *slog.Logger
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	if s.Store == nil || s.Resolve == nil {
		return errors.New("smtp server requires a store and recipient resolver")
	}
	if s.Hostname == "" {
		s.Hostname = "localhost"
	}
	if s.Logger == nil {
		s.Logger = slog.Default()
	}
	listener, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return fmt.Errorf("listen SMTP on %s: %w", s.Addr, err)
	}
	s.Logger.Info("SMTP server listening", "address", listener.Addr().String(), "tls", false)
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			var temporary interface{ Temporary() bool }
			if errors.As(err, &temporary) && temporary.Temporary() {
				s.Logger.Warn("temporary SMTP accept error", "error", err)
				continue
			}
			return err
		}
		go s.handle(ctx, conn)
	}
}

func (s *Server) logger() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}

func (s *Server) startTLSConfig() *tls.Config {
	return s.StartTLSConfig
}

func messageSubject(data []byte) string {
	message, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		return ""
	}
	subject := message.Header.Get("Subject")
	if subject == "" {
		return ""
	}
	decoded, err := (&mime.WordDecoder{}).DecodeHeader(subject)
	if err != nil {
		return subject
	}
	return decoded
}

type transaction struct {
	started    bool
	from       string
	recipients []string
	mailboxes  []string
	forward    []string
}

func (s *Server) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	logger := s.logger()
	remoteAddr := remoteAddress(conn)
	var authConnection *auth.Connection
	if s.AuthLimiter != nil {
		authConnection = s.AuthLimiter.NewConnection(remoteAddr)
	}
	tlsActive := false
	reader := bufio.NewReaderSize(conn, 64*1024)
	writer := bufio.NewWriterSize(conn, 16*1024)
	write := func(format string, args ...any) error {
		if _, err := fmt.Fprintf(writer, format+"\r\n", args...); err != nil {
			return err
		}
		return writer.Flush()
	}
	if err := write("220 %s ESMTP MyMail", s.Hostname); err != nil {
		logger.Debug("SMTP greeting failed", "remote_addr", remoteAddr, "error", err)
		return
	}
	logger.Info("SMTP connection started", "remote_addr", remoteAddr, "hostname", s.Hostname)
	var tx transaction
	authenticated := false
	for {
		_ = conn.SetReadDeadline(time.Now().Add(15 * time.Minute))
		line, err := reader.ReadString('\n')
		if err != nil {
			if !errors.Is(err, io.EOF) {
				logger.Debug("SMTP connection ended", "remote_addr", remoteAddr, "error", err)
			} else {
				logger.Info("SMTP connection ended", "remote_addr", remoteAddr)
			}
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			logger.Warn("SMTP invalid action", "remote_addr", remoteAddr, "reason", "command required")
			_ = write("500 5.5.2 command required")
			continue
		}
		command, argument := line, ""
		if index := strings.IndexByte(line, ' '); index >= 0 {
			command, argument = line[:index], strings.TrimSpace(line[index+1:])
		}
		command = strings.ToUpper(command)
		logger.Info("SMTP action", "remote_addr", remoteAddr, "command", command, "arguments", smtpLogArgument(command, argument), "authenticated", authenticated, "sender", tx.from, "recipients", len(tx.recipients))
		switch command {
		case "EHLO", "HELO":
			if strings.EqualFold(command, "EHLO") {
				startTLS := s.startTLSConfig() != nil && !tlsActive
				if _, err := fmt.Fprintf(writer, "250-%s\r\n250-SIZE %d\r\n250-8BITMIME\r\n", s.Hostname, maxMessageBytes); err != nil {
					return
				}
				if startTLS {
					if _, err := fmt.Fprint(writer, "250-STARTTLS\r\n"); err != nil {
						return
					}
				}
				auth := !s.RequireSTARTTLS || tlsActive
				if auth {
					if _, err := fmt.Fprint(writer, "250-AUTH PLAIN LOGIN\r\n"); err != nil {
						return
					}
				}
				if _, err := fmt.Fprint(writer, "250 PIPELINING\r\n"); err != nil || writer.Flush() != nil {
					return
				}
			} else if write("250 %s", s.Hostname) != nil {
				return
			}
		case "STARTTLS":
			if tlsActive {
				_ = write("503 5.5.1 TLS already active")
				continue
			}
			tlsConfig := s.startTLSConfig()
			if tlsConfig == nil {
				_ = write("454 4.7.0 TLS not available")
				continue
			}
			if err := write("220 2.0.0 ready to start TLS"); err != nil {
				return
			}
			tlsConn := tls.Server(conn, tlsConfig)
			if err := tlsConn.Handshake(); err != nil {
				return
			}
			conn = tlsConn
			reader = bufio.NewReaderSize(conn, 64*1024)
			writer = bufio.NewWriterSize(conn, 16*1024)
			tlsActive = true
			tx = transaction{}
			authenticated = false
		case "AUTH":
			if s.RequireSTARTTLS && !tlsActive {
				_ = write("530 5.7.0 Must issue STARTTLS first")
				continue
			}
			if s.authenticate(argument, reader, write, &authenticated, remoteAddr, authConnection) != nil {
				return
			}
		case "MAIL":
			if s.RequireSTARTTLS && !tlsActive {
				_ = write("530 5.7.0 Must issue STARTTLS first")
				continue
			}
			from, ok := parseSMTPPath(argument, "FROM:")
			if !ok {
				logger.Warn("SMTP MAIL rejected", "remote_addr", remoteAddr, "reason", "invalid sender")
				_ = write("501 5.5.4 invalid sender")
				continue
			}
			tx = transaction{started: true, from: from}
			logger.Info("SMTP sender accepted", "remote_addr", remoteAddr, "sender", from)
			if write("250 2.1.0 sender ok") != nil {
				return
			}
		case "RCPT":
			if !tx.started {
				logger.Warn("SMTP recipient rejected", "remote_addr", remoteAddr, "reason", "MAIL required")
				_ = write("503 5.5.1 send MAIL first")
				continue
			}
			address, ok := parseSMTPPath(argument, "TO:")
			if !ok {
				logger.Warn("SMTP recipient rejected", "remote_addr", remoteAddr, "reason", "invalid recipient")
				_ = write("501 5.5.4 invalid recipient")
				continue
			}
			mailbox, exists := s.Resolve(address)
			if exists {
				tx.recipients = append(tx.recipients, address)
				tx.mailboxes = append(tx.mailboxes, mailbox)
				logger.Info("SMTP recipient accepted", "remote_addr", remoteAddr, "recipient", address, "route", "local", "mailbox", mailbox)
			} else if domain, ok := recipientDomain(address); ok && s.LocalDomain != nil && !s.LocalDomain(domain) {
				if !authenticated {
					logger.Warn("SMTP recipient rejected", "remote_addr", remoteAddr, "recipient", address, "reason", "authentication required for forwarding")
					_ = write("530 5.7.0 authentication required for forwarding")
					continue
				}
				tx.recipients = append(tx.recipients, address)
				tx.forward = append(tx.forward, address)
				logger.Info("SMTP recipient accepted", "remote_addr", remoteAddr, "recipient", address, "route", "forward", "domain", domain)
			} else {
				logger.Warn("SMTP recipient rejected", "remote_addr", remoteAddr, "recipient", address, "reason", "mailbox unavailable")
				_ = write("550 5.1.1 mailbox unavailable")
				continue
			}
			if write("250 2.1.5 recipient ok") != nil {
				return
			}
		case "DATA":
			if len(tx.recipients) == 0 {
				logger.Warn("SMTP DATA rejected", "remote_addr", remoteAddr, "reason", "recipient required")
				_ = write("503 5.5.1 need RCPT TO first")
				continue
			}
			if write("354 End data with <CR><LF>.<CR><LF>") != nil {
				return
			}
			logger.Info("SMTP DATA started", "remote_addr", remoteAddr, "sender", tx.from, "recipients", len(tx.recipients))
			data, readErr := readData(reader)
			if readErr != nil {
				logger.Warn("SMTP DATA rejected", "remote_addr", remoteAddr, "error", readErr)
				_ = write("552 5.3.4 message too large or malformed")
				tx = transaction{}
				continue
			}
			logger.Info("SMTP message received", "remote_addr", remoteAddr, "from", tx.from, "to", tx.recipients, "subject", messageSubject(data), "sender", tx.from, "recipients", len(tx.recipients), "bytes", len(data))
			message := &plugins.Message{Data: data, From: tx.from, Recipients: append([]string(nil), tx.recipients...), Metadata: map[string]string{"peer": remoteAddr}}
			result := plugins.Result{Decision: plugins.Accept}
			if s.Processors != nil {
				result = s.Processors.Process(ctx, message)
			}
			logger.Info("SMTP message processed", "remote_addr", remoteAddr, "decision", decisionName(result.Decision), "reason", cleanReason(result.Reason, ""))
			switch result.Decision {
			case plugins.Reject:
				logger.Warn("SMTP message rejected", "remote_addr", remoteAddr, "reason", cleanReason(result.Reason, "message rejected"))
				_ = write("550 5.7.1 %s", cleanReason(result.Reason, "message rejected"))
			case plugins.TemporaryFailure:
				logger.Warn("SMTP message processing failed", "remote_addr", remoteAddr, "reason", cleanReason(result.Reason, "message processing temporarily unavailable"))
				_ = write("451 4.7.0 %s", cleanReason(result.Reason, "message processing temporarily unavailable"))
			case plugins.Discard:
				logger.Info("SMTP message discarded", "remote_addr", remoteAddr)
				_ = write("250 2.0.0 message accepted")
			default:
				if err := s.deliver(ctx, tx, data); err != nil {
					logger.Warn("SMTP delivery failed", "remote_addr", remoteAddr, "error", err)
					_ = write("451 4.3.0 delivery temporarily unavailable")
				} else {
					logger.Info("SMTP delivery completed", "remote_addr", remoteAddr, "local_recipients", len(tx.mailboxes), "forwarded_recipients", len(tx.forward), "bytes", len(data))
					_ = write("250 2.0.0 message accepted for delivery")
				}
			}
			tx = transaction{}
		case "RSET":
			tx = transaction{}
			logger.Info("SMTP transaction reset", "remote_addr", remoteAddr)
			if write("250 2.0.0 reset") != nil {
				return
			}
		case "NOOP":
			if write("250 2.0.0 ok") != nil {
				return
			}
		case "QUIT":
			logger.Info("SMTP connection closing", "remote_addr", remoteAddr)
			_ = write("221 2.0.0 closing connection")
			return
		default:
			logger.Warn("SMTP invalid action", "remote_addr", remoteAddr, "command", command, "reason", "command not implemented")
			_ = write("502 5.5.1 command not implemented")
		}
	}
}

func (s *Server) deliver(ctx context.Context, tx transaction, data []byte) error {
	for _, mailbox := range tx.mailboxes {
		message, err := s.Store.Deliver(mailbox, data)
		if err != nil {
			return err
		}
		s.logger().Info("SMTP local delivery completed", "mailbox", mailbox, "filename", message.Filename, "bytes", len(data))
	}
	for _, recipient := range tx.forward {
		if err := s.forward(ctx, tx.from, recipient, data); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) forward(ctx context.Context, from, recipient string, data []byte) error {
	domain, ok := recipientDomain(recipient)
	if !ok {
		return errors.New("invalid forwarding recipient")
	}
	lookup := s.LookupMX
	if lookup == nil {
		lookup = net.DefaultResolver.LookupMX
	}
	records, err := lookup(ctx, domain)
	if err != nil {
		s.logger().Warn("SMTP MX lookup failed", "domain", domain, "recipient", recipient, "error", err)
		return fmt.Errorf("lookup MX for %s: %w", domain, err)
	}
	if len(records) == 0 {
		s.logger().Warn("SMTP forwarding unavailable", "domain", domain, "recipient", recipient, "reason", "no MX record")
		return fmt.Errorf("domain %s has no MX record", domain)
	}
	records = append([]*net.MX(nil), records...)
	sort.SliceStable(records, func(i, j int) bool { return records[i].Pref < records[j].Pref })
	var lastErr error
	for _, record := range records {
		host := strings.TrimSuffix(strings.TrimSpace(record.Host), ".")
		if host == "" {
			continue
		}
		s.logger().Info("SMTP forwarding attempt", "domain", domain, "recipient", recipient, "mx_host", host, "sender", from)
		connection, dialErr := s.dialSMTP(ctx, net.JoinHostPort(host, "25"))
		if dialErr != nil {
			s.logger().Warn("SMTP forwarding connection failed", "domain", domain, "recipient", recipient, "mx_host", host, "error", dialErr)
			lastErr = dialErr
			continue
		}
		err = relaySMTP(connection, s.Hostname, from, recipient, data)
		_ = connection.Close()
		if err == nil {
			s.logger().Info("SMTP forwarding completed", "domain", domain, "recipient", recipient, "mx_host", host, "bytes", len(data))
			return nil
		}
		s.logger().Warn("SMTP forwarding attempt failed", "domain", domain, "recipient", recipient, "mx_host", host, "error", err)
		lastErr = err
		if response, ok := err.(smtpResponseError); ok && response.Code >= 500 && response.Code < 600 {
			break
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no usable MX record")
	}
	return fmt.Errorf("forward message to %s: %w", recipient, lastErr)
}

func (s *Server) dialSMTP(ctx context.Context, address string) (net.Conn, error) {
	if s.DialSMTP != nil {
		return s.DialSMTP(ctx, address)
	}
	return (&net.Dialer{Timeout: 30 * time.Second}).DialContext(ctx, "tcp", address)
}

type smtpResponseError struct {
	Code int
	Text string
}

func (e smtpResponseError) Error() string { return fmt.Sprintf("SMTP %d %s", e.Code, e.Text) }

func relaySMTP(connection net.Conn, hostname, from, recipient string, data []byte) error {
	reader := bufio.NewReaderSize(connection, 16*1024)
	writer := bufio.NewWriterSize(connection, 16*1024)
	if _, err := readSMTPResponse(reader, 220); err != nil {
		return err
	}
	if err := sendSMTPCommand(reader, writer, 250, "EHLO %s", hostname); err != nil {
		if response, ok := err.(smtpResponseError); !ok || response.Code < 500 || response.Code >= 600 {
			return err
		}
		if err := sendSMTPCommand(reader, writer, 250, "HELO %s", hostname); err != nil {
			return err
		}
	}
	if err := sendSMTPCommand(reader, writer, 250, "MAIL FROM:<%s>", from); err != nil {
		return err
	}
	if err := sendSMTPCommand(reader, writer, 250, "RCPT TO:<%s>", recipient); err != nil {
		return err
	}
	if err := sendSMTPCommand(reader, writer, 354, "DATA"); err != nil {
		return err
	}
	if err := writeSMTPData(writer, data); err != nil {
		return err
	}
	if err := writer.Flush(); err != nil {
		return err
	}
	if _, err := readSMTPResponse(reader, 250); err != nil {
		return err
	}
	_, _ = fmt.Fprint(writer, "QUIT\r\n")
	_ = writer.Flush()
	return nil
}

func sendSMTPCommand(reader *bufio.Reader, writer *bufio.Writer, expected int, format string, args ...any) error {
	if _, err := fmt.Fprintf(writer, format+"\r\n", args...); err != nil {
		return err
	}
	if err := writer.Flush(); err != nil {
		return err
	}
	_, err := readSMTPResponse(reader, expected)
	return err
}

func readSMTPResponse(reader *bufio.Reader, expected int) (string, error) {
	var text strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		line = strings.TrimRight(line, "\r\n")
		if len(line) < 3 {
			return "", errors.New("malformed SMTP response")
		}
		code, parseErr := strconv.Atoi(line[:3])
		if parseErr != nil {
			return "", errors.New("malformed SMTP response code")
		}
		if text.Len() > 0 {
			text.WriteByte(' ')
		}
		if len(line) > 4 {
			text.WriteString(line[4:])
		}
		if len(line) < 4 || line[3] != '-' {
			if code != expected {
				return "", smtpResponseError{Code: code, Text: text.String()}
			}
			return text.String(), nil
		}
	}
}

func writeSMTPData(writer *bufio.Writer, data []byte) error {
	normalized := bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	normalized = bytes.ReplaceAll(normalized, []byte("\r"), []byte("\n"))
	if len(normalized) == 0 || normalized[len(normalized)-1] != '\n' {
		normalized = append(normalized, '\n')
	}
	lines := bytes.Split(normalized, []byte{'\n'})
	for index, line := range lines {
		if index == len(lines)-1 && len(line) == 0 {
			break
		}
		if len(line) > 0 && line[0] == '.' {
			if err := writer.WriteByte('.'); err != nil {
				return err
			}
		}
		if _, err := writer.Write(line); err != nil {
			return err
		}
		if _, err := writer.WriteString("\r\n"); err != nil {
			return err
		}
	}
	_, err := writer.WriteString(".\r\n")
	return err
}

func recipientDomain(address string) (string, bool) {
	address = strings.TrimSpace(address)
	separator := strings.LastIndexByte(address, '@')
	if separator <= 0 || separator == len(address)-1 || strings.ContainsAny(address, " \t\r\n") {
		return "", false
	}
	domain := strings.TrimSuffix(strings.ToLower(address[separator+1:]), ".")
	if domain == "" || strings.Contains(domain, "@") {
		return "", false
	}
	return domain, true
}

func (s *Server) authenticate(argument string, reader *bufio.Reader, write func(string, ...any) error, authenticated *bool, remoteAddr string, authConnection *auth.Connection) error {
	mechanism, initial, _ := strings.Cut(argument, " ")
	mechanism = strings.ToUpper(mechanism)
	username := ""
	logResult := func(success bool, reason string) {
		s.logger().Info("SMTP authentication", "remote_addr", remoteAddr, "mechanism", mechanism, "username", username, "success", success, "reason", reason)
	}
	throttleResponse := func(err error) error {
		if errors.Is(err, auth.ErrConnectionLimit) {
			logResult(false, "connection authentication limit exceeded")
			_ = write("421 4.7.0 too many authentication attempts")
			return err
		}
		logResult(false, "authentication backoff")
		return write("454 4.7.0 authentication temporarily unavailable")
	}
	checkThrottle := func() error {
		if authConnection == nil {
			return nil
		}
		return authConnection.Allow(username)
	}
	failAuthentication := func(response, reason string) error {
		if err := checkThrottle(); err != nil {
			return throttleResponse(err)
		}
		if authConnection != nil {
			time.Sleep(authConnection.Failure(username))
		}
		logResult(false, reason)
		return write(response)
	}
	if s.Authenticate == nil {
		logResult(false, "authentication unavailable")
		return write("502 5.5.1 authentication unavailable")
	}
	var password string
	if mechanism == "PLAIN" {
		if initial == "" {
			if err := write("334 "); err != nil {
				return err
			}
			line, err := reader.ReadString('\n')
			if err != nil {
				return err
			}
			initial = strings.TrimSpace(line)
		}
		decoded, err := base64.StdEncoding.DecodeString(initial)
		parts := strings.Split(string(decoded), "\x00")
		if err != nil || len(parts) != 3 {
			return failAuthentication("535 5.7.8 invalid credentials", "invalid credentials")
		}
		username, password = parts[1], parts[2]
	} else if mechanism == "LOGIN" {
		if err := write("334 VXNlcm5hbWU6"); err != nil {
			return err
		}
		line, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		usernameBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(line))
		if err != nil {
			return failAuthentication("535 5.7.8 invalid credentials", "invalid credentials")
		}
		username = string(usernameBytes)
		if err := write("334 UGFzc3dvcmQ6"); err != nil {
			return err
		}
		line, err = reader.ReadString('\n')
		if err != nil {
			return err
		}
		passwordBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(line))
		if err != nil {
			return failAuthentication("535 5.7.8 invalid credentials", "invalid credentials")
		}
		password = string(passwordBytes)
	} else {
		return failAuthentication("504 5.5.4 unsupported authentication mechanism", "unsupported authentication mechanism")
	}
	if err := checkThrottle(); err != nil {
		return throttleResponse(err)
	}
	if !s.Authenticate(username, password) {
		if authConnection != nil {
			time.Sleep(authConnection.Failure(username))
		}
		logResult(false, "invalid credentials")
		return write("535 5.7.8 authentication credentials invalid")
	}
	if authConnection != nil {
		authConnection.Success(username)
	}
	*authenticated = true
	logResult(true, "authentication successful")
	return write("235 2.7.0 authentication successful")
}

func remoteAddress(conn net.Conn) string {
	if conn == nil || conn.RemoteAddr() == nil {
		return "unknown"
	}
	return conn.RemoteAddr().String()
}

func smtpLogArgument(command, argument string) string {
	if command == "AUTH" {
		mechanism, _, _ := strings.Cut(argument, " ")
		if mechanism == "" {
			return "[REDACTED]"
		}
		return mechanism + " [REDACTED]"
	}
	return argument
}

func decisionName(decision plugins.Decision) string {
	switch decision {
	case plugins.Accept:
		return "accept"
	case plugins.Reject:
		return "reject"
	case plugins.TemporaryFailure:
		return "temporary_failure"
	case plugins.Discard:
		return "discard"
	default:
		return "unknown"
	}
}

func parseSMTPPath(argument, prefix string) (string, bool) {
	if len(argument) < len(prefix) || !strings.EqualFold(argument[:len(prefix)], prefix) {
		return "", false
	}
	path := strings.TrimSpace(argument[len(prefix):])
	if len(path) < 2 || path[0] != '<' {
		return "", false
	}
	closing := strings.IndexByte(path, '>')
	if closing < 1 || (closing+1 < len(path) && path[closing+1] != ' ' && path[closing+1] != '\t') {
		return "", false
	}
	return strings.TrimSpace(path[1:closing]), true
}

func readData(reader *bufio.Reader) ([]byte, error) {
	data := make([]byte, 0, 4096)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		trimmed := strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
		if trimmed == "." {
			return data, nil
		}
		if strings.HasPrefix(trimmed, "..") {
			line = line[1:]
		}
		data = append(data, line...)
		if len(data) > maxMessageBytes {
			return nil, errors.New("message too large")
		}
	}
}

func cleanReason(reason, fallback string) string {
	reason = strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(reason, "\r", " "), "\n", " "))
	if reason == "" {
		return fallback
	}
	return reason
}
