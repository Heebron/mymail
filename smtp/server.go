// Package smtp implements the receiving SMTP service.
package smtp

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"time"

	"mymail/maildir"
	"mymail/plugins"
)

const maxMessageBytes = 50 << 20

type Resolver func(address string) (mailbox string, ok bool)
type Authenticator func(username, password string) bool

type Server struct {
	Addr         string
	TLSConfig    *tls.Config
	Hostname     string
	Store        *maildir.Store
	Processors   *plugins.Chain
	Resolve      Resolver
	Authenticate Authenticator
	Logger       *slog.Logger
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
	listener, err := listen(s.Addr, s.TLSConfig)
	if err != nil {
		return fmt.Errorf("listen %s smtp on %s: %w", tlsLabel(s.TLSConfig), s.Addr, err)
	}
	s.Logger.Info("SMTP server listening", "address", listener.Addr().String(), "tls", s.TLSConfig != nil)
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

func listen(address string, config *tls.Config) (net.Listener, error) {
	if config != nil {
		return tls.Listen("tcp", address, config)
	}
	return net.Listen("tcp", address)
}

func tlsLabel(config *tls.Config) string {
	if config != nil {
		return "TLS"
	}
	return "plain"
}

type transaction struct {
	started    bool
	from       string
	recipients []string
	mailboxes  []string
}

func (s *Server) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReaderSize(conn, 64*1024)
	writer := bufio.NewWriterSize(conn, 16*1024)
	write := func(format string, args ...any) error {
		if _, err := fmt.Fprintf(writer, format+"\r\n", args...); err != nil {
			return err
		}
		return writer.Flush()
	}
	if err := write("220 %s ESMTP MyMail", s.Hostname); err != nil {
		return
	}
	var tx transaction
	authenticated := false
	for {
		_ = conn.SetReadDeadline(time.Now().Add(15 * time.Minute))
		line, err := reader.ReadString('\n')
		if err != nil {
			if !errors.Is(err, io.EOF) {
				s.Logger.Debug("SMTP connection ended", "error", err)
			}
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			_ = write("500 5.5.2 command required")
			continue
		}
		command, argument := line, ""
		if index := strings.IndexByte(line, ' '); index >= 0 {
			command, argument = line[:index], strings.TrimSpace(line[index+1:])
		}
		switch strings.ToUpper(command) {
		case "EHLO", "HELO":
			if strings.EqualFold(command, "EHLO") {
				if _, err := fmt.Fprintf(writer, "250-%s\r\n250-SIZE %d\r\n250-8BITMIME\r\n250-AUTH PLAIN LOGIN\r\n250 PIPELINING\r\n", s.Hostname, maxMessageBytes); err != nil || writer.Flush() != nil {
					return
				}
			} else if write("250 %s", s.Hostname) != nil {
				return
			}
		case "AUTH":
			if s.authenticate(argument, reader, write, &authenticated) != nil {
				return
			}
		case "MAIL":
			from, ok := parseSMTPPath(argument, "FROM:")
			if !ok {
				_ = write("501 5.5.4 invalid sender")
				continue
			}
			tx = transaction{started: true, from: from}
			if write("250 2.1.0 sender ok") != nil {
				return
			}
		case "RCPT":
			if !tx.started {
				_ = write("503 5.5.1 send MAIL first")
				continue
			}
			address, ok := parseSMTPPath(argument, "TO:")
			if !ok {
				_ = write("501 5.5.4 invalid recipient")
				continue
			}
			mailbox, exists := s.Resolve(address)
			if !exists {
				_ = write("550 5.1.1 mailbox unavailable")
				continue
			}
			tx.recipients = append(tx.recipients, address)
			tx.mailboxes = append(tx.mailboxes, mailbox)
			if write("250 2.1.5 recipient ok") != nil {
				return
			}
		case "DATA":
			if len(tx.recipients) == 0 {
				_ = write("503 5.5.1 need RCPT TO first")
				continue
			}
			if write("354 End data with <CR><LF>.<CR><LF>") != nil {
				return
			}
			data, readErr := readData(reader)
			if readErr != nil {
				_ = write("552 5.3.4 message too large or malformed")
				tx = transaction{}
				continue
			}
			message := &plugins.Message{Data: data, From: tx.from, Recipients: append([]string(nil), tx.recipients...), Metadata: map[string]string{"peer": conn.RemoteAddr().String()}}
			result := plugins.Result{Decision: plugins.Accept}
			if s.Processors != nil {
				result = s.Processors.Process(ctx, message)
			}
			switch result.Decision {
			case plugins.Reject:
				_ = write("550 5.7.1 %s", cleanReason(result.Reason, "message rejected"))
			case plugins.TemporaryFailure:
				_ = write("451 4.7.0 %s", cleanReason(result.Reason, "message processing temporarily unavailable"))
			case plugins.Discard:
				_ = write("250 2.0.0 message accepted")
			default:
				if err := s.deliver(tx.mailboxes, data); err != nil {
					_ = write("451 4.3.0 delivery temporarily unavailable")
				} else {
					_ = write("250 2.0.0 message accepted for delivery")
				}
			}
			tx = transaction{}
		case "RSET":
			tx = transaction{}
			if write("250 2.0.0 reset") != nil {
				return
			}
		case "NOOP":
			if write("250 2.0.0 ok") != nil {
				return
			}
		case "QUIT":
			_ = write("221 2.0.0 closing connection")
			return
		default:
			_ = write("502 5.5.1 command not implemented")
		}
		_ = authenticated // reserved for submission policy and future AUTH-required rules
	}
}

func (s *Server) deliver(mailboxes []string, data []byte) error {
	for _, mailbox := range mailboxes {
		if _, err := s.Store.Deliver(mailbox, data); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) authenticate(argument string, reader *bufio.Reader, write func(string, ...any) error, authenticated *bool) error {
	if s.Authenticate == nil {
		return write("502 5.5.1 authentication unavailable")
	}
	mechanism, initial, _ := strings.Cut(argument, " ")
	mechanism = strings.ToUpper(mechanism)
	var username, password string
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
			return write("535 5.7.8 invalid credentials")
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
			return write("535 5.7.8 invalid credentials")
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
			return write("535 5.7.8 invalid credentials")
		}
		password = string(passwordBytes)
	} else {
		return write("504 5.5.4 unsupported authentication mechanism")
	}
	if !s.Authenticate(username, password) {
		return write("535 5.7.8 authentication credentials invalid")
	}
	*authenticated = true
	return write("235 2.7.0 authentication successful")
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
