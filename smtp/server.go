// Package smtp implements the receiving SMTP service.
package smtp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
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
	"sync"
	"time"

	"mymail/auth"
	"mymail/maildir"
	"mymail/plugins"
)

const maxMessageBytes = 50 << 20

// Resolver maps a local recipient address to a mailbox name.
type Resolver func(address string) (mailbox string, ok bool)

// DomainResolver reports whether a domain is configured for local delivery.
type DomainResolver func(domain string) bool

// MXLookup resolves the MX records used for forwarding external recipients.
type MXLookup func(context.Context, string) ([]*net.MX, error)

// SMTPDialer opens a connection to an external SMTP server.
type SMTPDialer func(context.Context, string) (net.Conn, error)

// Authenticator verifies SMTP credentials.
type Authenticator func(username, password string) bool

// SplitForwarder sends a message to a peer split server. When non-nil, the
// SMTP server uses this instead of direct MX relay for non-local recipients
// (local role) or for local-mailbox recipients (remote role).
// The fallback argument is a function that performs the default MX-based
// relay; the SplitForwarder may call it when the split link is unavailable.
type SplitForwarder func(ctx context.Context, from, recipient string, data []byte, fallback func(ctx context.Context, from, recipient string, data []byte) error) error

// Server receives SMTP messages, delivers local mail, and forwards external
// recipients after authentication.
type Server struct {
	// Addr is the TCP address to listen on.
	Addr string
	// TLSConfig enables implicit TLS when non-nil.
	TLSConfig *tls.Config
	// StartTLSConfig enables STARTTLS when non-nil.
	StartTLSConfig *tls.Config
	// TLSAvailable, when non-nil, reports whether a certificate is currently
	// loaded. STARTTLS is neither advertised nor accepted while it returns false.
	TLSAvailable func() bool
	// RequireSTARTTLS blocks authentication and MAIL until TLS is active.
	RequireSTARTTLS bool
	// RequireTLSForAuth blocks authentication until TLS is active, while still
	// allowing unauthenticated inbound SMTP delivery.
	RequireTLSForAuth bool
	// Hostname is the name used in SMTP greetings and EHLO responses.
	Hostname string
	// Store receives locally delivered messages.
	Store *maildir.Store
	// Processors handles locally delivered messages before storage.
	Processors *plugins.Chain
	// Resolve maps local recipients to mailbox names.
	Resolve Resolver
	// LocalDomain identifies domains that must not be forwarded.
	LocalDomain DomainResolver
	// LookupMX resolves external recipient domains. The system resolver is used
	// when it is nil.
	LookupMX MXLookup
	// DialSMTP connects to an external MX host. A 30-second dialer is used when
	// it is nil.
	DialSMTP SMTPDialer
	// RelayNetwork selects the address family for outbound MX connections.
	// It defaults to "tcp" when empty.
	RelayNetwork string
	// DKIMSigner signs outgoing email messages before forwarding when non-nil.
	DKIMSigner func(msg []byte) ([]byte, error)
	// Authenticate verifies SMTP login credentials.
	Authenticate Authenticator
	// AuthenticateContext verifies SMTP credentials with the active server context.
	// When set, it takes precedence over Authenticate.
	AuthenticateContext func(ctx context.Context, username, password string) (bool, error)
	// AuthLimiter applies shared authentication throttling when non-nil.
	AuthLimiter *auth.Limiter
	// Logger receives structured service logs. The default logger is used when
	// it is nil.
	Logger *slog.Logger
	// OnReady is called after the listener starts accepting connections.
	OnReady func()
	// SplitForward, when non-nil, replaces the default MX-based forwarding.
	// It is used in split mode to send mail over the TLS link to the peer.
	SplitForward SplitForwarder
	activeMu     sync.Mutex
	active       map[net.Conn]struct{}
	activeWG     sync.WaitGroup
}

// ListenAndServe listens until ctx is canceled or the listener fails. Active
// connections are closed during shutdown before the method returns.
func (s *Server) ListenAndServe(ctx context.Context) error {
	if s.Resolve == nil {
		return errors.New("smtp server requires a recipient resolver")
	}
	if s.Store == nil && s.SplitForward == nil {
		return errors.New("smtp server requires a store or SplitForward")
	}
	if s.Hostname == "" {
		s.Hostname = "localhost"
	}
	if s.Logger == nil {
		s.Logger = slog.Default()
	}
	var listener net.Listener
	var err error
	if s.TLSConfig != nil {
		listener, err = tls.Listen("tcp", s.Addr, s.TLSConfig)
	} else {
		listener, err = net.Listen("tcp", s.Addr)
	}
	if err != nil {
		return fmt.Errorf("listen SMTP on %s: %w", s.Addr, err)
	}
	s.Logger.Info("SMTP server listening", "address", listener.Addr().String(), "tls", s.TLSConfig != nil)
	if s.OnReady != nil {
		s.OnReady()
	}
	defer func() {
		_ = listener.Close()
		s.Logger.Info("SMTP listener stopped", "address", listener.Addr().String())
		closed := s.closeActiveConnections()
		s.Logger.Info("SMTP active connections closed", "address", listener.Addr().String(), "count", closed)
		s.activeWG.Wait()
		s.Logger.Info("SMTP server stopped", "address", listener.Addr().String())
	}()
	go func() {
		<-ctx.Done()
		s.Logger.Info("SMTP shutdown requested", "address", listener.Addr().String())
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
		s.trackConnection(conn)
		go func() {
			defer s.untrackConnection(conn)
			s.handle(ctx, conn)
		}()
	}
}

func (s *Server) trackConnection(conn net.Conn) {
	s.activeMu.Lock()
	defer s.activeMu.Unlock()
	if s.active == nil {
		s.active = make(map[net.Conn]struct{})
	}
	s.active[conn] = struct{}{}
	s.activeWG.Add(1)
}

func (s *Server) untrackConnection(conn net.Conn) {
	s.activeMu.Lock()
	delete(s.active, conn)
	s.activeMu.Unlock()
	s.activeWG.Done()
}

func (s *Server) closeActiveConnections() int {
	s.activeMu.Lock()
	connections := make([]net.Conn, 0, len(s.active))
	for conn := range s.active {
		connections = append(connections, conn)
	}
	s.activeMu.Unlock()
	for _, conn := range connections {
		_ = conn.Close()
	}
	return len(connections)
}

func (s *Server) logger() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}

func (s *Server) startTLSConfig() *tls.Config {
	if s.TLSAvailable != nil && !s.TLSAvailable() {
		return nil
	}
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

// MessageID returns the message's Message-ID header, or an empty string when
// the message has no parseable headers or Message-ID.
func MessageID(data []byte) string {
	message, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(message.Header.Get("Message-ID"))
}

type transaction struct {
	started    bool
	from       string
	recipients []string
	mailboxes  []string
	forward    []string
}

func (s *Server) pluginMessage(tx transaction, data []byte, remoteAddr string) *plugins.Message {
	mailbox := ""
	if len(tx.mailboxes) > 0 {
		mailbox = tx.mailboxes[0]
	}
	return s.pluginMessageForMailbox(tx, data, remoteAddr, mailbox)
}

func (s *Server) pluginMessageForMailbox(tx transaction, data []byte, remoteAddr, mailbox string) *plugins.Message {
	message := &plugins.Message{
		Data:       append([]byte(nil), data...),
		From:       tx.from,
		Recipients: append([]string(nil), tx.recipients...),
		Metadata:   map[string]string{"peer": remoteAddr},
		Mailbox:    mailbox,
	}
	if mailbox != "" && s.Store != nil {
		if path, err := s.Store.MailboxPath(mailbox); err == nil {
			message.Maildir = path
		}
	}
	return message
}

type localDelivery struct {
	mailbox string
	message *plugins.Message
}

func (s *Server) processLocalRecipients(ctx context.Context, tx transaction, data []byte, remoteAddr string) ([]localDelivery, plugins.Result) {
	deliveries := make([]localDelivery, 0, len(tx.mailboxes))
	for _, mailbox := range tx.mailboxes {
		message := s.pluginMessageForMailbox(tx, data, remoteAddr, mailbox)
		result := plugins.Result{Decision: plugins.Accept}
		if s.Processors != nil {
			result = s.Processors.Process(ctx, message)
		}
		if result.Err != nil {
			s.logger().Warn("SMTP plugin failed", "mailbox", mailbox, "error", result.Err)
		}
		s.logger().Info("SMTP message processed", "mailbox", mailbox, "decision", decisionName(result.Decision), "reason", cleanReason(result.Reason, ""))
		switch result.Decision {
		case plugins.Accept:
			deliveries = append(deliveries, localDelivery{mailbox: mailbox, message: message})
		case plugins.Discard:
			continue
		case plugins.Reject, plugins.TemporaryFailure:
			return nil, result
		default:
			return nil, plugins.Result{Decision: plugins.TemporaryFailure, Reason: "processor returned invalid decision"}
		}
	}
	return deliveries, plugins.Result{Decision: plugins.Accept}
}

func (s *Server) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	logger := s.logger()
	remoteAddr := remoteAddress(conn)
	var authConnection *auth.Connection
	if s.AuthLimiter != nil {
		authConnection = s.AuthLimiter.NewConnection(remoteAddr)
	}
	_, tlsActive := conn.(*tls.Conn)
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
				authReq := !(s.RequireSTARTTLS || s.RequireTLSForAuth) || tlsActive
				if authReq {
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
			if (s.RequireSTARTTLS || s.RequireTLSForAuth) && !tlsActive {
				_ = write("530 5.7.0 Must issue STARTTLS first")
				continue
			}
			if s.authenticate(ctx, argument, reader, write, &authenticated, remoteAddr, authConnection) != nil {
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
				// A remote split instance has no local store, so local mailbox
				// recipients are returned to the local side over the split link.
				if s.Store == nil && s.SplitForward != nil {
					tx.forward = append(tx.forward, address)
					logger.Info("SMTP recipient accepted", "remote_addr", remoteAddr, "recipient", address, "route", "split-forward", "mailbox", mailbox)
				} else {
					tx.mailboxes = append(tx.mailboxes, mailbox)
					logger.Info("SMTP recipient accepted", "remote_addr", remoteAddr, "recipient", address, "route", "local", "mailbox", mailbox)
				}
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
			logger.Info("SMTP message received", "remote_addr", remoteAddr, "from", tx.from, "to", tx.recipients, "subject", messageSubject(data), "message_id", MessageID(data), "sender", tx.from, "recipients", len(tx.recipients), "bytes", len(data))
			result := plugins.Result{Decision: plugins.Accept}
			var deliveries []localDelivery
			if len(tx.mailboxes) > 0 && s.Store != nil {
				deliveries, result = s.processLocalRecipients(ctx, tx, data, remoteAddr)
			}
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
				if err := s.deliverProcessed(ctx, tx, deliveries, data); err != nil {
					logger.Warn("SMTP delivery failed", "remote_addr", remoteAddr, "error", err)
					_ = write("451 4.3.0 delivery temporarily unavailable")
				} else {
					logger.Info("SMTP delivery completed", "remote_addr", remoteAddr, "local_recipients", len(deliveries), "forwarded_recipients", len(tx.forward), "bytes", len(data))
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

func (s *Server) deliver(ctx context.Context, tx transaction, message *plugins.Message) error {
	deliveries := make([]localDelivery, 0, len(tx.mailboxes))
	for _, mailbox := range tx.mailboxes {
		deliveries = append(deliveries, localDelivery{mailbox: mailbox, message: message})
	}
	return s.deliverProcessed(ctx, tx, deliveries, message.Data)
}

func (s *Server) deliverProcessed(ctx context.Context, tx transaction, deliveries []localDelivery, forwardData []byte) error {
	s.warnIfForwardingSenderIsExternal(tx, forwardData)
	for _, delivery := range deliveries {
		delivered, err := s.Store.DeliverToFolder(delivery.mailbox, delivery.message.Folder, delivery.message.Data)
		if err != nil {
			return err
		}
		s.logger().Info("SMTP local delivery completed", "mailbox", delivery.mailbox, "folder", delivery.message.Folder, "filename", delivered.Filename, "bytes", len(delivery.message.Data))
	}
	for _, recipient := range tx.forward {
		if s.SplitForward != nil {
			fallback := func(ctx context.Context, from, recipient string, data []byte) error {
				return s.forward(ctx, from, recipient, data)
			}
			if err := s.SplitForward(ctx, tx.from, recipient, forwardData, fallback); err != nil {
				return err
			}
		} else {
			if err := s.forward(ctx, tx.from, recipient, forwardData); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Server) warnIfForwardingSenderIsExternal(tx transaction, data []byte) {
	if len(tx.forward) == 0 || s.LocalDomain == nil || tx.from == "" {
		return
	}
	envelopeDomain, ok := recipientDomain(tx.from)
	if !ok {
		return
	}
	envelopeIsLocal := s.LocalDomain(envelopeDomain)
	headerFrom := ""
	headerIsLocal := true
	if message, err := mail.ReadMessage(bytes.NewReader(data)); err == nil {
		if address, err := mail.ParseAddress(message.Header.Get("From")); err == nil {
			if domain, ok := recipientDomain(address.Address); ok {
				headerFrom = address.Address
				headerIsLocal = s.LocalDomain(domain)
				if envelopeIsLocal && !headerIsLocal {
					envelopeDomain = domain
				}
			}
		}
	}
	if envelopeIsLocal && headerIsLocal {
		return
	}
	s.logger().Warn("SMTP forwarding sender domain is not local", "sender", tx.from, "header_from", headerFrom, "domain", envelopeDomain, "reason", "recipient SPF/DMARC checks will likely fail")
}

// Relay forwards a message to an external recipient using the configured MX
// lookup and SMTP relay path.
func (s *Server) Relay(ctx context.Context, from, recipient string, data []byte) error {
	return s.relayMX(ctx, from, recipient, data)
}

// DeliverLocal processes and stores a message for a local mailbox. It is used
// by the local side when receiving mail over the split link.
func (s *Server) DeliverLocal(ctx context.Context, from, recipient string, data []byte) error {
	if s.Store == nil {
		return errors.New("local delivery store is not configured")
	}
	if s.Resolve == nil {
		return errors.New("local recipient resolver is not configured")
	}
	mailbox, ok := s.Resolve(recipient)
	if !ok {
		return fmt.Errorf("unknown local mailbox %s", recipient)
	}
	tx := transaction{
		started:    true,
		from:       from,
		recipients: []string{recipient},
		mailboxes:  []string{mailbox},
	}
	deliveries, result := s.processLocalRecipients(ctx, tx, data, "split")
	switch result.Decision {
	case plugins.Accept:
		return s.deliverProcessed(ctx, transaction{from: from}, deliveries, data)
	case plugins.Discard:
		return nil
	case plugins.Reject:
		return fmt.Errorf("local delivery rejected: %s", cleanReason(result.Reason, "message rejected"))
	case plugins.TemporaryFailure:
		return fmt.Errorf("local delivery temporarily failed: %s", cleanReason(result.Reason, "message processing temporarily unavailable"))
	default:
		return errors.New("local delivery processor returned invalid decision")
	}
}

// Submit processes a message received by the remote SMTP server through the
// local server's normal delivery and forwarding paths.
func (s *Server) Submit(ctx context.Context, from, recipient string, data []byte) error {
	if s.Resolve == nil {
		return errors.New("local recipient resolver is not configured")
	}
	if _, ok := s.Resolve(recipient); ok {
		return s.DeliverLocal(ctx, from, recipient, data)
	}
	tx := transaction{started: true, from: from, forward: []string{recipient}}
	return s.deliverProcessed(ctx, tx, nil, data)
}

func (s *Server) forward(ctx context.Context, from, recipient string, data []byte) error {
	return s.relayMX(ctx, from, recipient, s.SignDKIM(from, recipient, data))
}

// SignDKIM adds a DKIM signature when configured. If signing fails, it logs
// the failure and returns the original message.
func (s *Server) SignDKIM(from, recipient string, data []byte) []byte {
	if s.DKIMSigner == nil {
		return data
	}
	domain, _ := recipientDomain(recipient)
	signed, err := s.DKIMSigner(data)
	if err != nil {
		s.logger().Warn("SMTP DKIM signing failed", "domain", domain, "recipient", recipient, "sender", from, "error", err)
		return data
	}
	s.logger().Info("SMTP DKIM signature added", "domain", domain, "recipient", recipient, "sender", from)
	return signed
}

func (s *Server) relayMX(ctx context.Context, from, recipient string, data []byte) error {
	domain, ok := recipientDomain(recipient)
	if !ok {
		return errors.New("invalid forwarding recipient")
	}
	messageID := MessageID(data)
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
		s.logger().Info("SMTP forwarding attempt", "domain", domain, "recipient", recipient, "mx_host", host, "sender", from, "message_id", messageID)
		connection, dialErr := s.dialSMTP(ctx, net.JoinHostPort(host, "25"))
		if dialErr != nil {
			s.logger().Warn("SMTP forwarding connection failed", "domain", domain, "recipient", recipient, "mx_host", host, "message_id", messageID, "error", dialErr)
			lastErr = dialErr
			continue
		}
		response, tlsUsed, tlsVerified, relayErr := relaySMTP(connection, s.Hostname, host, from, recipient, data, true, s.logger())
		_ = connection.Close()
		if errors.Is(relayErr, errSMTPStartTLSHandshake) {
			s.logger().Warn("SMTP relay STARTTLS handshake failed; retrying MX in plaintext", "domain", domain, "recipient", recipient, "mx_host", host, "message_id", messageID, "error", relayErr)
			connection, dialErr = s.dialSMTP(ctx, net.JoinHostPort(host, "25"))
			if dialErr != nil {
				s.logger().Warn("SMTP forwarding plaintext retry connection failed", "domain", domain, "recipient", recipient, "mx_host", host, "message_id", messageID, "error", dialErr)
				lastErr = dialErr
				continue
			}
			response, tlsUsed, tlsVerified, relayErr = relaySMTP(connection, s.Hostname, host, from, recipient, data, false, s.logger())
			_ = connection.Close()
		}
		if relayErr == nil {
			s.logger().Info("SMTP forwarding completed", "domain", domain, "recipient", recipient, "mx_host", host, "bytes", len(data), "message_id", messageID, "response", response, "tls", tlsUsed, "tls_verified", tlsVerified)
			return nil
		}
		s.logger().Warn("SMTP forwarding attempt failed", "domain", domain, "recipient", recipient, "mx_host", host, "message_id", messageID, "error", relayErr)
		lastErr = relayErr
		if response, ok := relayErr.(smtpResponseError); ok && response.Code >= 500 && response.Code < 600 {
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
	network := strings.TrimSpace(s.RelayNetwork)
	if network == "" {
		network = "tcp"
	}
	return (&net.Dialer{Timeout: 30 * time.Second}).DialContext(ctx, network, address)
}

type smtpResponseError struct {
	Code int
	Text string
}

func (e smtpResponseError) Error() string { return fmt.Sprintf("SMTP %d %s", e.Code, e.Text) }

var errSMTPStartTLSHandshake = errors.New("SMTP STARTTLS handshake failed")

func relaySMTP(connection net.Conn, hostname, mxHost, from, recipient string, data []byte, allowSTARTTLS bool, logger *slog.Logger) (string, bool, bool, error) {
	reader := bufio.NewReaderSize(connection, 16*1024)
	writer := bufio.NewWriterSize(connection, 16*1024)
	if _, err := readSMTPResponse(reader, 220); err != nil {
		return "", false, false, err
	}
	capabilities, err := sendSMTPHello(reader, writer, hostname)
	if err != nil {
		return "", false, false, err
	}
	tlsUsed := false
	tlsVerified := false
	if allowSTARTTLS && hasSMTPCapability(capabilities, "STARTTLS") {
		if err := sendSMTPCommand(reader, writer, 220, "STARTTLS"); err != nil {
			return "", false, false, err
		}
		tlsConnection := tls.Client(connection, &tls.Config{
			ServerName:         strings.TrimSuffix(strings.TrimSpace(mxHost), "."),
			InsecureSkipVerify: true,
		})
		if err := tlsConnection.Handshake(); err != nil {
			return "", false, false, fmt.Errorf("%w: %v", errSMTPStartTLSHandshake, err)
		}
		tlsUsed = true
		if err := verifySMTPServerCertificate(tlsConnection.ConnectionState(), mxHost); err != nil {
			if logger != nil {
				logger.Warn("SMTP relay TLS certificate verification failed", "mx_host", mxHost, "error", err)
			}
		} else {
			tlsVerified = true
		}
		connection = tlsConnection
		reader = bufio.NewReaderSize(connection, 16*1024)
		writer = bufio.NewWriterSize(connection, 16*1024)
		capabilities, err = sendSMTPHello(reader, writer, hostname)
		if err != nil {
			return "", tlsUsed, tlsVerified, err
		}
	}
	if err := sendSMTPCommand(reader, writer, 250, "MAIL FROM:<%s>", from); err != nil {
		return "", tlsUsed, tlsVerified, err
	}
	if err := sendSMTPCommand(reader, writer, 250, "RCPT TO:<%s>", recipient); err != nil {
		return "", tlsUsed, tlsVerified, err
	}
	if err := sendSMTPCommand(reader, writer, 354, "DATA"); err != nil {
		return "", tlsUsed, tlsVerified, err
	}
	if err := writeSMTPData(writer, data); err != nil {
		return "", tlsUsed, tlsVerified, err
	}
	if err := writer.Flush(); err != nil {
		return "", tlsUsed, tlsVerified, err
	}
	response, err := readSMTPResponse(reader, 250)
	if err != nil {
		return "", tlsUsed, tlsVerified, err
	}
	_, _ = fmt.Fprint(writer, "QUIT\r\n")
	_ = writer.Flush()
	return "250 " + strings.TrimSpace(response), tlsUsed, tlsVerified, nil
}

func sendSMTPHello(reader *bufio.Reader, writer *bufio.Writer, hostname string) ([]string, error) {
	lines, err := sendSMTPCommandLines(reader, writer, 250, "EHLO %s", hostname)
	if err == nil {
		return lines, nil
	}
	response, ok := err.(smtpResponseError)
	if !ok || response.Code < 500 || response.Code >= 600 {
		return nil, err
	}
	if err := sendSMTPCommand(reader, writer, 250, "HELO %s", hostname); err != nil {
		return nil, err
	}
	return nil, nil
}

func hasSMTPCapability(lines []string, capability string) bool {
	for _, line := range lines {
		if len(line) < 4 {
			continue
		}
		fields := strings.Fields(line[4:])
		if len(fields) > 0 && strings.EqualFold(fields[0], capability) {
			return true
		}
	}
	return false
}

func verifySMTPServerCertificate(state tls.ConnectionState, serverName string) error {
	if len(state.PeerCertificates) == 0 {
		return errors.New("SMTP relay did not present a certificate")
	}
	intermediates := x509.NewCertPool()
	for _, certificate := range state.PeerCertificates[1:] {
		intermediates.AddCert(certificate)
	}
	_, err := state.PeerCertificates[0].Verify(x509.VerifyOptions{
		DNSName:       strings.TrimSuffix(strings.TrimSpace(serverName), "."),
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	return err
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

func sendSMTPCommandLines(reader *bufio.Reader, writer *bufio.Writer, expected int, format string, args ...any) ([]string, error) {
	if _, err := fmt.Fprintf(writer, format+"\r\n", args...); err != nil {
		return nil, err
	}
	if err := writer.Flush(); err != nil {
		return nil, err
	}
	return readSMTPResponseLines(reader, expected)
}

func readSMTPResponse(reader *bufio.Reader, expected int) (string, error) {
	lines, err := readSMTPResponseLines(reader, expected)
	if err != nil {
		return "", err
	}
	parts := make([]string, 0, len(lines))
	for _, line := range lines {
		if len(line) > 4 {
			parts = append(parts, line[4:])
		}
	}
	return strings.Join(parts, " "), nil
}

func readSMTPResponseLines(reader *bufio.Reader, expected int) ([]string, error) {
	var text strings.Builder
	var lines []string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		lines = append(lines, line)
		if len(line) < 3 {
			return nil, errors.New("malformed SMTP response")
		}
		code, parseErr := strconv.Atoi(line[:3])
		if parseErr != nil {
			return nil, errors.New("malformed SMTP response code")
		}
		if text.Len() > 0 {
			text.WriteByte(' ')
		}
		if len(line) > 4 {
			text.WriteString(line[4:])
		}
		if len(line) < 4 || line[3] != '-' {
			if code != expected {
				return nil, smtpResponseError{Code: code, Text: text.String()}
			}
			return lines, nil
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

func (s *Server) authenticate(ctx context.Context, argument string, reader *bufio.Reader, write func(string, ...any) error, authenticated *bool, remoteAddr string, authConnection *auth.Connection) error {
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
	if s.Authenticate == nil && s.AuthenticateContext == nil {
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
	accepted := false
	if s.AuthenticateContext != nil {
		var err error
		accepted, err = s.AuthenticateContext(ctx, username, password)
		if err != nil {
			logResult(false, "authentication temporarily unavailable")
			return write("454 4.7.0 authentication temporarily unavailable")
		}
	} else {
		accepted = s.Authenticate(username, password)
	}
	if !accepted {
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
