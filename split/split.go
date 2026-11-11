// Package split implements the TLS link between the local and remote halves
// of a split MyMail deployment.
//
// In split mode the daemon runs as either the "local" side (behind the ISP
// firewall, serving IMAP and local SMTP) or the "remote" side (in cloud
// infrastructure, handling external SMTP delivery).  The two sides exchange
// email over a mutual-TLS connection using a length-prefixed wire protocol
// with stream-based multiplexing so multiple messages can be in flight
// simultaneously.
//
// Wire protocol (all multi-byte integers are big-endian):
//
//	Frame: [1 byte type][4 byte length][payload...]
//
// Frame types:
//
//	TypeHandshake (0x00) — protocol handshake; each side sends exactly one as
//	the first frame on every connection.
//	Payload: [4 byte magic] where magic is 0xABBA for protocol version 1.
//
//	TypeMailboxList (0x02) — local sends its mailbox addresses to the remote.
//	Payload: [4 byte streamID][4 byte count][count x ([4 byte len][address bytes])]
//
//	TypeSendMail (0x01) — one side asks the other to deliver a message.
//	Payload: [4 byte streamID][4 byte fromLen][from bytes][4 byte rcptLen][rcpt bytes][message bytes]
//
//	TypeSubmitMail (0x03) — the remote asks the local side to submit a message
//	for processing and delivery.
//	Payload: same as TypeSendMail.
//
//	TypeAuth (0x04) — the remote asks the local side to authenticate SMTP credentials.
//	Payload: [4 byte streamID][4 byte usernameLen][username bytes][4 byte passwordLen][password bytes]
//
//	TypeTLSCertificate (0x05) — the local sends the remote its SMTP server certificate and key.
//	Payload: [4 byte streamID][4 byte certLen][certificate PEM][4 byte keyLen][private key PEM]
//
//	TypeAck (0x10) — positive acknowledgement for a delivered frame.
//	Payload: [4 byte streamID]
//
//	TypeErr (0x11) — error response for a delivered frame.
//	Payload: [4 byte streamID][4 byte msgLen][error message bytes]
package split

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ProtocolMagic is the 4-byte magic number sent during the handshake to
// identify the split protocol version.
const ProtocolMagic = 0xABBA

// Frame types exchanged over the split TLS link.
const (
	TypeHandshake      byte = 0x00
	TypeSendMail       byte = 0x01
	TypeMailboxList    byte = 0x02
	TypeSubmitMail     byte = 0x03
	TypeAuth           byte = 0x04
	TypeTLSCertificate byte = 0x05
	TypeAck            byte = 0x10
	TypeErr            byte = 0x11
)

// ErrAuthRejected reports that the local side rejected SMTP credentials.
var ErrAuthRejected = errors.New("authentication rejected")

// SendRequest carries a single email that one side of the split link asks the
// other side to deliver.
type SendRequest struct {
	From      string
	Recipient string
	Data      []byte
}

// link wraps a single TLS connection with multiplexed I/O.
// A background reader loop dispatches incoming requests to callbacks and
// routes Ack/Err frames to the pending channel for the matching stream ID.
type link struct {
	c      net.Conn
	log    *slog.Logger
	reader *bufio.Reader

	// writeMu protects concurrent writes to the shared writer.
	writeMu sync.Mutex
	writer  *bufio.Writer

	// Stream ID allocator — monotonically increasing, starts at 1.
	nextStreamID atomic.Uint32

	// Pending response waiters keyed by stream ID.
	pendingMu sync.Mutex
	pending   map[uint32]chan response

	// Deliver callback for incoming SendMail frames (server-side).
	deliver func(ctx context.Context, req SendRequest) error
	// submit callback for incoming SubmitMail frames (client-side).
	submit func(ctx context.Context, req SendRequest) error
	// authenticate callback for incoming Auth frames (client-side).
	authenticate func(ctx context.Context, username, password string) (bool, error)

	// onMailboxList callback for incoming MailboxList frames (server-side).
	onMailboxList func(addresses []string)
	// onTLSCertificate receives a TLS certificate sent by the local peer.
	onTLSCertificate func(certPEM, keyPEM []byte) error

	// done is closed when the reader loop exits.
	done chan struct{}

	// closed is set to 1 when close() is called, so new operations can check.
	closed atomic.Uint32
}

type response struct {
	ok  bool
	err string
}

func newLink(c net.Conn, log *slog.Logger, reader *bufio.Reader, writer *bufio.Writer,
	deliver func(ctx context.Context, req SendRequest) error,
	submit func(ctx context.Context, req SendRequest) error,
	authenticate func(ctx context.Context, username, password string) (bool, error),
	onMailboxList func(addresses []string),
	onTLSCertificate func(certPEM, keyPEM []byte) error,
) *link {
	l := &link{
		c:                c,
		log:              log,
		reader:           reader,
		writer:           writer,
		pending:          make(map[uint32]chan response),
		deliver:          deliver,
		submit:           submit,
		authenticate:     authenticate,
		onMailboxList:    onMailboxList,
		onTLSCertificate: onTLSCertificate,
		done:             make(chan struct{}),
	}
	l.nextStreamID.Store(1)
	return l
}

// start launches the background reader loop.
func (l *link) start() {
	go l.readLoop()
}

// readLoop reads frames from the connection and dispatches them.
func (l *link) readLoop() {
	defer close(l.done)
	for {
		frameType, frameData, err := readFrame(l.reader)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				l.log.Debug("split read error", "error", err)
			}
			// Clean up all pending waiters so Send calls unblock.
			l.pendingMu.Lock()
			for _, ch := range l.pending {
				ch <- response{ok: false, err: "connection closed"}
				close(ch)
			}
			l.pending = nil
			l.pendingMu.Unlock()
			return
		}
		switch frameType {
		case TypeSendMail:
			streamID, req, err := parseSendRequestWithStreamID(frameData)
			if err != nil {
				l.log.Warn("split malformed SendMail", "error", err)
				go l.writeErr(streamID, "malformed SendMail")
				continue
			}
			l.log.Info("split SendMail received", "stream", streamID, "from", req.From, "to", req.Recipient, "bytes", len(req.Data))
			go l.handleSendMail(streamID, req)
		case TypeSubmitMail:
			streamID, req, err := parseSendRequestWithStreamID(frameData)
			if err != nil {
				l.log.Warn("split malformed SubmitMail", "error", err)
				go l.writeErr(streamID, "malformed SubmitMail")
				continue
			}
			l.log.Info("split SubmitMail received", "stream", streamID, "from", req.From, "to", req.Recipient, "bytes", len(req.Data))
			go l.handleSubmitMail(streamID, req)
		case TypeAuth:
			streamID, username, password, err := parseAuthRequestWithStreamID(frameData)
			if err != nil {
				l.log.Warn("split malformed Auth", "error", err)
				go l.writeErr(streamID, "malformed Auth")
				continue
			}
			l.log.Info("split Auth received", "stream", streamID, "username", username)
			go l.handleAuthenticate(streamID, username, password)
		case TypeTLSCertificate:
			streamID, certPEM, keyPEM, err := parseTLSCertificateWithStreamID(frameData)
			if err != nil {
				l.log.Warn("split malformed TLS certificate", "error", err)
				go l.writeErr(streamID, "malformed TLS certificate")
				continue
			}
			go l.handleTLSCertificate(streamID, certPEM, keyPEM)
		case TypeAck:
			streamID := parseStreamIDFromAck(frameData)
			l.respondPending(streamID, response{ok: true})
		case TypeErr:
			streamID, errMsg := parseStreamIDAndErr(frameData)
			l.respondPending(streamID, response{ok: false, err: errMsg})
		case TypeHandshake:
			// Older servers sent a second handshake frame after the exchange.
			l.log.Debug("split ignoring duplicate handshake frame")
		case TypeMailboxList:
			streamID, addresses, err := parseMailboxListWithStreamID(frameData)
			if err != nil {
				l.log.Warn("split malformed MailboxList", "error", err)
				go l.writeErr(streamID, "malformed MailboxList")
				continue
			}
			l.log.Info("split MailboxList received", "stream", streamID, "count", len(addresses))
			if l.onMailboxList != nil {
				l.onMailboxList(addresses)
			}
			go l.writeAck(streamID)
		default:
			l.log.Warn("split unknown frame type", "type", fmt.Sprintf("0x%02x", frameType))
		}
	}
}

func (l *link) handleSendMail(streamID uint32, req SendRequest) {
	if l.deliver == nil {
		err := errors.New("no delivery handler")
		l.log.Warn("split Deliver failed", "stream", streamID, "from", req.From, "to", req.Recipient, "error", err)
		l.writeErr(streamID, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err := l.deliver(ctx, req)
	if err != nil {
		l.log.Warn("split Deliver failed", "stream", streamID, "from", req.From, "to", req.Recipient, "error", err)
		l.writeErr(streamID, err.Error())
	} else {
		l.log.Info("split Deliver completed", "stream", streamID, "from", req.From, "to", req.Recipient)
		l.writeAck(streamID)
	}
}

func (l *link) handleSubmitMail(streamID uint32, req SendRequest) {
	if l.submit == nil {
		err := errors.New("no submission handler")
		l.log.Warn("split SubmitMail failed", "stream", streamID, "from", req.From, "to", req.Recipient, "error", err)
		l.writeErr(streamID, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := l.submit(ctx, req); err != nil {
		l.log.Warn("split SubmitMail failed", "stream", streamID, "from", req.From, "to", req.Recipient, "error", err)
		l.writeErr(streamID, err.Error())
		return
	}
	l.log.Info("split SubmitMail completed", "stream", streamID, "from", req.From, "to", req.Recipient)
	l.writeAck(streamID)
}

func (l *link) handleAuthenticate(streamID uint32, username, password string) {
	if l.authenticate == nil {
		err := errors.New("no authentication handler")
		l.log.Warn("split Auth failed", "stream", streamID, "username", username, "error", err)
		l.writeErr(streamID, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ok, err := l.authenticate(ctx, username, password)
	if err != nil {
		l.log.Warn("split Auth failed", "stream", streamID, "username", username, "error", err)
		l.writeErr(streamID, err.Error())
		return
	}
	if !ok {
		l.log.Info("split Auth rejected", "stream", streamID, "username", username)
		l.writeErr(streamID, ErrAuthRejected.Error())
		return
	}
	l.log.Info("split Auth accepted", "stream", streamID, "username", username)
	l.writeAck(streamID)
}

func (l *link) handleTLSCertificate(streamID uint32, certPEM, keyPEM []byte) {
	if l.onTLSCertificate == nil {
		l.writeErr(streamID, "peer does not accept TLS certificates")
		return
	}
	if err := l.onTLSCertificate(certPEM, keyPEM); err != nil {
		l.log.Warn("split TLS certificate rejected", "stream", streamID, "error", err)
		l.writeErr(streamID, err.Error())
		return
	}
	l.log.Info("split TLS certificate accepted", "stream", streamID, "certificate_bytes", len(certPEM))
	l.writeAck(streamID)
}

func (l *link) writeAck(streamID uint32) {
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, streamID)
	l.writeMu.Lock()
	_ = writeFrame(l.writer, TypeAck, data)
	l.writeMu.Unlock()
}

func (l *link) writeErr(streamID uint32, msg string) {
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, streamID)
	writeString(&buf, msg)
	l.writeMu.Lock()
	_ = writeFrame(l.writer, TypeErr, buf.Bytes())
	l.writeMu.Unlock()
}

func (l *link) respondPending(streamID uint32, resp response) {
	l.pendingMu.Lock()
	ch, ok := l.pending[streamID]
	if ok {
		delete(l.pending, streamID)
	}
	l.pendingMu.Unlock()
	if ok {
		ch <- resp
		close(ch)
	}
}

// sendRequest sends a SendMail frame and waits for the Ack/Err response.
func (l *link) sendRequest(ctx context.Context, req SendRequest) error {
	return l.sendMailRequest(ctx, TypeSendMail, "SendMail", req)
}

func (l *link) submitRequest(ctx context.Context, req SendRequest) error {
	return l.sendMailRequest(ctx, TypeSubmitMail, "SubmitMail", req)
}

func (l *link) sendMailRequest(ctx context.Context, frameType byte, name string, req SendRequest) error {
	started := time.Now()
	streamID := uint32(0)
	fail := func(err error) error {
		l.log.Warn("split "+name+" failed", "stream", streamID, "from", req.From, "to", req.Recipient, "error", err, "duration", time.Since(started))
		return err
	}
	var err error
	streamID, err = l.request(ctx, frameType, name, func(id uint32) []byte {
		return marshalSendRequestWithStreamID(id, req)
	}, func(id uint32) {
		l.log.Info("split "+name+" sent", "stream", id, "from", req.From, "to", req.Recipient, "bytes", len(req.Data))
	})
	if err != nil {
		return fail(err)
	}
	l.log.Info("split "+name+" acknowledged", "stream", streamID, "to", req.Recipient, "duration", time.Since(started))
	return nil
}

func (l *link) authenticateRequest(ctx context.Context, username, password string) (bool, error) {
	_, err := l.request(ctx, TypeAuth, "Auth", func(streamID uint32) []byte {
		return marshalAuthRequestWithStreamID(streamID, username, password)
	}, nil)
	if err != nil {
		if err.Error() == ErrAuthRejected.Error() {
			return false, ErrAuthRejected
		}
		return false, err
	}
	return true, nil
}

func (l *link) request(ctx context.Context, frameType byte, name string, payload func(uint32) []byte, onSent func(uint32)) (uint32, error) {
	streamID := l.nextStreamID.Add(1) - 1
	if l.closed.Load() == 1 {
		return streamID, errors.New("connection closed")
	}
	ch := make(chan response, 1)
	l.pendingMu.Lock()
	if l.pending == nil {
		l.pendingMu.Unlock()
		return streamID, errors.New("connection closed")
	}
	l.pending[streamID] = ch
	l.pendingMu.Unlock()

	l.writeMu.Lock()
	err := writeFrame(l.writer, frameType, payload(streamID))
	l.writeMu.Unlock()
	if err != nil {
		l.removePending(streamID)
		return streamID, fmt.Errorf("write %s: %w", name, err)
	}
	if onSent != nil {
		onSent(streamID)
	}

	select {
	case resp, ok := <-ch:
		if !ok {
			return streamID, errors.New("connection closed")
		}
		if !resp.ok {
			return streamID, errors.New(resp.err)
		}
		return streamID, nil
	case <-ctx.Done():
		l.removePending(streamID)
		return streamID, ctx.Err()
	}
}

func (l *link) removePending(streamID uint32) {
	l.pendingMu.Lock()
	delete(l.pending, streamID)
	l.pendingMu.Unlock()
}

// sendMailboxList sends the mailbox list frame and waits for the response.
func (l *link) sendMailboxList(ctx context.Context, addresses []string) error {
	if l.closed.Load() == 1 {
		return errors.New("connection closed")
	}
	streamID := l.nextStreamID.Add(1) - 1
	ch := make(chan response, 1)
	l.pendingMu.Lock()
	if l.pending != nil {
		l.pending[streamID] = ch
	} else {
		l.pendingMu.Unlock()
		return errors.New("connection closed")
	}
	l.pendingMu.Unlock()

	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, streamID)
	buf.Write(marshalMailboxList(addresses))

	l.writeMu.Lock()
	err := writeFrame(l.writer, TypeMailboxList, buf.Bytes())
	l.writeMu.Unlock()
	if err != nil {
		l.removePending(streamID)
		return fmt.Errorf("write MailboxList: %w", err)
	}

	select {
	case resp, ok := <-ch:
		if !ok {
			return errors.New("connection closed")
		}
		if resp.ok {
			return nil
		}
		return errors.New(resp.err)
	case <-ctx.Done():
		l.removePending(streamID)
		return ctx.Err()
	}
}

func (l *link) close() {
	if !l.closed.CompareAndSwap(0, 1) {
		return // already closed
	}
	l.c.Close()
	// Wait for the read loop to exit, but with a timeout so that a stuck
	// read does not block shutdown indefinitely.
	select {
	case <-l.done:
	case <-time.After(3 * time.Second):
		l.log.Warn("split link read loop did not exit in time")
	}
}

// Server listens for incoming TLS connections from the peer side and dispatches
// SendRequest frames to the provided Deliver callback.
//
// In the remote role the server accepts exactly one connection at a time.
// When a connection is established, OnConnected is called (if set). When the
// connection drops, OnDisconnected is called. The remote can use these hooks
// to gate SMTP acceptance and refresh its mailbox cache.
type Server struct {
	Addr      string
	TLSConfig *tls.Config
	Logger    *slog.Logger
	OnReady   func()

	// ExpectedClientDN, when non-empty, requires the connecting client's
	// certificate subject DN to match exactly. The connection is rejected
	// if the DN does not match.
	ExpectedClientDN string

	// Deliver is called for each SendMail frame received from the peer. It
	// should return nil on success or an error describing the failure.
	// Multiple Deliver calls may run concurrently.
	Deliver func(ctx context.Context, req SendRequest) error

	// OnMailboxList is called when the peer sends its mailbox address list
	// (after the handshake). The remote side uses this to know which
	// incoming SMTP recipients should be forwarded back to the local.
	OnMailboxList func(addresses []string)

	// OnTLSCertificate validates and installs the SMTP certificate received from
	// the local peer. It is optional; when nil, certificate updates are rejected.
	OnTLSCertificate func(certPEM, keyPEM []byte) error

	// OnConnected is called when a peer connection completes its handshake
	// successfully. Only one peer can be connected at a time; a new
	// connection will reject the peer if one is already connected.
	OnConnected func()

	// OnDisconnected is called when a connected peer disconnects. The server
	// clears its mailbox cache and notifies via this callback.
	OnDisconnected func()

	activeMu sync.Mutex
	active   net.Conn // only one active connection at a time
	activeLn *link    // the multiplexed link wrapper
	activeWG sync.WaitGroup
	ctx      context.Context // set by ListenAndServe, used by handleConn
}

// ListenAndServe accepts TLS connections until ctx is canceled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	if s.TLSConfig == nil {
		return errors.New("split server requires TLS config")
	}
	if s.Deliver == nil {
		return errors.New("split server requires Deliver callback")
	}
	if s.Logger == nil {
		s.Logger = slog.Default()
	}

	listener, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return fmt.Errorf("listen split on %s: %w", s.Addr, err)
	}
	tlsListener := tls.NewListener(listener, s.TLSConfig)
	s.Logger.Info("split server listening", "address", tlsListener.Addr().String())
	if s.OnReady != nil {
		s.OnReady()
	}
	defer func() {
		_ = tlsListener.Close()
		s.Logger.Info("split server stopped")
		s.closeActive()
		s.activeWG.Wait()
	}()
	go func() {
		<-ctx.Done()
		_ = tlsListener.Close()
	}()
	s.ctx = ctx
	for {
		c, err := tlsListener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			s.Logger.Warn("split accept error", "error", err)
			time.Sleep(time.Second)
			continue
		}
		s.track(c)
		go func() {
			defer s.untrack(c)
			s.handleConn(c)
		}()
	}
}

func (s *Server) track(c net.Conn) {
	s.activeMu.Lock()
	s.active = c
	s.activeWG.Add(1)
	s.activeMu.Unlock()
}

func (s *Server) untrack(c net.Conn) {
	s.activeMu.Lock()
	if s.active == c {
		s.active = nil
		s.activeLn = nil
	}
	s.activeMu.Unlock()
	s.activeWG.Done()
}

func (s *Server) closeActive() {
	s.activeMu.Lock()
	if s.active != nil {
		_ = s.active.Close()
		s.active = nil
		s.activeLn = nil
	}
	s.activeMu.Unlock()
}

// HasActiveConnection reports whether a peer is currently connected.
func (s *Server) HasActiveConnection() bool {
	s.activeMu.Lock()
	defer s.activeMu.Unlock()
	return s.active != nil
}

// Send delivers a message to the connected peer over the split link.
// It returns an error if no peer is currently connected.
func (s *Server) Send(ctx context.Context, req SendRequest) error {
	s.activeMu.Lock()
	ln := s.activeLn
	s.activeMu.Unlock()
	if ln == nil {
		return errors.New("no active split connection")
	}
	return ln.sendRequest(ctx, req)
}

// Submit asks the local side to process and deliver a message through its
// normal submission path.
func (s *Server) Submit(ctx context.Context, req SendRequest) error {
	s.activeMu.Lock()
	ln := s.activeLn
	s.activeMu.Unlock()
	if ln == nil {
		return errors.New("no active split connection")
	}
	return ln.submitRequest(ctx, req)
}

// Authenticate asks the local side to validate SMTP credentials.
func (s *Server) Authenticate(ctx context.Context, username, password string) (bool, error) {
	s.activeMu.Lock()
	ln := s.activeLn
	s.activeMu.Unlock()
	if ln == nil {
		return false, errors.New("no active split connection")
	}
	return ln.authenticateRequest(ctx, username, password)
}

func (s *Server) handleConn(c net.Conn) {
	defer func() {
		c.Close()
		s.activeMu.Lock()
		if s.active == c {
			s.activeLn = nil
		}
		s.activeMu.Unlock()
	}()
	remote := c.RemoteAddr().String()
	s.Logger.Info("split connection accepted", "remote", remote)
	if tlsConn, ok := c.(*tls.Conn); ok {
		parent := s.ctx
		if parent == nil {
			parent = context.Background()
		}
		deadline := time.Now().Add(30 * time.Second)
		if err := tlsConn.SetDeadline(deadline); err != nil {
			s.Logger.Warn("split TLS handshake deadline set failed", "remote", remote, "error", err)
			return
		}
		ctx, cancel := context.WithDeadline(parent, deadline)
		err := tlsConn.HandshakeContext(ctx)
		cancel()
		if err != nil {
			attrs := []any{"remote", remote, "error", err, "reason", explainTLSError(err, "server")}
			attrs = append(attrs, certificateLogAttrs("server_certificate", configuredCertificate(s.TLSConfig))...)
			attrs = append(attrs, certificateLogAttrs("client_certificate", verificationCertificate(err))...)
			s.Logger.Warn("split TLS handshake failed", attrs...)
			s.onDisconnected()
			return
		}
		if err := tlsConn.SetDeadline(time.Time{}); err != nil {
			s.Logger.Warn("split TLS handshake deadline clear failed", "remote", remote, "error", err)
			return
		}
	}

	// Verify client certificate DN if configured.
	if s.ExpectedClientDN != "" {
		tlsConn, ok := c.(*tls.Conn)
		if !ok {
			s.Logger.Warn("split connection is not TLS, cannot verify client DN")
			return
		}
		state := tlsConn.ConnectionState()
		if len(state.PeerCertificates) == 0 {
			s.Logger.Warn("split connection has no client certificate")
			return
		}
		clientDN := state.PeerCertificates[0].Subject.String()
		if clientDN != s.ExpectedClientDN {
			s.Logger.Warn("split client DN mismatch",
				"expected", s.ExpectedClientDN, "got", clientDN)
			return
		}
		s.Logger.Info("split client DN verified", "dn", clientDN)
	}

	// Reject if another connection is already active.
	s.activeMu.Lock()
	if s.active != c {
		s.activeMu.Unlock()
		s.Logger.Warn("split connection rejected: another peer is already connected")
		c.Close()
		return
	}
	s.activeMu.Unlock()

	reader := bufio.NewReader(c)
	writer := bufio.NewWriter(c)

	// Perform handshake: send magic number and expect the same back.
	handshakeData := make([]byte, 4)
	binary.BigEndian.PutUint32(handshakeData, ProtocolMagic)
	if err := writeFrame(writer, TypeHandshake, handshakeData); err != nil {
		s.Logger.Warn("split handshake write error", "remote", remote, "error", err)
		s.onDisconnected()
		return
	}
	frameType, frameData, err := readFrame(reader)
	if err != nil {
		s.Logger.Warn("split handshake read error", "remote", remote, "error", err)
		s.onDisconnected()
		return
	}
	if frameType != TypeHandshake {
		s.Logger.Warn("split expected handshake, got different type",
			"remote", remote, "type", fmt.Sprintf("0x%02x", frameType))
		s.onDisconnected()
		return
	}
	if len(frameData) != 4 {
		s.Logger.Warn("split handshake payload wrong length", "remote", remote, "length", len(frameData))
		s.onDisconnected()
		return
	}
	magic := binary.BigEndian.Uint32(frameData)
	if magic != ProtocolMagic {
		s.Logger.Warn("split handshake magic mismatch",
			"remote", remote, "expected", fmt.Sprintf("0x%08X", ProtocolMagic), "got", fmt.Sprintf("0x%08X", magic))
		s.onDisconnected()
		return
	}
	s.Logger.Info("split handshake completed", "remote", remote)

	// Create the multiplexed link wrapper and start the reader loop.
	ln := newLink(c, s.Logger, reader, writer, s.Deliver, nil, nil, s.OnMailboxList, s.OnTLSCertificate)
	s.activeMu.Lock()
	s.activeLn = ln
	s.activeMu.Unlock()

	// Notify that the peer is connected.
	s.onConnected()

	// Start the reader loop; it handles all frames (SendMail, MailboxList, etc).
	ln.start()

	// Wait for the connection to close or the server context to be canceled.
	select {
	case <-ln.done:
		s.onDisconnected()
	case <-s.ctx.Done():
		// Shutdown requested — close the connection so the read loop exits.
		c.Close()
		s.onDisconnected()
	}
}

func (s *Server) onConnected() {
	if s.OnConnected != nil {
		s.OnConnected()
	}
}

func (s *Server) onDisconnected() {
	if s.OnDisconnected != nil {
		s.OnDisconnected()
	}
}

// reconnectInterval is how often the client retries connecting to the peer
// when the connection is lost or not yet established.
const reconnectInterval = 10 * time.Second

// Client connects to the remote split server and provides Send, Submit, and
// Authenticate operations. It maintains a persistent TLS connection with
// automatic reconnection and multiplexed I/O so multiple requests can be in
// flight simultaneously.
type Client struct {
	Addr             string
	TLSConfig        *tls.Config
	IgnoreServerName bool
	Logger           *slog.Logger
	// Deliver handles mail sent by the peer over the split connection.
	Deliver func(ctx context.Context, req SendRequest) error
	// Submit handles a submission request sent by the peer.
	Submit func(ctx context.Context, req SendRequest) error
	// Authenticate handles an SMTP authentication request sent by the peer.
	Authenticate func(ctx context.Context, username, password string) (bool, error)

	// OnConnected is called each time a connection is successfully established
	// (after the handshake). It runs in the background reconnect goroutine.
	OnConnected func()
	// OnDisconnected is called each time the connection is lost.
	OnDisconnected func()

	connMu    sync.Mutex
	conn      net.Conn
	clientLn  *link
	startDone chan struct{}
}

// Send delivers a message to the peer side over the split link. It reconnects
// if the connection is not currently open. Multiple Send calls can proceed
// concurrently over the same connection.
func (c *Client) Send(ctx context.Context, req SendRequest) error {
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	ln := c.getClientLink()
	if ln == nil {
		return errors.New("no active split connection")
	}
	return ln.sendRequest(ctx, req)
}

func (c *Client) getClientLink() *link {
	c.connMu.Lock()
	defer c.connMu.Unlock()
	return c.clientLn
}

// SendMailboxList sends the list of local mailbox addresses to the peer.
// This is typically called once after the connection is established so the
// remote knows which recipients should be forwarded back to the local.
func (c *Client) SendMailboxList(addresses []string) error {
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	ln := c.getClientLink()
	if ln == nil {
		return errors.New("no active split connection")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := ln.sendMailboxList(ctx, addresses)
	if err == nil {
		c.Logger.Info("split mailbox list sent", "count", len(addresses))
	}
	return err
}

// SendTLSCertificate sends the local SMTP certificate and its private key to
// the connected remote over the mutually authenticated split TLS link.
func (c *Client) SendTLSCertificate(certPEM, keyPEM []byte) error {
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	ln := c.getClientLink()
	if ln == nil {
		return errors.New("no active split connection")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := ln.request(ctx, TypeTLSCertificate, "TLSCertificate", func(streamID uint32) []byte {
		return marshalTLSCertificateWithStreamID(streamID, certPEM, keyPEM)
	}, nil)
	if err != nil {
		return err
	}
	c.Logger.Info("split TLS certificate sent", "certificate_bytes", len(certPEM))
	return nil
}

// IsConnected reports whether the client currently has an active connection
// to the peer split server.
func (c *Client) IsConnected() bool {
	c.connMu.Lock()
	defer c.connMu.Unlock()
	return c.conn != nil
}

// Start begins a background goroutine that maintains a persistent connection
// to the peer split server.  It retries every reconnectInterval (10 seconds)
// until the provided context is canceled.  Call Close or cancel the context
// to stop. Wait blocks until the background goroutine has exited.
func (c *Client) Start(ctx context.Context) {
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	if c.startDone == nil {
		c.startDone = make(chan struct{})
	}
	go func() {
		defer close(c.startDone)
		ticker := time.NewTicker(reconnectInterval)
		defer ticker.Stop()
		for {
			c.connMu.Lock()
			hasConn := c.conn != nil
			c.connMu.Unlock()

			if !hasConn {
				c.Logger.Info("split client connecting", "address", c.Addr)
				conn, ln, err := c.dialAndHandshake(ctx)
				if err != nil {
					if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
						c.closeConnection()
						return
					}
					c.Logger.Warn("split client connect failed, retrying in 10s", "error", err)
				} else {
					c.connMu.Lock()
					c.conn = conn
					c.clientLn = ln
					c.connMu.Unlock()
					c.Logger.Info("split client connected", "address", c.Addr)
					if c.OnConnected != nil {
						c.OnConnected()
					}
					continue
				}
			}
			select {
			case <-ctx.Done():
				c.closeConnection()
				return
			case <-ticker.C:
				c.connMu.Lock()
				ln := c.clientLn
				if ln != nil {
					select {
					case <-ln.done:
						c.Logger.Info("split client connection lost, reconnecting")
						c.closeConnectionLocked()
						if c.OnDisconnected != nil {
							go c.OnDisconnected()
						}
					default:
					}
				}
				c.connMu.Unlock()
			}
		}
	}()
}

// Wait blocks until the background goroutine started by Start has exited.
func (c *Client) Wait() {
	if c.startDone != nil {
		<-c.startDone
	}
}

// dialAndHandshake dials the peer and completes the handshake.
// Returns the net.Conn and the multiplexed link wrapper.
// Caller must NOT hold c.connMu.
func (c *Client) dialAndHandshake(ctx context.Context) (net.Conn, *link, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	tlsConfig := c.TLSConfig
	if c.IgnoreServerName && (tlsConfig == nil || !tlsConfig.InsecureSkipVerify) {
		tlsConfig = verifyChainIgnoringServerName(tlsConfig)
	}
	tlsDialer := &tls.Dialer{
		Config:    tlsConfig,
		NetDialer: dialer,
	}
	conn, err := tlsDialer.DialContext(ctx, "tcp", c.Addr)
	if err != nil {
		return nil, nil, fmt.Errorf("dial split %s: %w; TLS diagnosis: %s", c.Addr, err, explainTLSError(err, "client"))
	}
	writer := bufio.NewWriter(conn)
	reader := bufio.NewReader(conn)

	// Perform handshake: send magic number and expect the same back.
	handshakeData := make([]byte, 4)
	binary.BigEndian.PutUint32(handshakeData, ProtocolMagic)
	if err := writeFrame(writer, TypeHandshake, handshakeData); err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("split handshake write: %w; TLS diagnosis: %s", err, explainTLSError(err, "client"))
	}
	// Read the handshake response in a goroutine so context cancellation
	// can interrupt a blocking read.
	type frameResult struct {
		typ  byte
		data []byte
		err  error
	}
	frameCh := make(chan frameResult, 1)
	go func() {
		typ, data, err := readFrame(reader)
		frameCh <- frameResult{typ, data, err}
	}()
	select {
	case <-ctx.Done():
		conn.Close()
		return nil, nil, ctx.Err()
	case result := <-frameCh:
		if result.err != nil {
			conn.Close()
			return nil, nil, fmt.Errorf("split handshake read: %w; TLS diagnosis: %s", result.err, explainTLSError(result.err, "client"))
		}
		if result.typ != TypeHandshake {
			conn.Close()
			return nil, nil, fmt.Errorf("split handshake expected type 0x00, got 0x%02x", result.typ)
		}
		if len(result.data) != 4 {
			conn.Close()
			return nil, nil, fmt.Errorf("split handshake response wrong length %d", len(result.data))
		}
		remoteMagic := binary.BigEndian.Uint32(result.data)
		if remoteMagic != ProtocolMagic {
			conn.Close()
			return nil, nil, fmt.Errorf("split handshake magic mismatch: expected 0x%08X, got 0x%08X", ProtocolMagic, remoteMagic)
		}
	}

	// Create the multiplexed link wrapper and start the reader loop.
	ln := newLink(conn, c.Logger, reader, writer, c.Deliver, c.Submit, c.Authenticate, nil, nil)
	ln.start()

	return conn, ln, nil
}

// Close shuts down the client connection.
func (c *Client) Close() {
	c.closeConnection()
}

func (c *Client) closeConnectionLocked() {
	if c.clientLn != nil {
		c.clientLn.close()
		c.clientLn = nil
	}
	if c.conn != nil {
		_ = c.conn.Close()
		c.conn = nil
	}
}

func (c *Client) closeConnection() {
	c.connMu.Lock()
	c.closeConnectionLocked()
	c.connMu.Unlock()
}

// readFrame reads one length-prefixed frame from the reader.
func readFrame(r *bufio.Reader) (byte, []byte, error) {
	typ, err := r.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return 0, nil, err
	}
	length := binary.BigEndian.Uint32(lenBuf)
	if length == 0 {
		return typ, nil, nil
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(r, data); err != nil {
		return 0, nil, err
	}
	return typ, data, nil
}

// writeFrame writes one length-prefixed frame to the writer.
func writeFrame(w *bufio.Writer, typ byte, data []byte) error {
	if err := w.WriteByte(typ); err != nil {
		return err
	}
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(data)))
	if _, err := w.Write(lenBuf); err != nil {
		return err
	}
	if len(data) > 0 {
		if _, err := w.Write(data); err != nil {
			return err
		}
	}
	return w.Flush()
}

func marshalSendRequestWithStreamID(streamID uint32, req SendRequest) []byte {
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, streamID)
	writeString(&buf, req.From)
	writeString(&buf, req.Recipient)
	buf.Write(req.Data)
	return buf.Bytes()
}

func parseSendRequestWithStreamID(data []byte) (uint32, SendRequest, error) {
	r := bytes.NewReader(data)
	var streamID uint32
	if err := binary.Read(r, binary.BigEndian, &streamID); err != nil {
		return 0, SendRequest{}, fmt.Errorf("read streamID: %w", err)
	}
	from, err := readString(r)
	if err != nil {
		return 0, SendRequest{}, fmt.Errorf("read from: %w", err)
	}
	rcpt, err := readString(r)
	if err != nil {
		return 0, SendRequest{}, fmt.Errorf("read recipient: %w", err)
	}
	msg, err := io.ReadAll(r)
	if err != nil {
		return 0, SendRequest{}, fmt.Errorf("read message: %w", err)
	}
	return streamID, SendRequest{
		From:      from,
		Recipient: rcpt,
		Data:      msg,
	}, nil
}

func marshalAuthRequestWithStreamID(streamID uint32, username, password string) []byte {
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, streamID)
	writeString(&buf, username)
	writeString(&buf, password)
	return buf.Bytes()
}

func parseAuthRequestWithStreamID(data []byte) (uint32, string, string, error) {
	r := bytes.NewReader(data)
	var streamID uint32
	if err := binary.Read(r, binary.BigEndian, &streamID); err != nil {
		return 0, "", "", fmt.Errorf("read streamID: %w", err)
	}
	username, err := readString(r)
	if err != nil {
		return streamID, "", "", fmt.Errorf("read username: %w", err)
	}
	password, err := readString(r)
	if err != nil {
		return streamID, "", "", fmt.Errorf("read password: %w", err)
	}
	if r.Len() != 0 {
		return streamID, "", "", errors.New("unexpected trailing authentication data")
	}
	return streamID, username, password, nil
}

func marshalTLSCertificateWithStreamID(streamID uint32, certPEM, keyPEM []byte) []byte {
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, streamID)
	writeBytes(&buf, certPEM)
	writeBytes(&buf, keyPEM)
	return buf.Bytes()
}

func parseTLSCertificateWithStreamID(data []byte) (uint32, []byte, []byte, error) {
	r := bytes.NewReader(data)
	var streamID uint32
	if err := binary.Read(r, binary.BigEndian, &streamID); err != nil {
		return 0, nil, nil, fmt.Errorf("read streamID: %w", err)
	}
	certPEM, err := readBytes(r)
	if err != nil {
		return streamID, nil, nil, fmt.Errorf("read certificate: %w", err)
	}
	keyPEM, err := readBytes(r)
	if err != nil {
		return streamID, nil, nil, fmt.Errorf("read private key: %w", err)
	}
	if r.Len() != 0 {
		return streamID, nil, nil, errors.New("unexpected trailing TLS certificate data")
	}
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		return streamID, nil, nil, errors.New("certificate and private key must not be empty")
	}
	return streamID, certPEM, keyPEM, nil
}

func writeBytes(buf *bytes.Buffer, data []byte) {
	buf.Grow(4 + len(data))
	binary.Write(buf, binary.BigEndian, uint32(len(data)))
	buf.Write(data)
}

func readBytes(r *bytes.Reader) ([]byte, error) {
	var length uint32
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return nil, err
	}
	if uint64(length) > uint64(r.Len()) {
		return nil, io.ErrUnexpectedEOF
	}
	data := make([]byte, int(length))
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, err
	}
	return data, nil
}

func parseStreamIDFromAck(data []byte) uint32 {
	if len(data) >= 4 {
		return binary.BigEndian.Uint32(data)
	}
	return 0
}

func parseStreamIDAndErr(data []byte) (uint32, string) {
	r := bytes.NewReader(data)
	var streamID uint32
	if err := binary.Read(r, binary.BigEndian, &streamID); err != nil {
		return 0, "malformed error"
	}
	msg, err := readString(r)
	if err != nil {
		return streamID, "malformed error"
	}
	return streamID, msg
}

func parseMailboxListWithStreamID(data []byte) (uint32, []string, error) {
	r := bytes.NewReader(data)
	var streamID uint32
	if err := binary.Read(r, binary.BigEndian, &streamID); err != nil {
		return 0, nil, fmt.Errorf("read streamID: %w", err)
	}
	addresses, err := parseMailboxList(data[4:])
	return streamID, addresses, err
}

func writeString(buf *bytes.Buffer, s string) {
	b := []byte(s)
	buf.Grow(4 + len(b))
	binary.Write(buf, binary.BigEndian, uint32(len(b)))
	buf.Write(b)
}

func readString(r *bytes.Reader) (string, error) {
	var lenBuf [4]byte
	if _, err := r.Read(lenBuf[:]); err != nil {
		return "", err
	}
	length := binary.BigEndian.Uint32(lenBuf[:])
	if length == 0 {
		return "", nil
	}
	data := make([]byte, length)
	if _, err := r.Read(data); err != nil {
		return "", err
	}
	return string(data), nil
}

func marshalMailboxList(addresses []string) []byte {
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint32(len(addresses)))
	for _, addr := range addresses {
		writeString(&buf, addr)
	}
	return buf.Bytes()
}

func parseMailboxList(data []byte) ([]string, error) {
	r := bytes.NewReader(data)
	var countBuf [4]byte
	if _, err := r.Read(countBuf[:]); err != nil {
		return nil, fmt.Errorf("read count: %w", err)
	}
	count := binary.BigEndian.Uint32(countBuf[:])
	addresses := make([]string, 0, count)
	for i := uint32(0); i < count; i++ {
		addr, err := readString(r)
		if err != nil {
			return nil, fmt.Errorf("read address %d: %w", i, err)
		}
		addresses = append(addresses, addr)
	}
	return addresses, nil
}
