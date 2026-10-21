// Package imap implements the IMAP4rev1 service used to access Maildir.
package imap

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
	"mime/multipart"
	"net"
	netmail "net/mail"
	"net/textproto"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"mymail/auth"
	"mymail/maildir"
)

type Resolver func(username string) (mailbox string, ok bool)
type Authenticator func(username, password string) bool

var (
	errAuthenticationInvalid   = errors.New("invalid authentication response")
	errAuthenticationCancelled = errors.New("authentication cancelled")
)

type Server struct {
	Addr            string
	TLSConfig       *tls.Config
	StartTLSConfig  *tls.Config
	RequireSTARTTLS bool
	Hostname        string
	Version         string
	Store           *maildir.Store
	Resolve         Resolver
	Authenticate    Authenticator
	AuthLimiter     *auth.Limiter
	Logger          *slog.Logger
	recentMu        sync.Mutex
	recentClaims    map[string]map[uint32]struct{}
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	if s.Store == nil || s.Resolve == nil || s.Authenticate == nil {
		return errors.New("imap server requires store, resolver, and authenticator")
	}
	if s.Hostname == "" {
		s.Hostname = "localhost"
	}
	if s.Logger == nil {
		s.Logger = slog.Default()
	}
	listener, err := listen(s.Addr, s.TLSConfig)
	if err != nil {
		return fmt.Errorf("listen %s imap on %s: %w", tlsLabel(s.TLSConfig), s.Addr, err)
	}
	s.Logger.Info("IMAP server listening", "address", listener.Addr().String(), "tls", s.TLSConfig != nil)
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
			return err
		}
		go s.handle(ctx, conn)
	}
}

func (s *Server) startTLSConfig() *tls.Config {
	if s.StartTLSConfig != nil {
		return s.StartTLSConfig
	}
	return s.TLSConfig
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

func isTLSConnection(conn net.Conn) bool {
	_, ok := conn.(*tls.Conn)
	return ok
}

type session struct {
	username      string
	rootMailbox   string
	mailbox       string
	exists        int
	authenticated bool
	selected      bool
	readonly      bool
	recent        map[uint32]bool
	sequence      []uint32
	sequenceReady bool
}

func (s *Server) claimRecent(mailbox string, messages []maildir.Message) map[uint32]bool {
	s.recentMu.Lock()
	defer s.recentMu.Unlock()
	if s.recentClaims == nil {
		s.recentClaims = make(map[string]map[uint32]struct{})
	}
	claims := s.recentClaims[mailbox]
	if claims == nil {
		claims = make(map[uint32]struct{})
		s.recentClaims[mailbox] = claims
	}
	claimed := make(map[uint32]bool)
	for _, message := range messages {
		if !message.Recent {
			continue
		}
		if _, alreadyClaimed := claims[message.UID]; alreadyClaimed {
			continue
		}
		claims[message.UID] = struct{}{}
		claimed[message.UID] = true
	}
	return claimed
}

func (s *Server) refreshRecent(state *session, messages []maildir.Message) {
	if state.recent == nil {
		state.recent = make(map[uint32]bool)
	}
	for uid := range s.claimRecent(state.mailbox, messages) {
		state.recent[uid] = true
	}
}

func syncSequence(state *session, messages []maildir.Message) []maildir.Message {
	byUID := make(map[uint32]maildir.Message, len(messages))
	for _, message := range messages {
		byUID[message.UID] = message
	}
	if !state.sequenceReady {
		state.sequenceReady = true
		state.sequence = make([]uint32, 0, len(messages))
		for _, message := range messages {
			state.sequence = append(state.sequence, message.UID)
		}
		state.exists = len(messages)
		return messages
	}
	ordered := make([]maildir.Message, 0, len(messages))
	sequence := make([]uint32, 0, len(messages))
	for _, uid := range state.sequence {
		message, ok := byUID[uid]
		if !ok {
			continue
		}
		ordered = append(ordered, message)
		sequence = append(sequence, uid)
		delete(byUID, uid)
	}
	for _, message := range messages {
		if _, ok := byUID[message.UID]; !ok {
			continue
		}
		ordered = append(ordered, message)
		sequence = append(sequence, message.UID)
		delete(byUID, message.UID)
	}
	state.sequence = sequence
	state.exists = len(ordered)
	return ordered
}

func sequenceMessages(state *session, messages []maildir.Message) ([]maildir.Message, bool) {
	if !state.sequenceReady {
		messages = syncSequence(state, messages)
		state.exists = len(messages)
		return messages, false
	}
	byUID := make(map[uint32]maildir.Message, len(messages))
	for _, message := range messages {
		byUID[message.UID] = message
	}
	for _, uid := range state.sequence {
		if _, ok := byUID[uid]; !ok {
			ordered := make([]maildir.Message, len(state.sequence))
			for index, sequenceUID := range state.sequence {
				ordered[index] = byUID[sequenceUID]
			}
			return ordered, false
		}
	}
	added := len(messages) > len(state.sequence)
	if added {
		known := make(map[uint32]bool, len(state.sequence))
		for _, uid := range state.sequence {
			known[uid] = true
		}
		for _, message := range messages {
			if !known[message.UID] {
				state.sequence = append(state.sequence, message.UID)
				known[message.UID] = true
			}
		}
		state.exists = len(state.sequence)
	}
	ordered := make([]maildir.Message, len(state.sequence))
	for index, uid := range state.sequence {
		ordered[index] = byUID[uid]
	}
	return ordered, added
}

func removeSequenceUID(state *session, uid uint32) {
	for index, sequenceUID := range state.sequence {
		if sequenceUID != uid {
			continue
		}
		copy(state.sequence[index:], state.sequence[index+1:])
		state.sequence = state.sequence[:len(state.sequence)-1]
		state.exists = len(state.sequence)
		return
	}
}

func syncSequenceAndNotify(state *session, messages []maildir.Message, write func(string, ...any) error, announceGrowth bool) ([]maildir.Message, error, bool) {
	previous := append([]uint32(nil), state.sequence...)
	wasReady := state.sequenceReady
	messages = syncSequence(state, messages)
	state.exists = len(messages)
	if !wasReady {
		return messages, nil, false
	}
	present := make(map[uint32]bool, len(messages))
	for _, message := range messages {
		present[message.UID] = true
	}
	removed := make([]int, 0)
	for index, uid := range previous {
		if !present[uid] {
			removed = append(removed, index+1)
		}
	}
	sort.Ints(removed)
	for index := len(removed) - 1; index >= 0; index-- {
		if err := write("* %d EXPUNGE", removed[index]); err != nil {
			return messages, err, false
		}
	}
	added := false
	for _, message := range messages {
		found := false
		for _, uid := range previous {
			if uid == message.UID {
				found = true
				break
			}
		}
		if !found {
			added = true
			break
		}
	}
	if added && announceGrowth {
		if err := write("* %d EXISTS", len(messages)); err != nil {
			return messages, err, true
		}
	}
	return messages, nil, added
}

func (s *Server) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	tlsActive := isTLSConnection(conn)
	var authConnection *auth.Connection
	if s.AuthLimiter != nil {
		authConnection = s.AuthLimiter.NewConnection(remoteAddress(conn))
	}
	reader := bufio.NewReaderSize(conn, 64*1024)
	writer := bufio.NewWriterSize(conn, 64*1024)
	write := func(format string, args ...any) error {
		if _, err := fmt.Fprintf(writer, format+"\r\n", args...); err != nil {
			return err
		}
		return writer.Flush()
	}
	version := s.Version
	if version == "" {
		version = "devel"
	}
	if write("* OK %s MyMail IMAP4rev1 ready (version %s)", s.Hostname, version) != nil {
		return
	}
	var state session
	for {
		_ = conn.SetReadDeadline(time.Now().Add(30 * time.Minute))
		line, err := reader.ReadString('\n')
		if err != nil {
			if !errors.Is(err, io.EOF) {
				s.Logger.Debug("IMAP connection ended", "error", err)
			}
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := tokenize(line)
		if len(parts) < 2 {
			s.Logger.Warn("IMAP invalid action", "remote_addr", remoteAddress(conn))
			_ = write("* BAD command requires a tag and command")
			continue
		}
		tag, command := parts[0], strings.ToUpper(parts[1])
		args := parts[2:]
		s.Logger.Info("IMAP action", "remote_addr", remoteAddress(conn), "tag", tag, "command", command, "arguments", imapLogArguments(command, args), "username", state.username, "mailbox", state.mailbox, "authenticated", state.authenticated, "selected", state.selected, "readonly", state.readonly)
		switch command {
		case "CAPABILITY":
			if _, err := fmt.Fprintf(writer, "* CAPABILITY %s\r\n%s OK CAPABILITY completed\r\n", s.capabilitiesForTLS(tlsActive), tag); err != nil || writer.Flush() != nil {
				return
			}
		case "NOOP":
			if state.selected {
				messages, _ := s.Store.List(state.mailbox)
				s.refreshRecent(&state, messages)
				var syncErr error
				messages, syncErr, _ = syncSequenceAndNotify(&state, messages, write, false)
				if syncErr != nil {
					return
				}
				if write("* %d EXISTS", len(messages)) != nil || write("* %d RECENT", countRecent(messages, state.recent)) != nil {
					return
				}
			}
			if write("%s OK NOOP completed", tag) != nil {
				return
			}
		case "LOGIN":
			if len(args) != 2 {
				_ = write("%s BAD LOGIN requires username and password", tag)
				continue
			}
			if s.RequireSTARTTLS && !tlsActive {
				_ = write("%s NO [PRIVACYREQUIRED] TLS required", tag)
				continue
			}
			authenticated, authErr := s.authenticateSession(tag, args[0], args[1], &state, write, "LOGIN", tlsActive, authConnection)
			if authErr != nil {
				return
			}
			if !authenticated {
				continue
			}
		case "AUTHENTICATE":
			if len(args) < 1 || len(args) > 2 {
				_ = write("%s BAD AUTHENTICATE requires a mechanism", tag)
				continue
			}
			if s.RequireSTARTTLS && !tlsActive {
				_ = write("%s NO [PRIVACYREQUIRED] TLS required", tag)
				continue
			}
			initial := ""
			if len(args) == 2 {
				initial = args[1]
			}
			username, password, authErr := readAuthentication(args[0], initial, reader, write)
			if authErr != nil {
				if errors.Is(authErr, errAuthenticationInvalid) || errors.Is(authErr, errAuthenticationCancelled) {
					if authConnection != nil {
						if throttleErr := authConnection.Allow(""); throttleErr != nil {
							if errors.Is(throttleErr, auth.ErrConnectionLimit) {
								_ = write("%s BYE [AUTHENTICATIONFAILED] too many authentication attempts", tag)
								return
							}
							_ = write("%s NO [UNAVAILABLE] authentication temporarily unavailable", tag)
							continue
						}
						authConnection.Failure("")
					}
					message := "invalid credentials"
					if errors.Is(authErr, errAuthenticationCancelled) {
						message = "authentication cancelled"
					}
					_ = write("%s NO [AUTHENTICATIONFAILED] %s", tag, message)
					continue
				}
				return
			}
			authenticated, authErr := s.authenticateSession(tag, username, password, &state, write, "AUTHENTICATE", tlsActive, authConnection)
			if authErr != nil {
				return
			}
			if !authenticated {
				continue
			}
		case "APPEND":
			if !state.authenticated {
				_ = write("%s NO authenticate first", tag)
				continue
			}
			if len(args) < 2 {
				_ = write("%s BAD APPEND requires a mailbox and literal message", tag)
				continue
			}
			mailbox, ok := resolveMailbox(state.rootMailbox, args[0])
			if !ok {
				_ = write("%s NO invalid mailbox", tag)
				continue
			}
			literalSize, nonSynchronizing, ok := parseLiteral(args[len(args)-1])
			if !ok {
				_ = write("%s BAD APPEND requires a literal message", tag)
				continue
			}
			if !nonSynchronizing {
				if err := write("+ Ready for literal data"); err != nil {
					return
				}
			}
			data := make([]byte, literalSize)
			if _, err := io.ReadFull(reader, data); err != nil {
				return
			}
			message, err := s.Store.Deliver(mailbox, data)
			if err != nil {
				_ = write("%s NO cannot append message", tag)
				continue
			}
			flags := make(map[byte]bool)
			for _, value := range args[1 : len(args)-1] {
				if flag, valid := imapFlag(value); valid {
					flags[flag] = true
				}
			}
			if len(flags) > 0 {
				if message, err = s.Store.SetFlags(mailbox, message, flags); err != nil {
					_ = write("%s NO cannot set appended message flags", tag)
					continue
				}
			}
			messages, listErr := s.Store.List(mailbox)
			if listErr != nil {
				_ = write("%s NO cannot locate appended message", tag)
				continue
			}
			uid := 0
			for _, stored := range messages {
				if stored.Filename == message.Filename {
					uid = int(stored.UID)
					break
				}
			}
			if uid == 0 {
				_ = write("%s NO cannot locate appended message", tag)
				continue
			}
			if state.selected && state.mailbox == mailbox {
				s.refreshRecent(&state, messages)
				messages, err, _ = syncSequenceAndNotify(&state, messages, write, false)
				if err != nil {
					return
				}
				if err := write("* %d EXISTS", len(messages)); err != nil {
					return
				}
			}
			if err := write("%s OK [APPENDUID 1 %d] APPEND completed", tag, uid); err != nil {
				return
			}
		case "LOGOUT":
			if _, err := fmt.Fprintf(writer, "* BYE logging out\r\n%s OK LOGOUT completed\r\n", tag); err != nil || writer.Flush() != nil {
				return
			}
			return
		case "ID":
			if write("* ID NIL") != nil || write("%s OK ID completed", tag) != nil {
				return
			}
		case "IDLE":
			if !state.authenticated {
				_ = write("%s NO authenticate first", tag)
				continue
			}
			if !state.selected {
				_ = write("%s BAD select a mailbox first", tag)
				continue
			}
			knownMessages, listErr := s.Store.List(state.mailbox)
			if listErr != nil {
				_ = write("%s NO cannot monitor mailbox", tag)
				continue
			}
			s.refreshRecent(&state, knownMessages)
			if err := write("+ idling"); err != nil {
				return
			}
			selectedMessageCount := state.exists
			var syncErr error
			var added bool
			knownMessages, syncErr, added = syncSequenceAndNotify(&state, knownMessages, write, true)
			if syncErr != nil {
				return
			}
			knownMessagesByUID := idleMessagesByUID(knownMessages)
			if added {
				if err := write("* %d RECENT", countRecent(knownMessages, state.recent)); err != nil {
					return
				}
			} else if len(knownMessages) != selectedMessageCount {
				if err := write("* %d EXISTS", len(knownMessages)); err != nil || write("* %d RECENT", countRecent(knownMessages, state.recent)) != nil {
					return
				}
			}
			type idleRead struct {
				line string
				err  error
			}
			readResults := make(chan idleRead, 1)
			readLine := func() {
				go func() {
					line, err := reader.ReadString('\n')
					readResults <- idleRead{line: line, err: err}
				}()
			}
			readLine()
			ticker := time.NewTicker(500 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case result := <-readResults:
					if result.err != nil {
						return
					}
					if strings.EqualFold(strings.TrimSpace(result.line), "DONE") {
						if err := write("%s OK IDLE terminated", tag); err != nil {
							return
						}
						goto idleDone
					}
					readLine()
				case <-ticker.C:
					messages, listErr := s.Store.List(state.mailbox)
					if listErr != nil {
						continue
					}
					s.refreshRecent(&state, messages)
					messages = syncSequence(&state, messages)
					if err := writeIdleChanges(write, knownMessagesByUID, messages, state.recent); err != nil {
						return
					}
					state.exists = len(messages)
					knownMessagesByUID = idleMessagesByUID(messages)
				}
			}
		idleDone:
			_ = conn.SetReadDeadline(time.Now().Add(30 * time.Minute))
		case "LIST", "LSUB":
			if !state.authenticated {
				_ = write("%s NO authenticate first", tag)
				continue
			}
			s.listMailboxes(tag, args, &state, writer, command)
		case "NAMESPACE":
			if write("* NAMESPACE ((\"\" \".\")) NIL NIL") != nil || write("%s OK NAMESPACE completed", tag) != nil {
				return
			}
		case "SELECT", "EXAMINE":
			if !state.authenticated {
				_ = write("%s NO authenticate first", tag)
				continue
			}
			if len(args) != 1 {
				_ = write("%s BAD %s requires a mailbox", tag, command)
				continue
			}
			mailbox, ok := resolveMailbox(state.rootMailbox, args[0])
			if !ok {
				_ = write("%s NO invalid mailbox", tag)
				continue
			}
			messages, err := s.Store.List(mailbox)
			if err != nil {
				_ = write("%s NO cannot open mailbox", tag)
				continue
			}
			state.mailbox = mailbox
			state.selected = true
			state.readonly = command == "EXAMINE"
			state.recent = s.claimRecent(mailbox, messages)
			state.sequenceReady = false
			messages = syncSequence(&state, messages)
			if write("* %d EXISTS", len(messages)) != nil || write("* %d RECENT", countRecent(messages, state.recent)) != nil || write("* OK [UIDVALIDITY 1] mailbox selected") != nil || write("* OK [UIDNEXT %d] next uid", nextUID(messages)) != nil || write("%s OK [%s] %s completed", tag, map[bool]string{true: "READ-ONLY", false: "READ-WRITE"}[state.readonly], command) != nil {
				return
			}
		case "STATUS":
			if !state.authenticated || len(args) < 2 {
				_ = write("%s NO authenticate first", tag)
				continue
			}
			mailbox, ok := resolveMailbox(state.rootMailbox, args[0])
			if !ok {
				_ = write("%s NO invalid mailbox", tag)
				continue
			}
			messages, err := s.Store.List(mailbox)
			if err != nil {
				_ = write("%s NO mailbox unavailable", tag)
				continue
			}
			unseen := countUnseen(messages)
			if write("* STATUS %s (MESSAGES %d RECENT %d UNSEEN %d UIDNEXT %d UIDVALIDITY 1)", quoteIMAPString(args[0]), len(messages), countRecent(messages), unseen, nextUID(messages)) != nil || write("%s OK STATUS completed", tag) != nil {
				return
			}
		case "FETCH":
			if !s.requireSelected(&state, tag, write) {
				continue
			}
			s.fetch(tag, args, &state, writer, false)
		case "UID":
			if len(args) < 1 {
				_ = write("%s BAD UID requires a subcommand", tag)
				continue
			}
			if !s.requireSelected(&state, tag, write) {
				continue
			}
			switch strings.ToUpper(args[0]) {
			case "FETCH":
				s.fetch(tag, args[1:], &state, writer, true)
			case "SEARCH":
				s.search(tag, args[1:], &state, write, true)
			case "STORE":
				s.storeFlags(tag, args[1:], &state, write, true)
			case "COPY":
				s.copy(tag, args[1:], &state, write, true)
			case "EXPUNGE":
				if state.readonly {
					_ = write("%s NO mailbox is read-only", tag)
					continue
				}
				s.expungeUID(tag, args[1:], &state, write)
			default:
				_ = write("%s BAD unsupported UID subcommand", tag)
			}
		case "STORE":
			if !s.requireSelected(&state, tag, write) {
				continue
			}
			s.storeFlags(tag, args, &state, write, false)
		case "SEARCH":
			if !s.requireSelected(&state, tag, write) {
				continue
			}
			s.search(tag, args, &state, write, false)
		case "EXPUNGE":
			if !s.requireSelected(&state, tag, write) {
				continue
			}
			if state.readonly {
				_ = write("%s NO mailbox is read-only", tag)
				continue
			}
			s.expunge(tag, &state, write)
		case "CLOSE":
			if !s.requireSelected(&state, tag, write) {
				continue
			}
			if !state.readonly {
				if err := s.removeDeleted(&state); err != nil {
					_ = write("%s NO mailbox unavailable", tag)
					continue
				}
			}
			state.selected = false
			state.exists = 0
			state.sequence = nil
			state.sequenceReady = false
			if write("%s OK CLOSE completed", tag) != nil {
				return
			}
		case "CHECK":
			if !s.requireSelected(&state, tag, write) {
				continue
			}
			if write("%s OK CHECK completed", tag) != nil {
				return
			}
		case "COPY":
			if !s.requireSelected(&state, tag, write) {
				continue
			}
			s.copy(tag, args, &state, write, false)
		case "CREATE":
			if !state.authenticated {
				_ = write("%s NO authenticate first", tag)
				continue
			}
			if len(args) != 1 {
				_ = write("%s BAD CREATE requires a mailbox", tag)
				continue
			}
			mailbox, ok := resolveMailbox(state.rootMailbox, args[0])
			if !ok || mailbox == state.rootMailbox {
				_ = write("%s NO invalid mailbox", tag)
				continue
			}
			if err := s.Store.Ensure(mailbox); err != nil {
				_ = write("%s NO cannot create mailbox", tag)
				continue
			}
			_ = write("%s OK CREATE completed", tag)
		case "DELETE":
			if !state.authenticated {
				_ = write("%s NO authenticate first", tag)
				continue
			}
			if len(args) != 1 {
				_ = write("%s BAD DELETE requires a mailbox", tag)
				continue
			}
			mailbox, ok := resolveMailbox(state.rootMailbox, args[0])
			if !ok || mailbox == state.rootMailbox {
				_ = write("%s NO cannot delete INBOX or invalid mailbox", tag)
				continue
			}
			if err := s.Store.DeleteMailbox(mailbox); err != nil {
				_ = write("%s NO cannot delete mailbox", tag)
				continue
			}
			if state.selected && (state.mailbox == mailbox || strings.HasPrefix(state.mailbox, mailbox+".")) {
				state.mailbox = state.rootMailbox
				state.selected = false
				state.readonly = false
			}
			if write("%s OK DELETE completed", tag) != nil {
				return
			}
		case "RENAME":
			if !state.authenticated {
				_ = write("%s NO authenticate first", tag)
				continue
			}
			if len(args) != 2 {
				_ = write("%s BAD RENAME requires an old and new mailbox", tag)
				continue
			}
			oldMailbox, oldOK := resolveMailbox(state.rootMailbox, args[0])
			newMailbox, newOK := resolveMailbox(state.rootMailbox, args[1])
			if !oldOK || !newOK || oldMailbox == state.rootMailbox || newMailbox == state.rootMailbox {
				_ = write("%s NO cannot rename INBOX or invalid mailbox", tag)
				continue
			}
			if oldMailbox == newMailbox {
				if write("%s OK RENAME completed", tag) != nil {
					return
				}
				continue
			}
			if err := s.Store.RenameMailbox(oldMailbox, newMailbox); err != nil {
				_ = write("%s NO cannot rename mailbox", tag)
				continue
			}
			if state.selected && (state.mailbox == oldMailbox || strings.HasPrefix(state.mailbox, oldMailbox+".")) {
				state.mailbox = newMailbox + strings.TrimPrefix(state.mailbox, oldMailbox)
			}
			if write("%s OK RENAME completed", tag) != nil {
				return
			}
		case "SUBSCRIBE", "UNSUBSCRIBE":
			if !state.authenticated {
				_ = write("%s NO authenticate first", tag)
				continue
			}
			if len(args) != 1 {
				_ = write("%s BAD %s requires a mailbox", tag, command)
				continue
			}
			if _, ok := resolveMailbox(state.rootMailbox, args[0]); !ok {
				_ = write("%s NO invalid mailbox", tag)
				continue
			}
			if write("%s OK %s completed", tag, command) != nil {
				return
			}
		case "STARTTLS":
			if tlsActive {
				_ = write("%s BAD STARTTLS already active", tag)
				continue
			}
			if state.authenticated {
				_ = write("%s BAD STARTTLS not permitted after authentication", tag)
				continue
			}
			tlsConfig := s.startTLSConfig()
			if tlsConfig == nil {
				_ = write("%s NO TLS is not available", tag)
				continue
			}
			if err := write("%s OK Begin TLS negotiation now", tag); err != nil {
				return
			}
			tlsConn := tls.Server(conn, tlsConfig)
			if err := tlsConn.Handshake(); err != nil {
				return
			}
			conn = tlsConn
			tlsActive = true
			reader = bufio.NewReaderSize(conn, 64*1024)
			writer = bufio.NewWriterSize(conn, 64*1024)
			state = session{}
		default:
			_ = write("%s BAD command not implemented", tag)
		}
		_ = ctx
	}
}

func remoteAddress(conn net.Conn) string {
	if address := conn.RemoteAddr(); address != nil {
		return address.String()
	}
	return "unknown"
}

func imapLogArguments(command string, args []string) []string {
	logged := append([]string(nil), args...)
	switch command {
	case "LOGIN":
		if len(logged) > 1 {
			logged[1] = "[REDACTED]"
		}
	case "AUTHENTICATE":
		for index := 1; index < len(logged); index++ {
			logged[index] = "[REDACTED]"
		}
	}
	return logged
}

func (s *Server) authenticateSession(tag, username, password string, state *session, write func(string, ...any) error, command string, tlsActive bool, authConnection *auth.Connection) (bool, error) {
	if s.RequireSTARTTLS && !tlsActive {
		_ = write("%s NO [PRIVACYREQUIRED] TLS required", tag)
		return false, nil
	}
	if authConnection != nil {
		if err := authConnection.Allow(username); err != nil {
			if errors.Is(err, auth.ErrConnectionLimit) {
				_ = write("%s BYE [AUTHENTICATIONFAILED] too many authentication attempts", tag)
				return false, err
			}
			_ = write("%s NO [UNAVAILABLE] authentication temporarily unavailable", tag)
			return false, nil
		}
	}
	if !s.Authenticate(username, password) {
		if authConnection != nil {
			authConnection.Failure(username)
		}
		_ = write("%s NO [AUTHENTICATIONFAILED] invalid credentials", tag)
		return false, nil
	}
	mailbox, ok := s.Resolve(username)
	if !ok || s.Store.Ensure(mailbox) != nil {
		_ = write("%s NO mailbox unavailable", tag)
		return false, nil
	}
	if authConnection != nil {
		authConnection.Success(username)
	}
	state.authenticated = true
	state.username = username
	state.rootMailbox = mailbox
	state.mailbox = mailbox
	if command == "LOGIN" {
		_ = write("%s OK [CAPABILITY %s] LOGIN completed", tag, s.capabilitiesForTLS(tlsActive))
	} else {
		_ = write("%s OK [CAPABILITY %s] AUTHENTICATE completed", tag, s.capabilitiesForTLS(tlsActive))
	}
	return true, nil
}

func (s *Server) capabilities() string {
	return s.capabilitiesForTLS(false)
}

func (s *Server) capabilitiesForTLS(tlsActive bool) string {
	capability := "IMAP4rev1 NAMESPACE ID IDLE APPEND UIDPLUS"
	if !s.RequireSTARTTLS || tlsActive {
		capability += " AUTH=PLAIN AUTH=LOGIN"
	}
	if s.startTLSConfig() != nil && !tlsActive {
		capability += " STARTTLS"
	}
	return capability
}

func resolveMailbox(root, name string) (string, bool) {
	root = strings.TrimSpace(root)
	name = strings.TrimSpace(name)
	if root == "" || name == "" {
		return "", false
	}
	if strings.EqualFold(name, "INBOX") {
		return root, true
	}
	for _, prefix := range []string{"INBOX.", "INBOX/"} {
		if len(name) > len(prefix) && strings.EqualFold(name[:len(prefix)], prefix) {
			name = name[len(prefix):]
			break
		}
	}
	if name == "" || name == "." || name == ".." || strings.Contains(name, "\\") || strings.Contains(name, "\x00") {
		return "", false
	}
	if strings.Contains(name, "/") {
		parts := strings.Split(name, "/")
		for _, part := range parts {
			if part == "" || part == "." || part == ".." {
				return "", false
			}
		}
		name = strings.Join(parts, ".")
	}
	return root + "/" + name, true
}

func (s *Server) listMailboxes(tag string, args []string, state *session, writer *bufio.Writer, command string) {
	if len(args) < 2 {
		_, _ = fmt.Fprintf(writer, "%s BAD %s requires a reference and pattern\r\n", tag, command)
		_ = writer.Flush()
		return
	}
	folders, err := s.Store.ListMailboxes(state.rootMailbox)
	if err != nil {
		_, _ = fmt.Fprintf(writer, "%s NO mailbox unavailable\r\n", tag)
		_ = writer.Flush()
		return
	}
	names := []string{"INBOX"}
	for _, folder := range folders {
		names = append(names, folder)
	}
	pattern := args[len(args)-1]
	for _, name := range names {
		if !matchesMailboxPattern(name, pattern) {
			continue
		}
		attribute := `\HasNoChildren`
		for _, folder := range folders {
			if strings.HasPrefix(folder, name+".") {
				attribute = `\HasChildren`
				break
			}
		}
		if _, err := fmt.Fprintf(writer, "* %s (%s) \".\" \"%s\"\r\n", command, attribute, name); err != nil {
			return
		}
	}
	_, _ = fmt.Fprintf(writer, "%s OK %s completed\r\n", tag, command)
	_ = writer.Flush()
}

func matchesMailboxPattern(name, pattern string) bool {
	var match func(int, int) bool
	match = func(nameIndex, patternIndex int) bool {
		if patternIndex == len(pattern) {
			return nameIndex == len(name)
		}
		switch pattern[patternIndex] {
		case '*':
			return match(nameIndex, patternIndex+1) || (nameIndex < len(name) && match(nameIndex+1, patternIndex))
		case '%':
			if match(nameIndex, patternIndex+1) {
				return true
			}
			return nameIndex < len(name) && name[nameIndex] != '.' && match(nameIndex+1, patternIndex)
		default:
			return nameIndex < len(name) && name[nameIndex] == pattern[patternIndex] && match(nameIndex+1, patternIndex+1)
		}
	}
	return match(0, 0)
}

func readAuthentication(mechanism, initial string, reader *bufio.Reader, write func(string, ...any) error) (string, string, error) {
	switch strings.ToUpper(mechanism) {
	case "PLAIN":
		if initial == "" || initial == "=" {
			if err := write("+ "); err != nil {
				return "", "", err
			}
			var err error
			initial, err = readAuthenticationResponse(reader)
			if err != nil {
				return "", "", err
			}
		}
		decoded, err := base64.StdEncoding.DecodeString(initial)
		if err != nil {
			return "", "", errAuthenticationInvalid
		}
		parts := strings.Split(string(decoded), "\x00")
		if len(parts) != 3 || parts[1] == "" {
			return "", "", errAuthenticationInvalid
		}
		return parts[1], parts[2], nil
	case "LOGIN":
		if initial != "" {
			return "", "", errAuthenticationInvalid
		}
		if err := write("+ VXNlcm5hbWU6"); err != nil {
			return "", "", err
		}
		encodedUsername, err := readAuthenticationResponse(reader)
		if err != nil {
			return "", "", err
		}
		username, err := base64.StdEncoding.DecodeString(encodedUsername)
		if err != nil || len(username) == 0 {
			return "", "", errAuthenticationInvalid
		}
		if err := write("+ UGFzc3dvcmQ6"); err != nil {
			return "", "", err
		}
		encodedPassword, err := readAuthenticationResponse(reader)
		if err != nil {
			return "", "", err
		}
		password, err := base64.StdEncoding.DecodeString(encodedPassword)
		if err != nil {
			return "", "", errAuthenticationInvalid
		}
		return string(username), string(password), nil
	default:
		return "", "", errAuthenticationInvalid
	}
}

func readAuthenticationResponse(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	line = strings.TrimSpace(line)
	if line == "*" {
		return "", errAuthenticationCancelled
	}
	return line, nil
}

func (s *Server) requireSelected(state *session, tag string, write func(string, ...any) error) bool {
	if !state.authenticated {
		_ = write("%s NO authenticate first", tag)
		return false
	}
	if !state.selected {
		_ = write("%s BAD select a mailbox first", tag)
		return false
	}
	return true
}

func (s *Server) fetch(tag string, args []string, state *session, writer *bufio.Writer, uid bool) {
	if len(args) < 1 {
		fmt.Fprintf(writer, "%s BAD FETCH requires a sequence set\r\n", tag)
		_ = writer.Flush()
		return
	}
	messages, err := s.Store.List(state.mailbox)
	if err != nil {
		fmt.Fprintf(writer, "%s NO mailbox unavailable\r\n", tag)
		_ = writer.Flush()
		return
	}
	s.refreshRecent(state, messages)
	var added bool
	messages, added = sequenceMessages(state, messages)
	if added {
		fmt.Fprintf(writer, "* %d EXISTS\r\n", len(messages))
	}
	requested := strings.ToUpper(strings.Join(args[1:], " "))
	if requested == "" {
		requested = "FLAGS BODY[]"
	}
	includeUID := uid || strings.Contains(requested, "UID")
	bodyRequested := strings.Contains(requested, "BODY[") || strings.Contains(requested, "BODY.PEEK[") || strings.Contains(requested, "RFC822")
	structureRequested := strings.Contains(requested, "BODYSTRUCTURE")
	envelopeRequested := strings.Contains(requested, "ENVELOPE")
	numbers := sequenceNumbers(args[0], len(messages))
	if uid {
		numbers = uidMessageNumbers(args[0], messages)
	}
	for _, number := range numbers {
		message := messages[number-1]
		if message.UID == 0 {
			continue
		}
		bodySections := []fetchBodySection(nil)
		var data []byte
		dataLoaded := false
		if bodyRequested || structureRequested || envelopeRequested {
			var readErr error
			data, readErr = s.Store.Read(message)
			if readErr != nil {
				continue
			}
			dataLoaded = true
			if bodyRequested {
				bodySections = parseFetchBodySections(requested, data)
			}
		}
		markSeen := false
		for _, section := range bodySections {
			if section.markSeen {
				markSeen = true
				break
			}
		}
		if markSeen && !message.Flags['S'] && !state.readonly {
			if updated, updateErr := s.Store.SetFlags(state.mailbox, message, addFlag(message.Flags, 'S', true)); updateErr == nil {
				message = updated
				messages[number-1] = updated
			}
		}
		flags := formatMessageFlags(message, messageIsRecent(message, state.recent))
		if bodyRequested || structureRequested || envelopeRequested {
			fmt.Fprintf(writer, "* %d FETCH (", number)
			if includeUID {
				fmt.Fprintf(writer, "UID %d ", message.UID)
			}
			fmt.Fprintf(writer, "FLAGS (%s)", flags)
			if strings.Contains(requested, "INTERNALDATE") {
				fmt.Fprintf(writer, " INTERNALDATE %s", quoteIMAPString(message.InternalDate.UTC().Format("02-Jan-2006 15:04:05 -0700")))
			}
			size := message.Size
			if dataLoaded {
				size = int64(len(data))
			}
			fmt.Fprintf(writer, " RFC822.SIZE %d", size)
			if structureRequested {
				fmt.Fprintf(writer, " BODYSTRUCTURE %s", fetchBodyStructure(data))
			}
			if envelopeRequested {
				fmt.Fprintf(writer, " ENVELOPE %s", fetchEnvelope(data))
			}
			for _, section := range bodySections {
				fmt.Fprintf(writer, " %s {%d}\r\n", section.label, len(section.data))
				_, _ = writer.Write(section.data)
			}
			fmt.Fprint(writer, ")\r\n")
		} else {
			fmt.Fprintf(writer, "* %d FETCH (", number)
			if includeUID {
				fmt.Fprintf(writer, "UID %d ", message.UID)
			}
			size := message.Size
			if data, readErr := s.Store.Read(message); readErr == nil {
				size = int64(len(data))
			}
			fmt.Fprintf(writer, "FLAGS (%s) RFC822.SIZE %d INTERNALDATE \"%s\")\r\n", flags, size, message.InternalDate.UTC().Format("02-Jan-2006 15:04:05 -0700"))
		}
	}
	fmt.Fprintf(writer, "%s OK FETCH completed\r\n", tag)
	_ = writer.Flush()
}

func fetchBodyStructure(data []byte) string {
	entity, err := rootMIMEEntity(data)
	if err != nil {
		return `("TEXT" "PLAIN" NIL NIL NIL "7BIT" 0 0 NIL NIL NIL NIL)`
	}
	return formatMIMEBodyStructure(entity)
}

type mimeEntity struct {
	header textproto.MIMEHeader
	body   []byte
}

func rootMIMEEntity(data []byte) (mimeEntity, error) {
	separator, separatorSize := bytesIndex(data, []byte("\r\n\r\n"))
	if separator < 0 {
		separator, separatorSize = bytesIndex(data, []byte("\n\n"))
	}
	body := []byte(nil)
	if separator >= 0 {
		body = data[separator+separatorSize:]
	}
	return mimeEntity{header: parseEnvelopeHeaders(data), body: body}, nil
}

func formatMIMEBodyStructure(entity mimeEntity) string {
	mediaType, params, err := mime.ParseMediaType(entity.header.Get("Content-Type"))
	if err != nil || mediaType == "" {
		mediaType = "text/plain"
		params = nil
	}
	typeName, subtype, ok := strings.Cut(strings.ToUpper(mediaType), "/")
	if !ok || typeName == "" || subtype == "" {
		typeName, subtype = "TEXT", "PLAIN"
	}
	parameters := formatMIMEParameters(params)
	if typeName == "MULTIPART" {
		parts := multipartEntities(entity, params["boundary"])
		structure := make([]string, 0, len(parts)+5)
		for _, part := range parts {
			structure = append(structure, formatMIMEBodyStructure(part))
		}
		structure = append(structure, quoteIMAPString(subtype), parameters, formatMIMEDisposition(entity.header.Get("Content-Disposition")), formatMIMELanguage(entity.header.Get("Content-Language")), imapEnvelopeValue(entity.header.Get("Content-Location")))
		return "(" + strings.Join(structure, " ") + ")"
	}

	encoding := strings.ToUpper(strings.TrimSpace(entity.header.Get("Content-Transfer-Encoding")))
	if encoding == "" {
		encoding = "7BIT"
	}
	lines := 0
	if typeName == "TEXT" {
		lines = messageLines(entity.body)
	}
	return fmt.Sprintf("(%s %s %s %s %s %s %d %d %s %s %s %s)",
		quoteIMAPString(typeName), quoteIMAPString(subtype), parameters,
		imapHeaderValue(entity.header.Get("Content-ID")),
		imapHeaderValue(entity.header.Get("Content-Description")), quoteIMAPString(encoding),
		len(entity.body), lines, imapHeaderValue(entity.header.Get("Content-MD5")),
		formatMIMEDisposition(entity.header.Get("Content-Disposition")),
		formatMIMELanguage(entity.header.Get("Content-Language")), imapEnvelopeValue(entity.header.Get("Content-Location")))
}

func multipartEntities(entity mimeEntity, boundary string) []mimeEntity {
	if boundary == "" {
		return nil
	}
	reader := multipart.NewReader(bytes.NewReader(entity.body), boundary)
	var parts []mimeEntity
	for {
		part, err := reader.NextRawPart()
		if errors.Is(err, io.EOF) {
			return parts
		}
		if err != nil {
			return parts
		}
		body, err := io.ReadAll(part)
		if err != nil {
			return parts
		}
		parts = append(parts, mimeEntity{header: part.Header, body: body})
	}
}

func formatMIMEParameters(params map[string]string) string {
	if len(params) == 0 {
		return "NIL"
	}
	keys := make([]string, 0, len(params))
	for key := range params {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	values := make([]string, 0, len(keys)*2)
	for _, key := range keys {
		values = append(values, quoteIMAPString(strings.ToUpper(key)), quoteIMAPString(params[key]))
	}
	return "(" + strings.Join(values, " ") + ")"
}

func imapHeaderValue(value string) string {
	if strings.TrimSpace(value) == "" {
		return "NIL"
	}
	return quoteIMAPString(value)
}

func formatMIMEDisposition(value string) string {
	if strings.TrimSpace(value) == "" {
		return "NIL"
	}
	disposition, params, err := mime.ParseMediaType(value)
	if err != nil || disposition == "" {
		return "NIL"
	}
	return "(" + quoteIMAPString(strings.ToUpper(disposition)) + " " + formatMIMEParameters(params) + ")"
}

func formatMIMELanguage(value string) string {
	if strings.TrimSpace(value) == "" {
		return "NIL"
	}
	values := strings.Split(value, ",")
	quoted := make([]string, 0, len(values))
	for _, item := range values {
		if strings.TrimSpace(item) != "" {
			quoted = append(quoted, quoteIMAPString(strings.TrimSpace(item)))
		}
	}
	if len(quoted) == 0 {
		return "NIL"
	}
	return "(" + strings.Join(quoted, " ") + ")"
}

func messageLines(data []byte) int {
	if len(data) == 0 {
		return 0
	}
	lines := bytes.Count(data, []byte{'\n'})
	if data[len(data)-1] != '\n' {
		lines++
	}
	return lines
}

func fetchEnvelope(data []byte) string {
	header := parseEnvelopeHeaders(data)
	fields := []string{
		imapEnvelopeValue(header.Get("Date")),
		imapEnvelopeValue(header.Get("Subject")),
		envelopeAddresses(header.Get("From")),
		envelopeAddresses(header.Get("Sender")),
		envelopeAddresses(header.Get("Reply-To")),
		envelopeAddresses(header.Get("To")),
		envelopeAddresses(header.Get("Cc")),
		envelopeAddresses(header.Get("Bcc")),
		imapEnvelopeValue(header.Get("In-Reply-To")),
		imapEnvelopeValue(header.Get("Message-Id")),
	}
	return "(" + strings.Join(fields, " ") + ")"
}

func parseEnvelopeHeaders(data []byte) textproto.MIMEHeader {
	separator, separatorSize := bytesIndex(data, []byte("\r\n\r\n"))
	if separator < 0 {
		separator, separatorSize = bytesIndex(data, []byte("\n\n"))
	}
	if separator < 0 {
		separator = len(data)
		separatorSize = 0
	}
	headerData := data[:separator]
	if separatorSize == 4 {
		headerData = bytes.ReplaceAll(headerData, []byte("\r\n"), []byte("\n"))
	}
	result := make(textproto.MIMEHeader)
	current := ""
	for _, line := range bytes.Split(headerData, []byte{'\n'}) {
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			if current != "" {
				values := result[current]
				values[len(values)-1] += " " + strings.TrimSpace(string(line))
				result[current] = values
			}
			continue
		}
		colon := bytes.IndexByte(line, ':')
		if colon <= 0 {
			current = ""
			continue
		}
		name := textproto.CanonicalMIMEHeaderKey(strings.TrimSpace(string(line[:colon])))
		if name == "" {
			current = ""
			continue
		}
		result.Add(name, strings.TrimSpace(string(line[colon+1:])))
		current = name
	}
	return result
}

func imapEnvelopeValue(value string) string {
	if strings.TrimSpace(value) == "" {
		return "NIL"
	}
	return quoteIMAPString(value)
}

func envelopeAddresses(value string) string {
	if strings.TrimSpace(value) == "" {
		return "NIL"
	}
	addresses, err := netmail.ParseAddressList(value)
	if err != nil || len(addresses) == 0 {
		return "NIL"
	}
	result := make([]string, 0, len(addresses))
	for _, address := range addresses {
		local, domain, ok := strings.Cut(address.Address, "@")
		if !ok || local == "" || domain == "" {
			continue
		}
		name := "NIL"
		if address.Name != "" {
			name = quoteIMAPString(address.Name)
		}
		result = append(result, fmt.Sprintf("(%s NIL %s %s)", name, quoteIMAPString(local), quoteIMAPString(domain)))
	}
	if len(result) == 0 {
		return "NIL"
	}
	return "(" + strings.Join(result, " ") + ")"
}

type fetchBodySection struct {
	label    string
	data     []byte
	peek     bool
	markSeen bool
}

func parseFetchBodySections(requested string, data []byte) []fetchBodySection {
	upper := strings.ToUpper(requested)
	sections := make([]fetchBodySection, 0, 2)
	for index := 0; index < len(upper); {
		if strings.HasPrefix(upper[index:], "BODY.PEEK[") || strings.HasPrefix(upper[index:], "BODY[") {
			peek := strings.HasPrefix(upper[index:], "BODY.PEEK[")
			open := index + len("BODY")
			if peek {
				open += len(".PEEK")
			}
			closeIdx := strings.IndexByte(upper[open:], ']')
			if closeIdx < 0 {
				break
			}
			closeIdx += open
			section := requested[open+1 : closeIdx]
			sections = append(sections, fetchBodySection{
				label:    "BODY[" + upper[open+1:closeIdx] + "]",
				data:     bodySectionData(section, data),
				peek:     peek,
				markSeen: !peek && bodySectionMarksSeen(section),
			})
			index = closeIdx + 1
			continue
		}
		if strings.HasPrefix(upper[index:], "RFC822") {
			end := index + len("RFC822")
			for end < len(upper) && (upper[end] == '.' || (upper[end] >= 'A' && upper[end] <= 'Z')) {
				end++
			}
			label := upper[index:end]
			if label != "RFC822.SIZE" {
				section := strings.TrimPrefix(label, "RFC822.")
				sections = append(sections, fetchBodySection{label: label, data: bodySectionData(section, data), markSeen: bodySectionMarksSeen(section)})
			}
			index = end
			continue
		}
		index++
	}
	return sections
}

func bodySectionMarksSeen(section string) bool {
	switch strings.ToUpper(strings.TrimSpace(section)) {
	case "", "1", "TEXT", "RFC822", "RFC822.TEXT":
		return true
	default:
		return false
	}
}

func bodySectionData(section string, data []byte) []byte {
	section = strings.TrimSpace(section)
	if isMIMEPartSection(section) {
		return mimePartSectionData(section, data)
	}
	separator, separatorSize := bytesIndex(data, []byte("\r\n\r\n"))
	if separator < 0 {
		separator, separatorSize = bytesIndex(data, []byte("\n\n"))
	}
	header := data
	text := []byte(nil)
	lineEnding := []byte("\r\n")
	if separator >= 0 {
		header = data[:separator]
		text = data[separator+separatorSize:]
		if separatorSize == 2 {
			lineEnding = []byte("\n")
		}
	}
	headerWithEnding := append(append([]byte(nil), header...), lineEnding...)
	switch strings.ToUpper(section) {
	case "", "TEXT":
		if strings.EqualFold(section, "TEXT") {
			return text
		}
		return data
	case "HEADER", "RFC822.HEADER":
		return headerWithEnding
	}
	upper := strings.ToUpper(strings.TrimSpace(section))
	if strings.HasPrefix(upper, "HEADER.FIELDS") {
		open := strings.IndexByte(section, '(')
		closeIdx := strings.LastIndexByte(section, ')')
		if open >= 0 && closeIdx > open {
			fields := make(map[string]bool)
			for _, field := range strings.Fields(section[open+1 : closeIdx]) {
				fields[strings.ToUpper(field)] = true
			}
			return selectedHeaderFields(headerWithEnding, lineEnding, fields, strings.HasPrefix(upper, "HEADER.FIELDS.NOT"))
		}
	}
	return data
}

func isMIMEPartSection(section string) bool {
	parts := strings.Split(section, ".")
	if len(parts) == 0 {
		return false
	}
	_, err := strconv.Atoi(parts[0])
	return err == nil
}

func mimePartSectionData(section string, data []byte) []byte {
	parts := strings.Split(section, ".")
	entity, err := rootMIMEEntity(data)
	if err != nil {
		return data
	}
	index := 0
	for index < len(parts) {
		partNumber, parseErr := strconv.Atoi(parts[index])
		if parseErr != nil || partNumber < 1 {
			break
		}
		children := multipartEntitiesForSection(entity)
		if len(children) == 0 && index == 0 && partNumber == 1 && !isMultipartMIMEEntity(entity) {
			index++
			continue
		}
		if partNumber > len(children) {
			return data
		}
		entity = children[partNumber-1]
		index++
	}
	if index == 0 {
		return data
	}
	if index == len(parts) || strings.EqualFold(strings.Join(parts[index:], "."), "TEXT") {
		return entity.body
	}
	selector := strings.ToUpper(strings.Join(parts[index:], "."))
	header := mimeEntityHeaderBytes(entity.header)
	if selector == "HEADER" || selector == "MIME" {
		return header
	}
	if strings.HasPrefix(selector, "HEADER.FIELDS") {
		open := strings.IndexByte(selector, '(')
		closeIdx := strings.LastIndexByte(selector, ')')
		if open >= 0 && closeIdx > open {
			fields := make(map[string]bool)
			for _, field := range strings.Fields(selector[open+1 : closeIdx]) {
				fields[field] = true
			}
			return selectedHeaderFields(header, []byte("\r\n"), fields, strings.HasPrefix(selector, "HEADER.FIELDS.NOT"))
		}
	}
	return entity.body
}

func multipartEntitiesForSection(entity mimeEntity) []mimeEntity {
	mediaType, params, err := mime.ParseMediaType(entity.header.Get("Content-Type"))
	if err != nil || !strings.HasPrefix(strings.ToLower(mediaType), "multipart/") {
		return nil
	}
	return multipartEntities(entity, params["boundary"])
}

func isMultipartMIMEEntity(entity mimeEntity) bool {
	mediaType, _, err := mime.ParseMediaType(entity.header.Get("Content-Type"))
	return err == nil && strings.HasPrefix(strings.ToLower(mediaType), "multipart/")
}

func mimeEntityHeaderBytes(header textproto.MIMEHeader) []byte {
	keys := make([]string, 0, len(header))
	for key := range header {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]byte, 0)
	for _, key := range keys {
		for _, value := range header[key] {
			result = append(result, key+": "+value+"\r\n"...)
		}
	}
	return result
}

func bytesIndex(data, separator []byte) (int, int) {
	index := strings.Index(string(data), string(separator))
	return index, len(separator)
}

func selectedHeaderFields(header, lineEnding []byte, fields map[string]bool, negate bool) []byte {
	var selected []byte
	lines := strings.Split(string(header), string(lineEnding))
	include := false
	for _, line := range lines {
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			if include {
				selected = append(selected, []byte(line)...)
				selected = append(selected, lineEnding...)
			}
			continue
		}
		name, _, ok := strings.Cut(line, ":")
		include = ok && (fields[strings.ToUpper(name)] != negate)
		if include {
			selected = append(selected, []byte(line)...)
			selected = append(selected, lineEnding...)
		}
	}
	return selected
}

func (s *Server) storeFlags(tag string, args []string, state *session, write func(string, ...any) error, uid bool) {
	if len(args) < 3 || state.readonly {
		_ = write("%s NO mailbox is read-only or STORE arguments are incomplete", tag)
		return
	}
	messages, err := s.Store.List(state.mailbox)
	if err != nil {
		_ = write("%s NO mailbox unavailable", tag)
		return
	}
	s.refreshRecent(state, messages)
	var added bool
	messages, added = sequenceMessages(state, messages)
	if added {
		if err := write("* %d EXISTS", len(messages)); err != nil {
			return
		}
	}
	operation := strings.ToUpper(args[1])
	silent := strings.HasSuffix(operation, ".SILENT")
	operation = strings.TrimSuffix(operation, ".SILENT")
	values := strings.Fields(strings.Trim(strings.Join(args[2:], " "), "()"))
	numbers := sequenceNumbers(args[0], len(messages))
	if uid {
		numbers = uidMessageNumbers(args[0], messages)
	}
	for _, number := range numbers {
		if messages[number-1].UID == 0 {
			continue
		}
		flags := messages[number-1].Flags
		if operation == "FLAGS" {
			flags = make(map[byte]bool)
		}
		for _, value := range values {
			flag, ok := imapFlag(value)
			if !ok {
				continue
			}
			if strings.HasPrefix(operation, "-") {
				delete(flags, flag)
			} else {
				flags[flag] = true
			}
		}
		updated, updateErr := s.Store.SetFlags(state.mailbox, messages[number-1], flags)
		if updateErr == nil {
			messages[number-1] = updated
			if !silent {
				if uid {
					_ = write("* %d FETCH (UID %d FLAGS (%s))", number, updated.UID, formatFlags(updated.Flags))
				} else {
					_ = write("* %d FETCH (FLAGS (%s))", number, formatFlags(updated.Flags))
				}
			}
		}
	}
	_ = write("%s OK STORE completed", tag)
}

func (s *Server) search(tag string, args []string, state *session, write func(string, ...any) error, uid bool) {
	messages, err := s.Store.List(state.mailbox)
	if err != nil {
		_ = write("%s NO mailbox unavailable", tag)
		return
	}
	s.refreshRecent(state, messages)
	var added bool
	messages, added = sequenceMessages(state, messages)
	if added {
		if err := write("* %d EXISTS", len(messages)); err != nil {
			return
		}
	}
	criteriaArgs := args
	var uidSet map[uint32]bool
	if uid {
		criteriaArgs = nil
		for index := 0; index < len(args); index++ {
			if strings.EqualFold(args[index], "UID") && index+1 < len(args) {
				uidSet = make(map[uint32]bool)
				for _, number := range uidMessageNumbers(args[index+1], messages) {
					uidSet[messages[number-1].UID] = true
				}
				index++
				continue
			}
			criteriaArgs = append(criteriaArgs, args[index])
		}
	}
	criteria := strings.ToUpper(strings.Join(criteriaArgs, " "))
	var result []string
	for index, message := range messages {
		if message.UID == 0 {
			continue
		}
		include := criteria == "" || criteria == "ALL"
		if uidSet != nil {
			include = uidSet[message.UID]
		}
		if strings.Contains(criteria, "UNSEEN") {
			include = include && !message.Flags['S']
		}
		if strings.Contains(criteria, "SEEN") && !strings.Contains(criteria, "UNSEEN") {
			include = include && message.Flags['S']
		}
		if strings.Contains(criteria, "DELETED") {
			include = include && message.Flags['D']
		}
		if include {
			if uid {
				result = append(result, strconv.FormatUint(uint64(message.UID), 10))
			} else {
				result = append(result, strconv.Itoa(index+1))
			}
		}
	}
	if write("* SEARCH %s", strings.Join(result, " ")) != nil || write("%s OK SEARCH completed", tag) != nil {
		return
	}
}

func (s *Server) copy(tag string, args []string, state *session, write func(string, ...any) error, uid bool) {
	if len(args) != 2 {
		_ = write("%s BAD COPY requires a sequence set and destination mailbox", tag)
		return
	}
	destinationMailbox := state.mailbox
	if !(state.rootMailbox == "" && strings.EqualFold(args[1], "INBOX")) {
		var ok bool
		destinationMailbox, ok = resolveMailbox(state.rootMailbox, args[1])
		if !ok {
			_ = write("%s NO invalid destination mailbox", tag)
			return
		}
	}
	messages, err := s.Store.List(state.mailbox)
	if err != nil {
		_ = write("%s NO mailbox unavailable", tag)
		return
	}
	s.refreshRecent(state, messages)
	var added bool
	messages, added = sequenceMessages(state, messages)
	if added {
		if err := write("* %d EXISTS", len(messages)); err != nil {
			return
		}
	}
	selected := sequenceNumbers(args[0], len(messages))
	if uid {
		selected = uidMessageNumbers(args[0], messages)
	}
	var source []int
	for _, number := range selected {
		if messages[number-1].UID == 0 {
			continue
		}
		if uid {
			source = append(source, int(messages[number-1].UID))
		} else {
			source = append(source, number)
		}
	}
	var destination []int
	for _, number := range selected {
		if messages[number-1].UID == 0 {
			continue
		}
		data, readErr := s.Store.Read(messages[number-1])
		if readErr != nil {
			_ = write("%s NO cannot read message", tag)
			return
		}
		copied, deliverErr := s.Store.Deliver(destinationMailbox, data)
		if deliverErr != nil {
			_ = write("%s NO cannot copy message", tag)
			return
		}
		if len(messages[number-1].Flags) > 0 {
			if copied, deliverErr = s.Store.SetFlags(destinationMailbox, copied, messages[number-1].Flags); deliverErr != nil {
				_ = write("%s NO cannot copy message flags", tag)
				return
			}
		}
		updated, listErr := s.Store.List(destinationMailbox)
		if listErr != nil {
			_ = write("%s NO cannot locate copied message", tag)
			return
		}
		for index, message := range updated {
			if message.Filename == copied.Filename {
				if uid {
					destination = append(destination, int(message.UID))
				} else {
					destination = append(destination, index+1)
				}
				break
			}
		}
	}
	if destinationMailbox == state.mailbox {
		updated, listErr := s.Store.List(state.mailbox)
		if listErr != nil {
			_ = write("%s NO cannot refresh copied mailbox", tag)
			return
		}
		if _, syncErr, _ := syncSequenceAndNotify(state, updated, write, true); syncErr != nil {
			return
		}
	}
	if uid && len(destination) > 0 {
		_ = write("%s OK [COPYUID 1 %s %s] COPY completed", tag, sequenceSet(source), sequenceSet(destination))
		return
	}
	_ = write("%s OK COPY completed", tag)
}

func sequenceSet(numbers []int) string {
	values := make([]string, len(numbers))
	for index, number := range numbers {
		values[index] = strconv.Itoa(number)
	}
	return strings.Join(values, ",")
}

func nextUID(messages []maildir.Message) uint32 {
	var highest uint32
	for _, message := range messages {
		if message.UID > highest {
			highest = message.UID
		}
	}
	if highest == ^uint32(0) {
		return highest
	}
	return highest + 1
}

func (s *Server) expunge(tag string, state *session, write func(string, ...any) error) {
	messages, err := s.Store.List(state.mailbox)
	if err != nil {
		_ = write("%s NO mailbox unavailable", tag)
		return
	}
	s.refreshRecent(state, messages)
	var syncErr error
	messages, syncErr, _ = syncSequenceAndNotify(state, messages, write, true)
	if syncErr != nil {
		return
	}
	for index := len(messages) - 1; index >= 0; index-- {
		if messages[index].Flags['D'] && s.Store.DeleteFrom(state.mailbox, messages[index]) == nil {
			if write("* %d EXPUNGE", index+1) != nil {
				return
			}
			removeSequenceUID(state, messages[index].UID)
		}
	}
	if messages, err = s.Store.List(state.mailbox); err == nil {
		if _, syncErr, _ := syncSequenceAndNotify(state, messages, write, true); syncErr != nil {
			return
		}
	}
	_ = write("%s OK EXPUNGE completed", tag)
}

func (s *Server) removeDeleted(state *session) error {
	messages, err := s.Store.List(state.mailbox)
	if err != nil {
		return err
	}
	for index := len(messages) - 1; index >= 0; index-- {
		if messages[index].Flags['D'] {
			if err := s.Store.DeleteFrom(state.mailbox, messages[index]); err != nil {
				if errors.Is(err, os.ErrNotExist) {
					continue
				}
				return err
			}
		}
	}
	return nil
}

func (s *Server) expungeUID(tag string, args []string, state *session, write func(string, ...any) error) {
	if len(args) != 1 {
		_ = write("%s BAD UID EXPUNGE requires a sequence set", tag)
		return
	}
	messages, err := s.Store.List(state.mailbox)
	if err != nil {
		_ = write("%s NO mailbox unavailable", tag)
		return
	}
	s.refreshRecent(state, messages)
	var syncErr error
	messages, syncErr, _ = syncSequenceAndNotify(state, messages, write, true)
	if syncErr != nil {
		return
	}
	selected := uidMessageNumbers(args[0], messages)
	for index := len(selected) - 1; index >= 0; index-- {
		number := selected[index]
		if messages[number-1].Flags['D'] && s.Store.DeleteFrom(state.mailbox, messages[number-1]) == nil {
			if write("* %d EXPUNGE", number) != nil {
				return
			}
			removeSequenceUID(state, messages[number-1].UID)
		}
	}
	if messages, err = s.Store.List(state.mailbox); err == nil {
		if _, syncErr, _ := syncSequenceAndNotify(state, messages, write, true); syncErr != nil {
			return
		}
	}
	_ = write("%s OK UID EXPUNGE completed", tag)
}

func countUnseen(messages []maildir.Message) int {
	count := 0
	for _, message := range messages {
		if !message.Flags['S'] {
			count++
		}
	}
	return count
}

func countRecent(messages []maildir.Message, recent ...map[uint32]bool) int {
	var claimed map[uint32]bool
	if len(recent) > 0 {
		claimed = recent[0]
	}
	count := 0
	for _, message := range messages {
		if messageIsRecent(message, claimed) {
			count++
		}
	}
	return count
}

func messageIsRecent(message maildir.Message, claimed map[uint32]bool) bool {
	if !message.Recent {
		return false
	}
	return claimed == nil || claimed[message.UID]
}

type idleMessage struct {
	sequence int
	message  maildir.Message
}

func idleMessagesByUID(messages []maildir.Message) map[uint32]idleMessage {
	result := make(map[uint32]idleMessage, len(messages))
	for sequence, message := range messages {
		result[message.UID] = idleMessage{sequence: sequence + 1, message: message}
	}
	return result
}

func writeIdleChanges(write func(string, ...any) error, previous map[uint32]idleMessage, messages []maildir.Message, recent ...map[uint32]bool) error {
	var claimed map[uint32]bool
	if len(recent) > 0 {
		claimed = recent[0]
	}
	current := idleMessagesByUID(messages)
	removed := make([]int, 0)
	for uid, old := range previous {
		if _, ok := current[uid]; !ok {
			removed = append(removed, old.sequence)
		}
	}
	sort.Ints(removed)
	for index := len(removed) - 1; index >= 0; index-- {
		if err := write("* %d EXPUNGE", removed[index]); err != nil {
			return err
		}
	}
	added := false
	for uid := range current {
		if _, ok := previous[uid]; !ok {
			added = true
			break
		}
	}
	if added || len(removed) > 0 {
		if err := write("* %d EXISTS", len(messages)); err != nil {
			return err
		}
		if err := write("* %d RECENT", countRecent(messages, claimed)); err != nil {
			return err
		}
	}
	for sequence, message := range messages {
		old, ok := previous[message.UID]
		if !ok || sameMessageFlags(old.message.Flags, message.Flags) {
			continue
		}
		if err := write("* %d FETCH (UID %d FLAGS (%s))", sequence+1, message.UID, formatMessageFlags(message, messageIsRecent(message, claimed))); err != nil {
			return err
		}
	}
	return nil
}

func sameMessageFlags(left, right map[byte]bool) bool {
	if len(left) != len(right) {
		return false
	}
	for flag, set := range left {
		if set != right[flag] {
			return false
		}
	}
	return true
}

func addFlag(flags map[byte]bool, flag byte, value bool) map[byte]bool {
	theCopy := make(map[byte]bool, len(flags)+1)
	for key, set := range flags {
		theCopy[key] = set
	}
	if value {
		theCopy[flag] = true
	} else {
		delete(theCopy, flag)
	}
	return theCopy
}

func formatFlags(flags map[byte]bool) string {
	var result []string
	for _, item := range []struct {
		maildir byte
		imap    string
	}{{'R', "\\Answered"}, {'S', "\\Seen"}, {'F', "\\Flagged"}, {'D', "\\Deleted"}, {'T', "\\Draft"}} {
		if flags[item.maildir] {
			result = append(result, item.imap)
		}
	}
	return strings.Join(result, " ")
}

func formatMessageFlags(message maildir.Message, recent ...bool) string {
	flags := formatFlags(message.Flags)
	isRecent := message.Recent
	if len(recent) > 0 {
		isRecent = recent[0]
	}
	if isRecent {
		if flags != "" {
			flags += " "
		}
		flags += "\\Recent"
	}
	return flags
}

func imapFlag(value string) (byte, bool) {
	switch strings.ToUpper(strings.Trim(value, "()")) {
	case "\\SEEN":
		return 'S', true
	case "\\ANSWERED":
		return 'R', true
	case "\\FLAGGED":
		return 'F', true
	case "\\DELETED":
		return 'D', true
	case "\\DRAFT":
		return 'T', true
	default:
		return 0, false
	}
}

func sequenceNumbers(set string, count int) []int {
	seen := make(map[int]bool)
	for _, part := range strings.Split(set, ",") {
		bounds := strings.SplitN(part, ":", 2)
		start, end := parseSequenceNumber(bounds[0], count)
		if len(bounds) == 2 {
			_, end = parseSequenceNumber(bounds[1], count)
		}
		if start > end {
			start, end = end, start
		}
		for number := start; number <= end; number++ {
			if number >= 1 && number <= count && !seen[number] {
				seen[number] = true
			}
		}
	}
	result := make([]int, 0, len(seen))
	for number := 1; number <= count; number++ {
		if seen[number] {
			result = append(result, number)
		}
	}
	return result
}

func uidMessageNumbers(set string, messages []maildir.Message) []int {
	if len(messages) == 0 {
		return nil
	}
	var highest uint32
	for _, message := range messages {
		if message.UID > highest {
			highest = message.UID
		}
	}
	var result []int
	for index, message := range messages {
		if uidInSet(message.UID, set, highest) {
			result = append(result, index+1)
		}
	}
	return result
}

func uidInSet(uid uint32, set string, highest uint32) bool {
	for _, part := range strings.Split(set, ",") {
		bounds := strings.SplitN(strings.TrimSpace(part), ":", 2)
		start, ok := parseUIDBound(bounds[0], highest)
		if !ok {
			continue
		}
		end := start
		if len(bounds) == 2 {
			end, ok = parseUIDBound(bounds[1], highest)
			if !ok {
				continue
			}
		}
		if start > end {
			start, end = end, start
		}
		if uid >= start && uid <= end {
			return true
		}
	}
	return false
}

func parseUIDBound(value string, highest uint32) (uint32, bool) {
	if value == "*" {
		return highest, highest != 0
	}
	number, err := strconv.ParseUint(value, 10, 32)
	return uint32(number), err == nil && number > 0
}

func parseSequenceNumber(value string, count int) (int, int) {
	if value == "*" {
		return count, count
	}
	number, err := strconv.Atoi(value)
	if err != nil {
		return 0, 0
	}
	return number, number
}

func parseLiteral(value string) (int, bool, bool) {
	if len(value) < 3 || value[0] != '{' || value[len(value)-1] != '}' {
		return 0, false, false
	}
	literal := value[1 : len(value)-1]
	nonSynchronizing := strings.HasSuffix(literal, "+")
	sizeText := strings.TrimSuffix(literal, "+")
	if sizeText == "" {
		return 0, false, false
	}
	size, err := strconv.Atoi(sizeText)
	return size, nonSynchronizing, err == nil && size >= 0
}

func quoteIMAPString(value string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(value) + `"`
}

func tokenize(line string) []string {
	var result []string
	for len(line) > 0 {
		line = strings.TrimLeft(line, " \t")
		if line == "" {
			break
		}
		if line[0] == '"' {
			line = line[1:]
			if end := strings.IndexByte(line, '"'); end >= 0 {
				result = append(result, line[:end])
				line = line[end+1:]
			} else {
				result = append(result, line)
				break
			}
		} else {
			end := strings.IndexAny(line, " \t")
			if end < 0 {
				result = append(result, line)
				break
			}
			result = append(result, line[:end])
			line = line[end:]
		}
	}
	return result
}
