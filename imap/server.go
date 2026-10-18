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
	"net"
	netmail "net/mail"
	"sort"
	"strconv"
	"strings"
	"time"

	"mymail/maildir"
)

type Resolver func(username string) (mailbox string, ok bool)
type Authenticator func(username, password string) bool

var (
	errAuthenticationInvalid   = errors.New("invalid authentication response")
	errAuthenticationCancelled = errors.New("authentication cancelled")
)

type Server struct {
	Addr         string
	TLSConfig    *tls.Config
	Hostname     string
	Store        *maildir.Store
	Resolve      Resolver
	Authenticate Authenticator
	Logger       *slog.Logger
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

type session struct {
	username      string
	rootMailbox   string
	mailbox       string
	exists        int
	authenticated bool
	selected      bool
	readonly      bool
}

func (s *Server) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReaderSize(conn, 64*1024)
	writer := bufio.NewWriterSize(conn, 64*1024)
	write := func(format string, args ...any) error {
		if _, err := fmt.Fprintf(writer, format+"\r\n", args...); err != nil {
			return err
		}
		return writer.Flush()
	}
	if write("* OK %s MyMail IMAP4rev1 ready", s.Hostname) != nil {
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
			if _, err := fmt.Fprintf(writer, "* CAPABILITY %s\r\n%s OK CAPABILITY completed\r\n", s.capabilities(), tag); err != nil || writer.Flush() != nil {
				return
			}
		case "NOOP":
			if state.selected {
				messages, _ := s.Store.List(state.mailbox)
				state.exists = len(messages)
				if write("* %d EXISTS", len(messages)) != nil || write("* %d RECENT", countRecent(messages)) != nil {
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
			if !s.authenticateSession(tag, args[0], args[1], &state, write, "LOGIN") {
				continue
			}
		case "AUTHENTICATE":
			if len(args) < 1 || len(args) > 2 {
				_ = write("%s BAD AUTHENTICATE requires a mechanism", tag)
				continue
			}
			initial := ""
			if len(args) == 2 {
				initial = args[1]
			}
			username, password, authErr := readAuthentication(args[0], initial, reader, write)
			if authErr != nil {
				if errors.Is(authErr, errAuthenticationInvalid) || errors.Is(authErr, errAuthenticationCancelled) {
					message := "invalid credentials"
					if errors.Is(authErr, errAuthenticationCancelled) {
						message = "authentication cancelled"
					}
					_ = write("%s NO [AUTHENTICATIONFAILED] %s", tag, message)
					continue
				}
				return
			}
			if !s.authenticateSession(tag, username, password, &state, write, "AUTHENTICATE") {
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
				state.exists = len(messages)
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
			selectedMessageCount := state.exists
			knownMessagesByUID := idleMessagesByUID(knownMessages)
			if err := write("+ idling"); err != nil {
				return
			}
			if len(knownMessages) != selectedMessageCount {
				if err := write("* %d EXISTS", len(knownMessages)); err != nil || write("* %d RECENT", countRecent(knownMessages)) != nil {
					return
				}
				state.exists = len(knownMessages)
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
					if err := writeIdleChanges(write, knownMessagesByUID, messages); err != nil {
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
			state.exists = len(messages)
			if write("* %d EXISTS", len(messages)) != nil || write("* %d RECENT", countRecent(messages)) != nil || write("* OK [UIDVALIDITY 1] mailbox selected") != nil || write("* OK [UIDNEXT %d] next uid", nextUID(messages)) != nil || write("%s OK [%s] %s completed", tag, map[bool]string{true: "READ-ONLY", false: "READ-WRITE"}[state.readonly], command) != nil {
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
			if len(args) < 1 || !s.requireSelected(&state, tag, write) {
				_ = write("%s BAD UID requires a subcommand", tag)
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
			if state.authenticated {
				_ = write("%s BAD STARTTLS not permitted after authentication", tag)
				continue
			}
			if s.TLSConfig == nil {
				_ = write("%s NO TLS is not available", tag)
				continue
			}
			if err := write("%s OK Begin TLS negotiation now", tag); err != nil {
				return
			}
			tlsConn := tls.Server(conn, s.TLSConfig)
			if err := tlsConn.Handshake(); err != nil {
				return
			}
			conn = tlsConn
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

func (s *Server) authenticateSession(tag, username, password string, state *session, write func(string, ...any) error, command string) bool {
	if !s.Authenticate(username, password) {
		_ = write("%s NO [AUTHENTICATIONFAILED] invalid credentials", tag)
		return false
	}
	mailbox, ok := s.Resolve(username)
	if !ok || s.Store.Ensure(mailbox) != nil {
		_ = write("%s NO mailbox unavailable", tag)
		return false
	}
	state.authenticated = true
	state.username = username
	state.rootMailbox = mailbox
	state.mailbox = mailbox
	if command == "LOGIN" {
		_ = write("%s OK [CAPABILITY %s] LOGIN completed", tag, s.capabilities())
	} else {
		_ = write("%s OK [CAPABILITY %s] AUTHENTICATE completed", tag, s.capabilities())
	}
	return true
}

func (s *Server) capabilities() string {
	capability := "IMAP4rev1 AUTH=PLAIN AUTH=LOGIN NAMESPACE ID IDLE APPEND UIDPLUS"
	if s.TLSConfig != nil {
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
		bodySections := []fetchBodySection(nil)
		var data []byte
		if bodyRequested || structureRequested || envelopeRequested {
			data, readErr := s.Store.Read(message)
			if readErr != nil {
				continue
			}
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
		flags := formatMessageFlags(message)
		if bodyRequested || structureRequested || envelopeRequested {
			fmt.Fprintf(writer, "* %d FETCH (", number)
			if includeUID {
				fmt.Fprintf(writer, "UID %d ", message.UID)
			}
			fmt.Fprintf(writer, "FLAGS (%s)", flags)
			if strings.Contains(requested, "INTERNALDATE") {
				fmt.Fprintf(writer, " INTERNALDATE %s", quoteIMAPString(message.InternalDate.UTC().Format("02-Jan-2006 15:04:05 -0700")))
			}
			fmt.Fprintf(writer, " RFC822.SIZE %d", message.Size)
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
			fmt.Fprintf(writer, "FLAGS (%s) RFC822.SIZE %d INTERNALDATE \"%s\")\r\n", flags, message.Size, message.InternalDate.UTC().Format("02-Jan-2006 15:04:05 -0700"))
		}
	}
	fmt.Fprintf(writer, "%s OK FETCH completed\r\n", tag)
	_ = writer.Flush()
}

func fetchBodyStructure(data []byte) string {
	message, err := netmail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		return `("TEXT" "PLAIN" NIL NIL NIL "7BIT" 0 0 NIL NIL NIL)`
	}
	mediaType, params, err := mime.ParseMediaType(message.Header.Get("Content-Type"))
	if err != nil || mediaType == "" {
		mediaType = "text/plain"
		params = nil
	}
	typeName, subtype, ok := strings.Cut(strings.ToUpper(mediaType), "/")
	if !ok || typeName == "" || subtype == "" {
		typeName, subtype = "TEXT", "PLAIN"
	}
	parameters := "NIL"
	if charset := params["charset"]; charset != "" {
		parameters = fmt.Sprintf("(\"CHARSET\" %s)", quoteIMAPString(charset))
	}
	body, _ := io.ReadAll(message.Body)
	encoding := strings.ToUpper(strings.TrimSpace(message.Header.Get("Content-Transfer-Encoding")))
	if encoding == "" {
		encoding = "7BIT"
	}
	lines := bytes.Count(body, []byte{'\n'})
	if typeName != "TEXT" {
		lines = 0
	}
	return fmt.Sprintf("(%s %s %s NIL NIL %s %d %d NIL NIL NIL)", quoteIMAPString(typeName), quoteIMAPString(subtype), parameters, quoteIMAPString(encoding), len(body), lines)
}

func fetchEnvelope(data []byte) string {
	message, err := netmail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		return "(NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL)"
	}
	fields := []string{
		imapEnvelopeValue(message.Header.Get("Date")),
		imapEnvelopeValue(message.Header.Get("Subject")),
		envelopeAddresses(message.Header.Get("From")),
		envelopeAddresses(message.Header.Get("Sender")),
		envelopeAddresses(message.Header.Get("Reply-To")),
		envelopeAddresses(message.Header.Get("To")),
		envelopeAddresses(message.Header.Get("Cc")),
		envelopeAddresses(message.Header.Get("Bcc")),
		imapEnvelopeValue(message.Header.Get("In-Reply-To")),
		imapEnvelopeValue(message.Header.Get("Message-Id")),
	}
	return "(" + strings.Join(fields, " ") + ")"
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
	switch strings.ToUpper(strings.TrimSpace(section)) {
	case "", "1", "TEXT":
		if strings.EqualFold(strings.TrimSpace(section), "TEXT") {
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
	operation := strings.ToUpper(args[1])
	silent := strings.HasSuffix(operation, ".SILENT")
	operation = strings.TrimSuffix(operation, ".SILENT")
	values := strings.Fields(strings.Trim(strings.Join(args[2:], " "), "()"))
	numbers := sequenceNumbers(args[0], len(messages))
	if uid {
		numbers = uidMessageNumbers(args[0], messages)
	}
	for _, number := range numbers {
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
	selected := sequenceNumbers(args[0], len(messages))
	if uid {
		selected = uidMessageNumbers(args[0], messages)
	}
	source := make([]int, len(selected))
	for index, number := range selected {
		if uid {
			source[index] = int(messages[number-1].UID)
		} else {
			source[index] = number
		}
	}
	var destination []int
	for _, number := range selected {
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
	for index := len(messages) - 1; index >= 0; index-- {
		if messages[index].Flags['D'] && s.Store.DeleteFrom(state.mailbox, messages[index]) == nil {
			if write("* %d EXPUNGE", index+1) != nil {
				return
			}
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
	selected := uidMessageNumbers(args[0], messages)
	for index := len(selected) - 1; index >= 0; index-- {
		number := selected[index]
		if messages[number-1].Flags['D'] && s.Store.DeleteFrom(state.mailbox, messages[number-1]) == nil {
			if write("* %d EXPUNGE", number) != nil {
				return
			}
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

func countRecent(messages []maildir.Message) int {
	count := 0
	for _, message := range messages {
		if message.Recent {
			count++
		}
	}
	return count
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

func writeIdleChanges(write func(string, ...any) error, previous map[uint32]idleMessage, messages []maildir.Message) error {
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
		if err := write("* %d RECENT", countRecent(messages)); err != nil {
			return err
		}
	}
	for sequence, message := range messages {
		old, ok := previous[message.UID]
		if !ok || sameMessageFlags(old.message.Flags, message.Flags) {
			continue
		}
		if err := write("* %d FETCH (UID %d FLAGS (%s))", sequence+1, message.UID, formatMessageFlags(message)); err != nil {
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

func formatMessageFlags(message maildir.Message) string {
	flags := formatFlags(message.Flags)
	if message.Recent {
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
