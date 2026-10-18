// Package imap implements the IMAP4rev1 service used to access Maildir.
package imap

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
	authenticated bool
	username      string
	rootMailbox   string
	mailbox       string
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
			capability := "IMAP4rev1 AUTH=PLAIN AUTH=LOGIN NAMESPACE ID IDLE APPEND UIDPLUS"
			if s.TLSConfig != nil {
				capability += " STARTTLS"
			}
			if _, err := fmt.Fprintf(writer, "* CAPABILITY %s\r\n%s OK CAPABILITY completed\r\n", capability, tag); err != nil || writer.Flush() != nil {
				return
			}
		case "NOOP":
			if state.selected {
				messages, _ := s.Store.List(state.mailbox)
				if write("* %d EXISTS", len(messages)) != nil {
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
			for index, stored := range messages {
				if stored.Filename == message.Filename {
					uid = index + 1
					break
				}
			}
			if uid == 0 {
				_ = write("%s NO cannot locate appended message", tag)
				continue
			}
			if state.selected && state.mailbox == mailbox {
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
			if err := write("+ idling"); err != nil {
				return
			}
			for {
				idleLine, idleErr := reader.ReadString('\n')
				if idleErr != nil {
					return
				}
				if strings.EqualFold(strings.TrimSpace(idleLine), "DONE") {
					if err := write("%s OK IDLE terminated", tag); err != nil {
						return
					}
					break
				}
			}
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
			if write("* %d EXISTS", len(messages)) != nil || write("* 0 RECENT") != nil || write("* OK [UIDVALIDITY 1] mailbox selected") != nil || write("* OK [UIDNEXT %d] next uid", len(messages)+1) != nil || write("%s OK [%s] %s completed", tag, map[bool]string{true: "READ-ONLY", false: "READ-WRITE"}[state.readonly], command) != nil {
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
			if write("* STATUS %s (MESSAGES %d RECENT 0 UNSEEN %d UIDNEXT %d UIDVALIDITY 1)", args[0], len(messages), unseen, len(messages)+1) != nil || write("%s OK STATUS completed", tag) != nil {
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
				s.search(tag, args[1:], &state, write)
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
			s.search(tag, args, &state, write)
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
		case "DELETE", "RENAME":
			if !state.authenticated {
				_ = write("%s NO authenticate first", tag)
				continue
			}
			_ = write("%s NO only mailbox creation is supported", tag)
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
		_ = write("%s OK [CAPABILITY IMAP4rev1] LOGIN completed", tag)
	} else {
		_ = write("%s OK AUTHENTICATE completed", tag)
	}
	return true
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
	if len(name) > len("INBOX.") && strings.EqualFold(name[:len("INBOX.")], "INBOX.") {
		name = name[len("INBOX."):]
	}
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\`) || strings.Contains(name, "\x00") {
		return "", false
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
	names := append([]string{"INBOX"}, folders...)
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
	bodyRequested := strings.Contains(requested, "BODY[") || strings.Contains(requested, "BODY.PEEK[")
	for _, number := range sequenceNumbers(args[0], len(messages)) {
		message := messages[number-1]
		if bodyRequested && !strings.Contains(requested, "BODY.PEEK[") && !message.Flags['S'] && !state.readonly {
			if updated, updateErr := s.Store.SetFlags(state.mailbox, message, addFlag(message.Flags, 'S', true)); updateErr == nil {
				message = updated
				messages[number-1] = updated
			}
		}
		flags := formatFlags(message.Flags)
		if bodyRequested {
			data, readErr := s.Store.Read(message)
			if readErr != nil {
				continue
			}
			fmt.Fprintf(writer, "* %d FETCH (", number)
			if includeUID {
				fmt.Fprintf(writer, "UID %d ", number)
			}
			fmt.Fprintf(writer, "FLAGS (%s) RFC822.SIZE %d BODY[] {%d}\r\n", flags, len(data), len(data))
			_, _ = writer.Write(data)
			fmt.Fprint(writer, ")\r\n")
		} else {
			fmt.Fprintf(writer, "* %d FETCH (", number)
			if includeUID {
				fmt.Fprintf(writer, "UID %d ", number)
			}
			fmt.Fprintf(writer, "FLAGS (%s) RFC822.SIZE %d INTERNALDATE \"%s\")\r\n", flags, message.Size, message.InternalDate.UTC().Format("02-Jan-2006 15:04:05 -0700"))
		}
	}
	fmt.Fprintf(writer, "%s OK FETCH completed\r\n", tag)
	_ = writer.Flush()
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
	for _, number := range sequenceNumbers(args[0], len(messages)) {
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
					_ = write("* %d FETCH (UID %d FLAGS (%s))", number, number, formatFlags(updated.Flags))
				} else {
					_ = write("* %d FETCH (FLAGS (%s))", number, formatFlags(updated.Flags))
				}
			}
		}
	}
	_ = write("%s OK STORE completed", tag)
}

func (s *Server) search(tag string, args []string, state *session, write func(string, ...any) error) {
	messages, err := s.Store.List(state.mailbox)
	if err != nil {
		_ = write("%s NO mailbox unavailable", tag)
		return
	}
	criteria := strings.ToUpper(strings.Join(args, " "))
	var result []string
	for index, message := range messages {
		include := criteria == "" || criteria == "ALL"
		if strings.Contains(criteria, "UNSEEN") {
			include = !message.Flags['S']
		}
		if strings.Contains(criteria, "SEEN") && !strings.Contains(criteria, "UNSEEN") {
			include = message.Flags['S']
		}
		if strings.Contains(criteria, "DELETED") {
			include = message.Flags['D']
		}
		if include {
			result = append(result, strconv.Itoa(index+1))
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
				destination = append(destination, index+1)
				break
			}
		}
	}
	if uid && len(destination) > 0 {
		_ = write("%s OK [COPYUID 1 %s %s] COPY completed", tag, sequenceSet(selected), sequenceSet(destination))
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
	selected := sequenceNumbers(args[0], len(messages))
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

func addFlag(flags map[byte]bool, flag byte, value bool) map[byte]bool {
	copy := make(map[byte]bool, len(flags)+1)
	for key, set := range flags {
		copy[key] = set
	}
	if value {
		copy[flag] = true
	} else {
		delete(copy, flag)
	}
	return copy
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
