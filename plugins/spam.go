package plugins

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"strconv"
	"strings"
	"time"
)

const (
	defaultSpamdAddress    = "127.0.0.1:783"
	defaultSpamdTimeout    = 30 * time.Second
	defaultSpamdMessageMax = 10 << 20
	maxSpamdResponseSize   = 50 << 20
	maxSpamdHeaderLine     = 64 << 10
)

// SpamdClient sends messages to a SpamAssassin spamd daemon using the native
// SPAMC protocol. The PROCESS command is used so spamd can return the message
// with its X-Spam-* headers added.
//
// A client is safe for concurrent calls to Process. Initialize should be
// called before the client is used by a processor chain.
type SpamdClient struct {
	address        string
	user           string
	timeout        time.Duration
	maxMessageSize int64
}

// NewSpamdClient creates a client for a spamd TCP listener. An empty address
// uses spamd's conventional loopback address, 127.0.0.1:783.
func NewSpamdClient(address string) *SpamdClient {
	address = strings.TrimSpace(address)
	if address == "" {
		address = defaultSpamdAddress
	}
	return &SpamdClient{
		address:        address,
		timeout:        defaultSpamdTimeout,
		maxMessageSize: defaultSpamdMessageMax,
	}
}

// Name returns the processor name used in configuration and logs.
func (c *SpamdClient) Name() string { return "spamd" }

// Initialize applies optional settings. Supported settings are address, user,
// timeout, and max_message_size. Duration values use Go duration syntax and
// max_message_size is a positive byte count.
func (c *SpamdClient) Initialize(ctx context.Context, settings map[string]string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if c == nil {
		return errors.New("nil spamd client")
	}
	if address := strings.TrimSpace(settings["address"]); address != "" {
		c.address = address
	}
	if user, ok := settings["user"]; ok {
		user = strings.TrimSpace(user)
		if strings.ContainsAny(user, "\r\n") {
			return errors.New("spamd user contains a newline")
		}
		c.user = user
	}
	if value := strings.TrimSpace(settings["timeout"]); value != "" {
		timeout, err := time.ParseDuration(value)
		if err != nil || timeout <= 0 {
			return fmt.Errorf("invalid spamd timeout %q", value)
		}
		c.timeout = timeout
	}
	if value := strings.TrimSpace(settings["max_message_size"]); value != "" {
		maxMessageSize, err := strconv.ParseInt(value, 10, 64)
		if err != nil || maxMessageSize <= 0 {
			return fmt.Errorf("invalid spamd max_message_size %q", value)
		}
		c.maxMessageSize = maxMessageSize
	}
	return nil
}

// Process asks spamd to process message.Data. For training messages (indicated
// by 'spam-' or 'ham-' prefixes in recipient or message header addresses), the
// forwarded email(s) are sent to spamd to train as spam or ham, and the training
// output report email is placed in message.Data to be delivered to the inbox.
// For all other messages, spamd processes the message and adds X-Spam-* headers.
func (c *SpamdClient) Process(ctx context.Context, message *Message) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if c == nil {
		return Result{}, errors.New("nil spamd client")
	}
	if message == nil {
		return Result{}, errors.New("nil message")
	}
	if int64(len(message.Data)) > c.maxMessageSize {
		return Result{}, fmt.Errorf("message size %d exceeds spamd limit %d", len(message.Data), c.maxMessageSize)
	}
	user := message.Mailbox
	if user == "" {
		user = c.user
	}
	if strings.ContainsAny(user, "\r\n") {
		return Result{}, errors.New("spamd user contains a newline")
	}

	if trainClass, isTraining := detectTrainingClass(message); isTraining {
		emails := extractForwardedEmails(message.Data)
		reportItems := make([]trainingReportItem, 0, len(emails))
		var firstErr error
		for _, emailData := range emails {
			subj, fromHdr := extractSubjectAndFrom(emailData)
			res, err := c.trainMessage(ctx, emailData, trainClass, user)
			if err != nil && firstErr == nil {
				firstErr = err
			}
			reportItems = append(reportItems, trainingReportItem{
				subject: subj,
				from:    fromHdr,
				res:     res,
				err:     err,
			})
		}
		if firstErr != nil {
			return Result{}, firstErr
		}
		recipient := ""
		if len(message.Recipients) > 0 {
			recipient = message.Recipients[0]
		}
		message.Data = generateTrainingReport(trainClass, user, recipient, reportItems)
		message.Folder = ""
		return Result{Decision: Accept}, nil
	}

	connection, err := (&net.Dialer{Timeout: c.timeout}).DialContext(ctx, "tcp", c.address)
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return Result{}, contextErr
		}
		return Result{}, fmt.Errorf("connect to spamd: %w", err)
	}
	defer connection.Close()

	deadline := time.Now().Add(c.timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return Result{}, fmt.Errorf("set spamd deadline: %w", err)
	}
	connectionDone := make(chan struct{})
	defer close(connectionDone)
	go func() {
		select {
		case <-ctx.Done():
			_ = connection.Close()
		case <-connectionDone:
		}
	}()

	writer := bufio.NewWriterSize(connection, 64*1024)
	if _, err := fmt.Fprintf(writer, "PROCESS SPAMC/1.5\r\nContent-length: %d\r\n", len(message.Data)); err != nil {
		return Result{}, spamdConnectionError(ctx, "write spamd request", err)
	}
	if user != "" {
		if _, err := fmt.Fprintf(writer, "User: %s\r\n", user); err != nil {
			return Result{}, spamdConnectionError(ctx, "write spamd user", err)
		}
	}
	if _, err := writer.WriteString("\r\n"); err != nil {
		return Result{}, spamdConnectionError(ctx, "write spamd request separator", err)
	}
	if _, err := writer.Write(message.Data); err != nil {
		return Result{}, spamdConnectionError(ctx, "write spamd message", err)
	}
	if err := writer.Flush(); err != nil {
		return Result{}, spamdConnectionError(ctx, "flush spamd request", err)
	}

	response, err := readSpamdResponse(ctx, bufio.NewReaderSize(connection, 64*1024))
	if err != nil {
		return Result{}, err
	}
	message.Data = response
	return Result{Decision: Accept}, nil
}

type tellResult struct {
	statusLine string
	didSet     string
	didRemove  string
	spam       string
	body       string
}

type trainingReportItem struct {
	subject string
	from    string
	res     tellResult
	err     error
}

func (c *SpamdClient) trainMessage(ctx context.Context, emailData []byte, trainClass, user string) (tellResult, error) {
	if int64(len(emailData)) > c.maxMessageSize {
		return tellResult{}, fmt.Errorf("message size %d exceeds spamd limit %d", len(emailData), c.maxMessageSize)
	}
	connection, err := (&net.Dialer{Timeout: c.timeout}).DialContext(ctx, "tcp", c.address)
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return tellResult{}, contextErr
		}
		return tellResult{}, fmt.Errorf("connect to spamd: %w", err)
	}
	defer connection.Close()

	deadline := time.Now().Add(c.timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return tellResult{}, fmt.Errorf("set spamd deadline: %w", err)
	}
	connectionDone := make(chan struct{})
	defer close(connectionDone)
	go func() {
		select {
		case <-ctx.Done():
			_ = connection.Close()
		case <-connectionDone:
		}
	}()

	writer := bufio.NewWriterSize(connection, 64*1024)
	if _, err := fmt.Fprintf(writer, "TELL SPAMC/1.5\r\nMessage-class: %s\r\nSet: local\r\nContent-length: %d\r\n", trainClass, len(emailData)); err != nil {
		return tellResult{}, spamdConnectionError(ctx, "write spamd request", err)
	}
	if user != "" {
		if _, err := fmt.Fprintf(writer, "User: %s\r\n", user); err != nil {
			return tellResult{}, spamdConnectionError(ctx, "write spamd user", err)
		}
	}
	if _, err := writer.WriteString("\r\n"); err != nil {
		return tellResult{}, spamdConnectionError(ctx, "write spamd request separator", err)
	}
	if _, err := writer.Write(emailData); err != nil {
		return tellResult{}, spamdConnectionError(ctx, "write spamd message", err)
	}
	if err := writer.Flush(); err != nil {
		return tellResult{}, spamdConnectionError(ctx, "flush spamd request", err)
	}

	return readSpamdTellResponse(ctx, bufio.NewReaderSize(connection, 64*1024))
}

func readSpamdTellResponse(ctx context.Context, reader *bufio.Reader) (tellResult, error) {
	statusLine, err := readSpamdLine(reader)
	if err != nil {
		return tellResult{}, spamdConnectionError(ctx, "read spamd status", err)
	}
	statusFields := strings.SplitN(statusLine, " ", 3)
	if len(statusFields) < 2 || !isSpamdResponseVersion(statusFields[0]) {
		return tellResult{}, fmt.Errorf("invalid spamd status line %q", statusLine)
	}
	status, err := strconv.Atoi(statusFields[1])
	if err != nil {
		return tellResult{}, fmt.Errorf("invalid spamd status code %q", statusFields[1])
	}
	if status != 0 {
		detail := ""
		if len(statusFields) == 3 {
			detail = ": " + statusFields[2]
		}
		return tellResult{}, fmt.Errorf("spamd returned status %d%s", status, detail)
	}

	res := tellResult{statusLine: statusLine}
	contentLength := int64(0)
	for {
		line, readErr := readSpamdLine(reader)
		if readErr != nil {
			return tellResult{}, spamdConnectionError(ctx, "read spamd headers", readErr)
		}
		if line == "" {
			break
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			return tellResult{}, fmt.Errorf("malformed spamd response header %q", line)
		}
		valTrimmed := strings.TrimSpace(value)
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "content-length":
			contentLength, err = strconv.ParseInt(valTrimmed, 10, 64)
			if err != nil || contentLength < 0 {
				return tellResult{}, fmt.Errorf("invalid spamd content length %q", valTrimmed)
			}
		case "didset":
			res.didSet = valTrimmed
		case "didremove":
			res.didRemove = valTrimmed
		case "spam":
			res.spam = valTrimmed
		}
	}

	if contentLength > 0 {
		if contentLength > maxSpamdResponseSize {
			return tellResult{}, fmt.Errorf("spamd response size %d exceeds limit %d", contentLength, maxSpamdResponseSize)
		}
		body := make([]byte, int(contentLength))
		if _, err := io.ReadFull(reader, body); err != nil {
			return tellResult{}, spamdConnectionError(ctx, "read spamd message", err)
		}
		res.body = string(body)
	}
	return res, nil
}

func detectTrainingClass(message *Message) (string, bool) {
	for _, recipient := range message.Recipients {
		if class, ok := checkAddressForPrefix(recipient); ok {
			return class, true
		}
	}
	if class, ok := checkAddressForPrefix(message.From); ok {
		return class, true
	}
	if msg, err := mail.ReadMessage(bytes.NewReader(message.Data)); err == nil {
		for _, key := range []string{"To", "From", "Cc", "Resent-To", "Resent-From"} {
			val := msg.Header.Get(key)
			if val == "" {
				continue
			}
			if addrs, err := mail.ParseAddressList(val); err == nil {
				for _, addr := range addrs {
					if class, ok := checkAddressForPrefix(addr.Address); ok {
						return class, true
					}
				}
			} else if class, ok := checkAddressForPrefix(val); ok {
				return class, true
			}
		}
	}
	return "", false
}

func checkAddressForPrefix(address string) (string, bool) {
	address = strings.TrimSpace(address)
	if address == "" {
		return "", false
	}
	if parsed, err := mail.ParseAddress(address); err == nil {
		address = parsed.Address
	}
	localPart, _, _ := strings.Cut(address, "@")
	localPart = strings.ToLower(strings.TrimSpace(localPart))
	if strings.HasPrefix(localPart, "spam-") {
		return "spam", true
	}
	if strings.HasPrefix(localPart, "ham-") {
		return "ham", true
	}
	return "", false
}

func extractForwardedEmails(data []byte) [][]byte {
	msg, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		return [][]byte{data}
	}
	contentType := msg.Header.Get("Content-Type")
	if contentType == "" {
		return [][]byte{data}
	}
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return [][]byte{data}
	}
	if strings.HasPrefix(mediaType, "multipart/") {
		boundary := params["boundary"]
		if boundary != "" {
			emails := extractFromMultipart(msg.Body, boundary)
			if len(emails) > 0 {
				return emails
			}
		}
	} else if strings.EqualFold(mediaType, "message/rfc822") {
		body, err := io.ReadAll(msg.Body)
		if err == nil && len(bytes.TrimSpace(body)) > 0 {
			return [][]byte{body}
		}
	}
	return [][]byte{data}
}

func extractFromMultipart(r io.Reader, boundary string) [][]byte {
	mr := multipart.NewReader(r, boundary)
	var emails [][]byte
	for {
		part, err := mr.NextPart()
		if err != nil {
			break
		}
		partType := part.Header.Get("Content-Type")
		mediaType, params, _ := mime.ParseMediaType(partType)
		if strings.HasPrefix(mediaType, "multipart/") {
			subBoundary := params["boundary"]
			if subBoundary != "" {
				subEmails := extractFromMultipart(part, subBoundary)
				emails = append(emails, subEmails...)
			}
		} else if strings.EqualFold(mediaType, "message/rfc822") {
			decoded, err := decodePart(part)
			if err == nil && len(bytes.TrimSpace(decoded)) > 0 {
				emails = append(emails, decoded)
			}
		}
	}
	return emails
}

func decodePart(part *multipart.Part) ([]byte, error) {
	encoding := strings.ToLower(strings.TrimSpace(part.Header.Get("Content-Transfer-Encoding")))
	var r io.Reader = part
	switch encoding {
	case "base64":
		r = base64.NewDecoder(base64.StdEncoding, part)
	case "quoted-printable":
		r = quotedprintable.NewReader(part)
	}
	return io.ReadAll(r)
}

func extractSubjectAndFrom(data []byte) (string, string) {
	msg, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		return "", ""
	}
	return msg.Header.Get("Subject"), msg.Header.Get("From")
}

func generateTrainingReport(trainClass, user, recipient string, results []trainingReportItem) []byte {
	var buf bytes.Buffer
	dateStr := time.Now().UTC().Format(time.RFC1123Z)
	idBytes := make([]byte, 8)
	_, _ = rand.Read(idBytes)
	msgID := fmt.Sprintf("<%d.%x@mymail.spamd>", time.Now().UnixNano(), idBytes)

	fromHeader := "SpamAssassin <spamd@localhost>"
	toHeader := recipient
	if toHeader == "" {
		if user != "" {
			toHeader = user
		} else {
			toHeader = "postmaster@localhost"
		}
	}

	subject := fmt.Sprintf("SpamAssassin training output: %s", strings.ToUpper(trainClass))
	fmt.Fprintf(&buf, "From: %s\r\n", fromHeader)
	fmt.Fprintf(&buf, "To: %s\r\n", toHeader)
	fmt.Fprintf(&buf, "Date: %s\r\n", dateStr)
	fmt.Fprintf(&buf, "Subject: %s\r\n", subject)
	fmt.Fprintf(&buf, "Message-ID: %s\r\n", msgID)
	fmt.Fprintf(&buf, "Content-Type: text/plain; charset=utf-8\r\n")
	fmt.Fprintf(&buf, "\r\n")

	fmt.Fprintf(&buf, "SpamAssassin %s training report\r\n\r\n", strings.ToUpper(trainClass))
	if user != "" {
		fmt.Fprintf(&buf, "Account/Mailbox: %s\r\n", user)
	}
	fmt.Fprintf(&buf, "Trained message count: %d\r\n\r\n", len(results))

	for i, item := range results {
		fmt.Fprintf(&buf, "--- Message #%d ---\r\n", i+1)
		if item.subject != "" {
			fmt.Fprintf(&buf, "Subject: %s\r\n", item.subject)
		}
		if item.from != "" {
			fmt.Fprintf(&buf, "From: %s\r\n", item.from)
		}
		if item.err != nil {
			fmt.Fprintf(&buf, "Result: Failed - %v\r\n", item.err)
		} else {
			fmt.Fprintf(&buf, "Status: %s\r\n", item.res.statusLine)
			if item.res.didSet != "" {
				fmt.Fprintf(&buf, "DidSet: %s\r\n", item.res.didSet)
			}
			if item.res.didRemove != "" {
				fmt.Fprintf(&buf, "DidRemove: %s\r\n", item.res.didRemove)
			}
			if item.res.spam != "" {
				fmt.Fprintf(&buf, "Spam: %s\r\n", item.res.spam)
			}
			if item.res.body != "" {
				fmt.Fprintf(&buf, "Details: %s\r\n", strings.TrimSpace(item.res.body))
			}
		}
		fmt.Fprintf(&buf, "\r\n")
	}
	return buf.Bytes()
}

func readSpamdResponse(ctx context.Context, reader *bufio.Reader) ([]byte, error) {
	statusLine, err := readSpamdLine(reader)
	if err != nil {
		return nil, spamdConnectionError(ctx, "read spamd status", err)
	}
	statusFields := strings.SplitN(statusLine, " ", 3)
	if len(statusFields) < 2 || !isSpamdResponseVersion(statusFields[0]) {
		return nil, fmt.Errorf("invalid spamd status line %q", statusLine)
	}
	status, err := strconv.Atoi(statusFields[1])
	if err != nil {
		return nil, fmt.Errorf("invalid spamd status code %q", statusFields[1])
	}
	if status != 0 {
		detail := ""
		if len(statusFields) == 3 {
			detail = ": " + statusFields[2]
		}
		return nil, fmt.Errorf("spamd returned status %d%s", status, detail)
	}

	contentLength := int64(-1)
	for {
		line, readErr := readSpamdLine(reader)
		if readErr != nil {
			return nil, spamdConnectionError(ctx, "read spamd headers", readErr)
		}
		if line == "" {
			break
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			return nil, fmt.Errorf("malformed spamd response header %q", line)
		}
		if strings.EqualFold(strings.TrimSpace(name), "content-length") {
			contentLength, err = strconv.ParseInt(strings.TrimSpace(value), 10, 64)
			if err != nil || contentLength < 0 {
				return nil, fmt.Errorf("invalid spamd content length %q", strings.TrimSpace(value))
			}
		}
	}
	if contentLength < 0 {
		return nil, errors.New("spamd response has no content length")
	}
	if contentLength > maxSpamdResponseSize {
		return nil, fmt.Errorf("spamd response size %d exceeds limit %d", contentLength, maxSpamdResponseSize)
	}
	body := make([]byte, int(contentLength))
	if _, err := io.ReadFull(reader, body); err != nil {
		return nil, spamdConnectionError(ctx, "read spamd message", err)
	}
	return body, nil
}

func isSpamdResponseVersion(value string) bool {
	version, ok := strings.CutPrefix(value, "SPAMD/")
	if !ok {
		return false
	}
	major, minor, ok := strings.Cut(version, ".")
	if !ok || major != "1" || minor == "" {
		return false
	}
	for _, digit := range minor {
		if digit < '0' || digit > '9' {
			return false
		}
	}
	return true
}

func readSpamdLine(reader *bufio.Reader) (string, error) {
	var line []byte
	for {
		fragment, isPrefix, err := reader.ReadLine()
		if err != nil {
			return "", err
		}
		if len(line)+len(fragment) > maxSpamdHeaderLine {
			return "", fmt.Errorf("spamd header line exceeds %d bytes", maxSpamdHeaderLine)
		}
		line = append(line, fragment...)
		if !isPrefix {
			return string(line), nil
		}
	}
}

func spamdConnectionError(ctx context.Context, operation string, err error) error {
	if contextErr := ctx.Err(); contextErr != nil {
		return contextErr
	}
	return fmt.Errorf("%s: %w", operation, err)
}
