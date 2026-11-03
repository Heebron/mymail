package plugins

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
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

// Process asks spamd to process message.Data and replaces it with the
// SpamAssassin response body, which includes the added spam headers.
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
	if c.user != "" {
		if _, err := fmt.Fprintf(writer, "User: %s\r\n", c.user); err != nil {
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
