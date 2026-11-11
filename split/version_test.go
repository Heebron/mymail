package split

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseHandshake(t *testing.T) {
	legacy := make([]byte, 4)
	binary.BigEndian.PutUint32(legacy, ProtocolMagic)

	versioned, err := parseHandshake(marshalHandshake("v2.2.0"))
	if err != nil {
		t.Fatalf("parseHandshake(versioned) error = %v", err)
	}
	if versioned.magic != ProtocolMagic || !versioned.hasVersion || versioned.version != "v2.2.0" {
		t.Fatalf("parseHandshake(versioned) = %+v", versioned)
	}
	if !versioned.matches("v2.2.0") || versioned.matches("v2.1.0") {
		t.Fatalf("versioned handshake matches() is wrong: %+v", versioned)
	}

	old, err := parseHandshake(legacy)
	if err != nil {
		t.Fatalf("parseHandshake(legacy) error = %v", err)
	}
	if old.hasVersion || old.matches("") || old.displayVersion() != UnknownPeerVersion {
		t.Fatalf("legacy handshake = %+v, display %q; want no version", old, old.displayVersion())
	}

	tooLong := marshalHandshake(strings.Repeat("v", maxHandshakeVersionLength+1))
	for name, payload := range map[string][]byte{
		"empty":            nil,
		"short magic":      legacy[:3],
		"truncated length": append(append([]byte{}, legacy...), 0, 0),
		"trailing data":    append(marshalHandshake("v2.2.0"), 'x'),
		"missing data":     marshalHandshake("v2.2.0")[:10],
		"too long":         tooLong,
	} {
		if _, err := parseHandshake(payload); err == nil {
			t.Errorf("parseHandshake(%s) succeeded, want an error", name)
		}
	}
}

func TestSplitHandshakeMatchingVersionsConnect(t *testing.T) {
	logs := &lockedTestBuffer{}
	logger := slog.New(slog.NewTextHandler(logs, nil))
	server, client := startConfiguredTestSplitPair(t, func(context.Context, SendRequest) error { return nil }, nil, nil, nil, func(server *Server) {
		server.Version = "v2.2.0"
	}, logger)
	if client.Version != server.Version {
		t.Fatalf("test pair versions differ: client %q, server %q", client.Version, server.Version)
	}
	waitForTestLog(t, logs, `msg="split handshake completed"`)
	got := waitForTestLog(t, logs, `msg="split client connected"`)
	if strings.Contains(got, "version mismatch") {
		t.Fatalf("matching versions logged a mismatch: %s", got)
	}
	if !strings.Contains(got, "version=v2.2.0") {
		t.Fatalf("connection logs do not include the version: %s", got)
	}
}

func TestSplitHandshakeVersionMismatchLoggedByBothSides(t *testing.T) {
	serverLogs := &lockedTestBuffer{}
	var connected atomic.Bool
	addr := startVersionTestServer(t, "v2.2.0", serverLogs, func() { connected.Store(true) })

	clientLogs := &lockedTestBuffer{}
	client := &Client{
		Addr:      addr,
		TLSConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
		Logger:    slog.New(slog.NewTextHandler(clientLogs, nil)),
		Version:   "v2.1.0",
	}
	ctx, cancel := context.WithCancel(context.Background())
	client.Start(ctx)
	t.Cleanup(func() {
		cancel()
		client.Wait()
	})

	clientLog := waitForTestLog(t, clientLogs, "split version mismatch, connection closed by remote")
	assertVersionMismatchLog(t, clientLog, "v2.1.0", "v2.2.0")
	serverLog := waitForTestLog(t, serverLogs, "split version mismatch, closing connection from local")
	assertVersionMismatchLog(t, serverLog, "v2.1.0", "v2.2.0")
	if client.IsConnected() {
		t.Fatal("client is connected despite the version mismatch")
	}
	if connected.Load() {
		t.Fatal("server reported a connected peer despite the version mismatch")
	}
}

func TestSplitClientVersionMismatchWaitsForRemoteClose(t *testing.T) {
	serverLogs := &lockedTestBuffer{}
	addr := startVersionTestServer(t, "v2.2.0", serverLogs, nil)
	client := &Client{
		Addr:      addr,
		TLSConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Version:   "v2.1.0",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	_, _, err := client.dialAndHandshake(ctx)
	var mismatch *VersionMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("dialAndHandshake() error = %v, want *VersionMismatchError", err)
	}
	if mismatch.LocalVersion != "v2.1.0" || mismatch.RemoteVersion != "v2.2.0" {
		t.Fatalf("mismatch = %+v, want local v2.1.0 and remote v2.2.0", mismatch)
	}
	if !strings.Contains(err.Error(), "local version v2.1.0, remote version v2.2.0") {
		t.Fatalf("mismatch error does not name both versions: %v", err)
	}
	// The remote closes the connection itself, well before the client's
	// bounded wait expires.
	if elapsed := time.Since(start); elapsed >= 4*time.Second {
		t.Fatalf("dialAndHandshake() took %v; the remote did not close the connection", elapsed)
	}
	waitForTestLog(t, serverLogs, "split version mismatch, closing connection from local")
}

func TestSplitServerRejectsClientWithoutVersion(t *testing.T) {
	serverLogs := &lockedTestBuffer{}
	var connected atomic.Bool
	addr := startVersionTestServer(t, "v2.2.0", serverLogs, func() { connected.Store(true) })

	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	legacy := make([]byte, 4)
	binary.BigEndian.PutUint32(legacy, ProtocolMagic)
	if err := writeFrame(bufio.NewWriter(conn), TypeHandshake, legacy); err != nil {
		t.Fatalf("write legacy handshake: %v", err)
	}
	reader := bufio.NewReader(conn)
	typ, data, err := readFrame(reader)
	if err != nil || typ != TypeHandshake {
		t.Fatalf("read server handshake = type 0x%02x, error %v", typ, err)
	}
	if peer, err := parseHandshake(data); err != nil || peer.version != "v2.2.0" {
		t.Fatalf("server handshake = %+v, error %v; want version v2.2.0", peer, err)
	}
	if _, err := io.Copy(io.Discard, reader); err != nil {
		t.Fatalf("server did not close the connection cleanly: %v", err)
	}

	got := waitForTestLog(t, serverLogs, "split version mismatch, closing connection from local")
	assertVersionMismatchLog(t, got, UnknownPeerVersion, "v2.2.0")
	if connected.Load() {
		t.Fatal("server reported a connected peer without a version")
	}
}

func TestSplitClientRejectsServerWithoutVersion(t *testing.T) {
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{testSplitCertificate(t)},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	clientHandshake := make(chan []byte, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		// Emulate a server built before the version exchange.
		legacy := make([]byte, 4)
		binary.BigEndian.PutUint32(legacy, ProtocolMagic)
		if err := writeFrame(bufio.NewWriter(conn), TypeHandshake, legacy); err != nil {
			return
		}
		_, data, err := readFrame(bufio.NewReader(conn))
		if err == nil {
			clientHandshake <- data
		}
	}()

	client := &Client{
		Addr:      listener.Addr().String(),
		TLSConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Version:   "v2.2.0",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, _, err = client.dialAndHandshake(ctx)
	var mismatch *VersionMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("dialAndHandshake() error = %v, want *VersionMismatchError", err)
	}
	if mismatch.LocalVersion != "v2.2.0" || mismatch.RemoteVersion != UnknownPeerVersion {
		t.Fatalf("mismatch = %+v, want local v2.2.0 and an unknown remote version", mismatch)
	}
	select {
	case data := <-clientHandshake:
		if peer, err := parseHandshake(data); err != nil || peer.version != "v2.2.0" {
			t.Fatalf("client handshake = %+v, error %v; want version v2.2.0", peer, err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("legacy server did not receive the client handshake")
	}
}

func startVersionTestServer(t *testing.T, version string, logs *lockedTestBuffer, onConnected func()) string {
	t.Helper()
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.Addr().String()
	if err := probe.Close(); err != nil {
		t.Fatal(err)
	}
	ready := make(chan struct{}, 1)
	server := &Server{
		Addr:        addr,
		TLSConfig:   &tls.Config{Certificates: []tls.Certificate{testSplitCertificate(t)}, MinVersion: tls.VersionTLS12},
		Logger:      slog.New(slog.NewTextHandler(logs, nil)),
		OnReady:     func() { ready <- struct{}{} },
		OnConnected: onConnected,
		Version:     version,
		Deliver:     func(context.Context, SendRequest) error { return nil },
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.ListenAndServe(ctx) }()
	select {
	case <-ready:
	case err := <-done:
		cancel()
		t.Fatalf("split version test server failed to start: %v", err)
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("timed out waiting for split version test server")
	}
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("split version test server stopped with error: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("split version test server did not stop")
		}
	})
	return addr
}

func assertVersionMismatchLog(t *testing.T, logs, localVersion, remoteVersion string) {
	t.Helper()
	var line string
	for _, candidate := range strings.Split(logs, "\n") {
		if strings.Contains(candidate, "split version mismatch") {
			line = candidate
			break
		}
	}
	if !strings.Contains(line, "level=ERROR") {
		t.Fatalf("version mismatch is not logged as an error: %s", logs)
	}
	for _, want := range []string{"local_version=" + logValue(localVersion), "remote_version=" + logValue(remoteVersion)} {
		if !strings.Contains(line, want) {
			t.Fatalf("version mismatch log %q does not contain %q", line, want)
		}
	}
}

// logValue formats value the way slog's text handler does.
func logValue(value string) string {
	if strings.ContainsAny(value, " =\"") {
		return `"` + value + `"`
	}
	return value
}
