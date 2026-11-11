package split

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	mathrand "math/rand"
	"strings"
	"testing"
	"time"
)

func TestEncodeDecodeCompressibleFrame(t *testing.T) {
	payload := []byte(strings.Repeat("Subject: bandwidth test\r\nBody line with repeated text.\r\n", 512))
	wireType, wirePayload, err := encodeFramePayload(TypeSendMail, payload)
	if err != nil {
		t.Fatalf("encodeFramePayload() error = %v", err)
	}
	if wireType != TypeSendMail|FlagCompressed {
		t.Fatalf("wire frame type = 0x%02x, want compressed SendMail", wireType)
	}
	if len(wirePayload) >= len(payload) {
		t.Fatalf("compressed payload size = %d, original = %d", len(wirePayload), len(payload))
	}
	frameType, decoded, err := decodeFramePayload(wireType, wirePayload, maxDecompressedFrameBytes)
	if err != nil {
		t.Fatalf("decodeFramePayload() error = %v", err)
	}
	if frameType != TypeSendMail || !bytes.Equal(decoded, payload) {
		t.Fatal("decoded payload differs from original")
	}
}

func TestEncodeFrameLeavesSmallAndIncompressiblePayloadsPlain(t *testing.T) {
	for name, payload := range map[string][]byte{
		"small": []byte("small message"),
		"incompressible": func() []byte {
			data := make([]byte, 16<<10)
			_, _ = mathrand.New(mathrand.NewSource(42)).Read(data)
			return data
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			wireType, wirePayload, err := encodeFramePayload(TypeSubmitMail, payload)
			if err != nil {
				t.Fatalf("encodeFramePayload() error = %v", err)
			}
			if wireType != TypeSubmitMail || !bytes.Equal(wirePayload, payload) {
				t.Fatalf("payload was unexpectedly compressed: type 0x%02x, size %d (original %d)", wireType, len(wirePayload), len(payload))
			}
		})
	}
}

func TestEncodeFrameNeverCompressesSecretsOrControlFrames(t *testing.T) {
	payload := bytes.Repeat([]byte("secret material"), 1024)
	for _, frameType := range []byte{TypeAuth, TypeTLSCertificate, TypeAck, TypeErr} {
		wireType, wirePayload, err := encodeFramePayload(frameType, payload)
		if err != nil {
			t.Fatalf("encodeFramePayload(0x%02x) error = %v", frameType, err)
		}
		if wireType != frameType || !bytes.Equal(wirePayload, payload) {
			t.Errorf("frame type 0x%02x was compressed", frameType)
		}
	}
}

func TestDecodeFrameRejectsOversizeCorruptAndInvalidCompressedFrames(t *testing.T) {
	payload := bytes.Repeat([]byte("large body "), 2048)
	wireType, wirePayload, err := encodeFramePayload(TypeSendMail, payload)
	if err != nil {
		t.Fatal(err)
	}
	if wireType&FlagCompressed == 0 {
		t.Fatal("test payload was not compressed")
	}
	if _, _, err := decodeFramePayload(wireType, wirePayload, 100); err == nil {
		t.Fatal("decodeFramePayload() accepted data over the decompression limit")
	}
	if _, _, err := decodeFramePayload(wireType, []byte{0xff, 0xff, 0xff}, maxDecompressedFrameBytes); err == nil {
		t.Fatal("decodeFramePayload() accepted corrupt compressed data")
	}
	if _, _, err := decodeFramePayload(TypeAuth|FlagCompressed, wirePayload, maxDecompressedFrameBytes); err == nil {
		t.Fatal("decodeFramePayload() accepted a compression flag on Auth")
	}
}

func TestDecodePlainFramePassesThroughUnchanged(t *testing.T) {
	payload := []byte("uncompressed frame payload")
	frameType, decoded, err := decodeFramePayload(TypeAuth, payload, maxDecompressedFrameBytes)
	if err != nil {
		t.Fatalf("decodeFramePayload() error = %v", err)
	}
	if frameType != TypeAuth || !bytes.Equal(decoded, payload) {
		t.Fatal("plain frame changed during decoding")
	}
}

func TestSplitCompressedMailFramesRoundTrip(t *testing.T) {
	logs := &lockedTestBuffer{}
	logger := slog.New(slog.NewTextHandler(logs, nil))
	serverReceived := make(chan SendRequest, 1)
	clientReceived := make(chan SendRequest, 1)
	server, client := startConfiguredTestSplitPair(t,
		func(_ context.Context, req SendRequest) error {
			serverReceived <- req
			return nil
		},
		func(context.Context, SendRequest) error { return nil },
		func(_ context.Context, req SendRequest) error {
			clientReceived <- req
			return nil
		}, nil, nil, logger)

	message := []byte(strings.Repeat("From: alice@example.test\r\nSubject: repeated text\r\n\r\nA long repeated body line.\r\n", 2048))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	clientToServer := SendRequest{From: "alice@example.test", Recipient: "bob@example.test", Data: message}
	if err := client.Send(ctx, clientToServer); err != nil {
		t.Fatalf("client.Send() error = %v", err)
	}
	select {
	case got := <-serverReceived:
		assertSendRequest(t, got, clientToServer)
	case <-ctx.Done():
		t.Fatal("timed out waiting for compressed SendMail at server")
	}

	serverToClient := SendRequest{From: "carol@example.test", Recipient: "dave@example.test", Data: message}
	if err := server.Submit(ctx, serverToClient); err != nil {
		t.Fatalf("server.Submit() error = %v", err)
	}
	select {
	case got := <-clientReceived:
		assertSendRequest(t, got, serverToClient)
	case <-ctx.Done():
		t.Fatal("timed out waiting for compressed SubmitMail at client")
	}

	log := waitForTestLog(t, logs, `msg="split SendMail sent"`)
	assertCompressedWireLog(t, log, `msg="split SendMail sent"`)
	log = waitForTestLog(t, logs, `msg="split SubmitMail sent"`)
	assertCompressedWireLog(t, log, `msg="split SubmitMail sent"`)
	log = waitForTestLog(t, logs, `msg="split SendMail received"`)
	assertCompressedWireLog(t, log, `msg="split SendMail received"`)
	log = waitForTestLog(t, logs, `msg="split SubmitMail received"`)
	assertCompressedWireLog(t, log, `msg="split SubmitMail received"`)
}

func assertCompressedWireLog(t *testing.T, log, message string) {
	t.Helper()
	for _, line := range strings.Split(log, "\n") {
		if !strings.Contains(line, message) {
			continue
		}
		var original, wire int
		for _, field := range strings.Fields(line) {
			switch {
			case strings.HasPrefix(field, "bytes="):
				_, _ = fmt.Sscanf(strings.TrimPrefix(field, "bytes="), "%d", &original)
			case strings.HasPrefix(field, "wire_bytes="):
				_, _ = fmt.Sscanf(strings.TrimPrefix(field, "wire_bytes="), "%d", &wire)
			}
		}
		if original == 0 || wire == 0 {
			t.Fatalf("log lacks byte counts: %s", line)
		}
		if wire >= original {
			t.Fatalf("wire frame was not smaller than message bytes (%d >= %d): %s", wire, original, line)
		}
		return
	}
	t.Fatalf("log entry %q not found", message)
}
