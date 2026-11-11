package split

import (
	"bytes"
	"compress/flate"
	"fmt"
	"io"
	"sync"
)

// FlagCompressed marks a frame payload encoded with DEFLATE.
const FlagCompressed byte = 0x80

const (
	compressMinBytes          = 1024
	maxDecompressedFrameBytes = 64 << 20
)

var flateWriterPool = sync.Pool{
	New: func() any {
		writer, _ := flate.NewWriter(io.Discard, flate.DefaultCompression)
		return writer
	},
}

func compressibleFrameType(frameType byte) bool {
	switch frameType {
	case TypeSendMail, TypeSubmitMail, TypeMailboxList:
		return true
	default:
		return false
	}
}

func encodeFramePayload(frameType byte, payload []byte) (byte, []byte, error) {
	if len(payload) < compressMinBytes || !compressibleFrameType(frameType) {
		return frameType, payload, nil
	}

	var compressed bytes.Buffer
	writer := flateWriterPool.Get().(*flate.Writer)
	writer.Reset(&compressed)
	_, writeErr := writer.Write(payload)
	closeErr := writer.Close()
	writer.Reset(io.Discard)
	flateWriterPool.Put(writer)
	if writeErr != nil {
		return frameType, payload, fmt.Errorf("compress split frame: %w", writeErr)
	}
	if closeErr != nil {
		return frameType, payload, fmt.Errorf("finish split frame compression: %w", closeErr)
	}
	if compressed.Len() >= len(payload) {
		return frameType, payload, nil
	}
	return frameType | FlagCompressed, compressed.Bytes(), nil
}

func decodeFramePayload(frameType byte, payload []byte, limit int64) (byte, []byte, error) {
	if frameType&FlagCompressed == 0 {
		return frameType, payload, nil
	}

	originalType := frameType &^ FlagCompressed
	if !compressibleFrameType(originalType) {
		return 0, nil, fmt.Errorf("compression flag is not valid for frame type 0x%02x", originalType)
	}
	if limit < 0 || limit == int64(^uint64(0)>>1) {
		return 0, nil, fmt.Errorf("invalid decompressed frame limit %d", limit)
	}

	reader := flate.NewReader(bytes.NewReader(payload))
	decompressed, err := io.ReadAll(io.LimitReader(reader, limit+1))
	closeErr := reader.Close()
	if err != nil {
		return 0, nil, fmt.Errorf("decompress split frame: %w", err)
	}
	if closeErr != nil {
		return 0, nil, fmt.Errorf("close split frame decompressor: %w", closeErr)
	}
	if int64(len(decompressed)) > limit {
		return 0, nil, fmt.Errorf("decompressed frame exceeds %d bytes", limit)
	}
	return originalType, decompressed, nil
}
