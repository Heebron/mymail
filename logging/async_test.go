package logging

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type blockingHandler struct {
	started  chan struct{}
	release  chan struct{}
	startOne sync.Once
	handled  atomic.Int64
}

func (h *blockingHandler) Enabled(context.Context, slog.Level) bool {
	return true
}

func (h *blockingHandler) Handle(context.Context, slog.Record) error {
	h.startOne.Do(func() { close(h.started) })
	<-h.release
	h.handled.Add(1)
	return nil
}

func (h *blockingHandler) WithAttrs([]slog.Attr) slog.Handler {
	return h
}

func (h *blockingHandler) WithGroup(string) slog.Handler {
	return h
}

type collectingHandler struct {
	mu       sync.Mutex
	messages []string
}

func (h *collectingHandler) Enabled(context.Context, slog.Level) bool {
	return true
}

func (h *collectingHandler) Handle(_ context.Context, record slog.Record) error {
	h.mu.Lock()
	h.messages = append(h.messages, record.Message)
	h.mu.Unlock()
	return nil
}

func (h *collectingHandler) WithAttrs([]slog.Attr) slog.Handler {
	return h
}

func (h *collectingHandler) WithGroup(string) slog.Handler {
	return h
}

func (h *collectingHandler) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.messages)
}

func TestAsyncHandlerDoesNotBlockWhenOutputIsBlocked(t *testing.T) {
	output := &blockingHandler{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	handler := NewAsyncHandler(output, 1)
	logger := slog.New(handler)

	logger.Info("first")
	select {
	case <-output.started:
	case <-time.After(time.Second):
		t.Fatal("asynchronous output worker did not start")
	}

	returned := make(chan struct{})
	go func() {
		for index := 0; index < 1000; index++ {
			logger.Info("queued", "index", index)
		}
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("logging blocked while output handler was blocked")
	}

	close(output.release)
	handler.Close()
	if handler.Dropped() == 0 {
		t.Fatal("expected records to be dropped after the queue filled")
	}
}

func TestAsyncHandlerCloseDrainsAcceptedRecords(t *testing.T) {
	output := &collectingHandler{}
	handler := NewAsyncHandler(output, 8)
	logger := slog.New(handler)
	for index := 0; index < 3; index++ {
		logger.Info("message", "index", index)
	}

	handler.Close()
	if got := output.count(); got != 3 {
		t.Fatalf("output record count = %d, want 3", got)
	}
	if handler.Dropped() != 0 {
		t.Fatalf("dropped records = %d, want 0", handler.Dropped())
	}
}
