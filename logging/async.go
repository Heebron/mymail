// Package logging provides logging handlers used by the MyMail services.
package logging

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
)

// DefaultQueueSize is the number of records an asynchronous handler queues
// before it starts dropping records rather than delaying the caller.
const DefaultQueueSize = 4096

type event struct {
	ctx     context.Context
	handler slog.Handler
	record  slog.Record
}

type state struct {
	queue chan event
	stop  chan struct{}
	done  chan struct{}

	mu      sync.Mutex
	closed  bool
	close   sync.Once
	dropped atomic.Uint64
}

// AsyncHandler sends records to handler on a dedicated worker goroutine.
// Handle never waits for the destination handler: records are dropped when
// the queue is full or the handler is closing.
type AsyncHandler struct {
	state   *state
	handler slog.Handler
}

// NewAsyncHandler wraps handler in an asynchronous slog handler. A queueSize
// less than one uses DefaultQueueSize.
func NewAsyncHandler(handler slog.Handler, queueSize int) *AsyncHandler {
	if handler == nil {
		panic("logging: nil handler")
	}
	if queueSize < 1 {
		queueSize = DefaultQueueSize
	}
	state := &state{
		queue: make(chan event, queueSize),
		stop:  make(chan struct{}),
		done:  make(chan struct{}),
	}
	go state.run()
	return &AsyncHandler{state: state, handler: handler}
}

// Enabled accepts records so level filtering happens on the worker instead
// of making the caller execute destination-handler logic.
func (h *AsyncHandler) Enabled(context.Context, slog.Level) bool {
	return true
}

// Handle queues a clone of record without waiting for the destination.
func (h *AsyncHandler) Handle(ctx context.Context, record slog.Record) error {
	if ctx == nil {
		ctx = context.Background()
	}
	h.state.enqueue(event{ctx: ctx, handler: h.handler, record: record.Clone()})
	return nil
}

// WithAttrs preserves slog attributes while keeping records asynchronous.
func (h *AsyncHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &AsyncHandler{state: h.state, handler: h.handler.WithAttrs(attrs)}
}

// WithGroup preserves slog groups while keeping records asynchronous.
func (h *AsyncHandler) WithGroup(name string) slog.Handler {
	return &AsyncHandler{state: h.state, handler: h.handler.WithGroup(name)}
}

// Dropped reports the number of records discarded because the queue was full
// or the handler had started shutting down.
func (h *AsyncHandler) Dropped() uint64 {
	if h == nil || h.state == nil {
		return 0
	}
	return h.state.dropped.Load()
}

// Close stops accepting records, drains the queue, and waits for the worker
// to finish. It is safe to call Close more than once.
func (h *AsyncHandler) Close() {
	if h == nil || h.state == nil {
		return
	}
	h.state.close.Do(func() {
		h.state.mu.Lock()
		h.state.closed = true
		close(h.state.stop)
		h.state.mu.Unlock()
		<-h.state.done
	})
}

func (s *state) enqueue(item event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		s.dropped.Add(1)
		return
	}
	select {
	case s.queue <- item:
	default:
		s.dropped.Add(1)
	}
}

func (s *state) run() {
	defer close(s.done)
	for {
		select {
		case item := <-s.queue:
			s.handle(item)
		case <-s.stop:
			s.drain()
			return
		}
	}
}

func (s *state) drain() {
	for {
		select {
		case item := <-s.queue:
			s.handle(item)
		default:
			return
		}
	}
}

func (s *state) handle(item event) {
	if item.handler.Enabled(item.ctx, item.record.Level) {
		_ = item.handler.Handle(item.ctx, item.record)
	}
}
