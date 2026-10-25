// Package plugins defines the receiving-side SMTP processor extension point.
package plugins

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

type Decision uint8

const (
	Accept Decision = iota
	Reject
	TemporaryFailure
	Discard
)

type Message struct {
	Data       []byte
	From       string
	Recipients []string
	Metadata   map[string]string
	Folder     string
}

type Result struct {
	Decision Decision
	Reason   string
	Folder   string
}

// Processor is called in registration order after SMTP DATA has completed.
// Implementations must be safe for concurrent calls from multiple sessions.
type Processor interface {
	Name() string
	Initialize(context.Context) error
	Process(context.Context, *Message) (Result, error)
}

type InitializationFailure struct {
	Processor Processor
	Err       error
}

type Chain struct {
	mu         sync.RWMutex
	processors []Processor
}

func New() *Chain { return &Chain{} }

func (c *Chain) Add(processor Processor) error {
	if processor == nil {
		return errors.New("nil processor")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.processors = append(c.processors, processor)
	return nil
}

func (c *Chain) Initialize(ctx context.Context) []InitializationFailure {
	c.mu.Lock()
	defer c.mu.Unlock()
	active := make([]Processor, 0, len(c.processors))
	var failures []InitializationFailure
	for _, processor := range c.processors {
		if err := initializeOne(ctx, processor); err != nil {
			failures = append(failures, InitializationFailure{Processor: processor, Err: err})
			continue
		}
		active = append(active, processor)
	}
	c.processors = active
	return failures
}

func (c *Chain) Process(ctx context.Context, message *Message) Result {
	c.mu.RLock()
	processors := append([]Processor(nil), c.processors...)
	c.mu.RUnlock()
	for _, processor := range processors {
		result, err := processOne(ctx, processor, message)
		if err != nil {
			return Result{Decision: TemporaryFailure, Reason: fmt.Sprintf("processor %s failed: %v", processor.Name(), err)}
		}
		if result.Folder != "" {
			message.Folder = result.Folder
		}
		switch result.Decision {
		case Accept:
			continue
		case Reject, TemporaryFailure, Discard:
			if result.Reason == "" {
				result.Reason = processor.Name()
			}
			return result
		default:
			return Result{Decision: TemporaryFailure, Reason: "processor returned invalid decision"}
		}
	}
	return Result{Decision: Accept}
}

func initializeOne(ctx context.Context, processor Processor) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("panic: %v", recovered)
		}
	}()
	return processor.Initialize(ctx)
}

func processOne(ctx context.Context, processor Processor, message *Message) (result Result, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("panic: %v", recovered)
		}
	}()
	return processor.Process(ctx, message)
}
