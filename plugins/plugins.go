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
}

type Result struct {
	Decision Decision
	Reason   string
}

// Processor is called in registration order after SMTP DATA has completed.
// Implementations must be safe for concurrent calls from multiple sessions.
type Processor interface {
	Name() string
	Process(context.Context, *Message) (Result, error)
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

func (c *Chain) Process(ctx context.Context, message *Message) Result {
	c.mu.RLock()
	processors := append([]Processor(nil), c.processors...)
	c.mu.RUnlock()
	for _, processor := range processors {
		result, err := processOne(ctx, processor, message)
		if err != nil {
			return Result{Decision: TemporaryFailure, Reason: fmt.Sprintf("processor %s failed: %v", processor.Name(), err)}
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

func processOne(ctx context.Context, processor Processor, message *Message) (result Result, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("panic: %v", recovered)
		}
	}()
	return processor.Process(ctx, message)
}
