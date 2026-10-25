// Package plugins defines the receiving-side SMTP processor extension point.
package plugins

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// Decision is the action a processor requests for a message.
type Decision uint8

const (
	// Accept continues processing and eventually delivers the message.
	Accept Decision = iota
	// Reject returns a permanent SMTP failure to the sender.
	Reject
	// TemporaryFailure returns a retryable SMTP failure.
	TemporaryFailure
	// Discard accepts the message without delivering it.
	Discard
)

// Message is the message and delivery context passed to processors.
type Message struct {
	// Data contains the complete message and may be replaced by a processor.
	Data []byte
	// From is the SMTP envelope sender.
	From string
	// Recipients contains the SMTP envelope recipients.
	Recipients []string
	// Metadata contains connection and application context.
	Metadata map[string]string
	// Maildir is the absolute path to the first locally delivered user's
	// Maildir. It is empty for forwarded-only messages.
	Maildir string
	// Folder selects a Maildir++ folder for local delivery.
	Folder string
}

// Result is the action and optional explanation returned by a processor.
type Result struct {
	// Decision controls whether processing continues or delivery stops.
	Decision Decision
	// Reason is returned to the sender for rejected or temporary messages.
	Reason string
	// Folder overrides Message.Folder when non-empty.
	Folder string
}

// Processor is called in registration order after SMTP DATA has completed.
// Implementations must be safe for concurrent calls from multiple sessions.
type Processor interface {
	// Name returns a stable name for logs and error messages.
	Name() string
	// Initialize prepares the processor before listeners start. Settings are
	// selected by the processor name from the daemon configuration.
	Initialize(context.Context, map[string]string) error
	// Process examines or changes one locally delivered message.
	Process(context.Context, *Message) (Result, error)
}

// PluginConfig names one configured processor and its optional settings.
type PluginConfig struct {
	// Name identifies the processor that receives Config.
	Name string `yaml:"name"`
	// Config contains string settings passed to the processor at initialization.
	Config map[string]string `yaml:"config,omitempty"`
}

// InitializationFailure identifies a processor that could not initialize.
type InitializationFailure struct {
	Processor Processor
	Err       error
}

// Chain runs registered processors in order and is safe for concurrent
// processing after registration is complete.
type Chain struct {
	mu         sync.RWMutex
	processors []Processor
}

// New creates an empty processor chain.
func New() *Chain { return &Chain{} }

// Add appends a processor to the chain.
func (c *Chain) Add(processor Processor) error {
	if processor == nil {
		return errors.New("nil processor")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.processors = append(c.processors, processor)
	return nil
}

// Initialize initializes each processor and removes processors that fail.
// When configured is supplied, the first matching plugin name provides the
// settings passed to that processor. Processors without settings receive nil.
func (c *Chain) Initialize(ctx context.Context, configured ...[]PluginConfig) []InitializationFailure {
	c.mu.Lock()
	defer c.mu.Unlock()
	active := make([]Processor, 0, len(c.processors))
	var failures []InitializationFailure
	for _, processor := range c.processors {
		if err := initializeOne(ctx, processor, pluginSettings(processor.Name(), configured)); err != nil {
			failures = append(failures, InitializationFailure{Processor: processor, Err: err})
			continue
		}
		active = append(active, processor)
	}
	c.processors = active
	return failures
}

// Process runs the chain. Processor errors and panics become temporary
// failures; a non-accept decision stops the chain.
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

func pluginSettings(name string, configured [][]PluginConfig) map[string]string {
	if len(configured) == 0 {
		return nil
	}
	for _, plugin := range configured[0] {
		if plugin.Name == name {
			return cloneSettings(plugin.Config)
		}
	}
	return nil
}

func cloneSettings(settings map[string]string) map[string]string {
	if settings == nil {
		return nil
	}
	clone := make(map[string]string, len(settings))
	for key, value := range settings {
		clone[key] = value
	}
	return clone
}

func initializeOne(ctx context.Context, processor Processor, settings map[string]string) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("panic: %v", recovered)
		}
	}()
	return processor.Initialize(ctx, settings)
}

func processOne(ctx context.Context, processor Processor, message *Message) (result Result, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("panic: %v", recovered)
		}
	}()
	return processor.Process(ctx, message)
}
