package plugins

import (
	"context"
	"errors"
	"sync"
	"testing"
)

type testProcessor struct {
	name       string
	result     Result
	initErr    error
	initialize func(context.Context) error
	mutate     func(*Message)
	mu         sync.Mutex
	initCalls  int
	calls      int
}

func (p *testProcessor) Name() string { return p.name }
func (p *testProcessor) Initialize(ctx context.Context) error {
	p.mu.Lock()
	p.initCalls++
	p.mu.Unlock()
	if p.initialize != nil {
		return p.initialize(ctx)
	}
	return p.initErr
}
func (p *testProcessor) Process(_ context.Context, message *Message) (Result, error) {
	return p.process(message)
}

func (p *testProcessor) process(message *Message) (Result, error) {
	p.mu.Lock()
	p.calls++
	p.mu.Unlock()
	if p.mutate != nil {
		p.mutate(message)
	}
	return p.result, nil
}

func TestChainStopsAtDecision(t *testing.T) {
	first := &testProcessor{name: "spam", result: Result{Decision: Reject, Reason: "spam score exceeded"}}
	second := &testProcessor{name: "archive", result: Result{Decision: Accept}}
	chain := New()
	if err := chain.Add(first); err != nil {
		t.Fatal(err)
	}
	if err := chain.Add(second); err != nil {
		t.Fatal(err)
	}
	result := chain.Process(context.Background(), &Message{Data: []byte("message")})
	if result.Decision != Reject || result.Reason != "spam score exceeded" {
		t.Fatalf("unexpected result: %#v", result)
	}
	if first.calls != 1 || second.calls != 0 {
		t.Fatalf("processor calls: first=%d second=%d", first.calls, second.calls)
	}
}

func TestChainSupportsConcurrentProcessing(t *testing.T) {
	processor := &testProcessor{name: "accept", result: Result{Decision: Accept}}
	chain := New()
	if err := chain.Add(processor); err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	for i := 0; i < 100; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			if result := chain.Process(context.Background(), &Message{}); result.Decision != Accept {
				t.Errorf("unexpected result: %#v", result)
			}
		}()
	}
	group.Wait()
	if processor.calls != 100 {
		t.Fatalf("got %d calls, want 100", processor.calls)
	}
}

func TestInitializeInvokesProcessorsInRegistrationOrder(t *testing.T) {
	var order []string
	first := &testProcessor{name: "first", initialize: func(context.Context) error {
		order = append(order, "first")
		return nil
	}}
	second := &testProcessor{name: "second", initialize: func(context.Context) error {
		order = append(order, "second")
		return nil
	}}
	chain := New()
	if err := chain.Add(first); err != nil {
		t.Fatal(err)
	}
	if err := chain.Add(second); err != nil {
		t.Fatal(err)
	}

	if failures := chain.Initialize(context.Background()); len(failures) != 0 {
		t.Fatalf("initialization failures = %#v", failures)
	}
	if got, want := order, []string{"first", "second"}; !equalStrings(got, want) {
		t.Fatalf("initialization order = %#v, want %#v", got, want)
	}
	if first.initCalls != 1 || second.initCalls != 1 {
		t.Fatalf("initialization calls: first=%d second=%d", first.initCalls, second.initCalls)
	}
}

func TestInitializeDropsFailedProcessors(t *testing.T) {
	failed := &testProcessor{name: "failed", initErr: errors.New("unavailable")}
	healthy := &testProcessor{name: "healthy", result: Result{Decision: Accept}}
	chain := New()
	if err := chain.Add(failed); err != nil {
		t.Fatal(err)
	}
	if err := chain.Add(healthy); err != nil {
		t.Fatal(err)
	}
	failures := chain.Initialize(context.Background())
	if len(failures) != 1 || failures[0].Processor != failed || !errors.Is(failures[0].Err, failed.initErr) {
		t.Fatalf("initialization failures = %#v", failures)
	}
	if failed.initCalls != 1 || healthy.initCalls != 1 {
		t.Fatalf("initialization calls: failed=%d healthy=%d", failed.initCalls, healthy.initCalls)
	}
	if result := chain.Process(context.Background(), &Message{}); result.Decision != Accept {
		t.Fatalf("process result = %#v", result)
	}
	if failed.calls != 0 || healthy.calls != 1 {
		t.Fatalf("processor calls: failed=%d healthy=%d", failed.calls, healthy.calls)
	}
}

func TestProcessorCanChangeMessageAndFolder(t *testing.T) {
	processor := &testProcessor{
		name:   "mutate",
		result: Result{Decision: Accept, Folder: "Archive"},
		mutate: func(message *Message) { message.Data = []byte("changed") },
	}
	chain := New()
	if err := chain.Add(processor); err != nil {
		t.Fatal(err)
	}
	if failures := chain.Initialize(context.Background()); len(failures) != 0 {
		t.Fatalf("initialization failures = %#v", failures)
	}
	message := &Message{Data: []byte("original")}
	result := chain.Process(context.Background(), message)
	if result.Decision != Accept || string(message.Data) != "changed" || message.Folder != "Archive" {
		t.Fatalf("message = %#v, result = %#v", message, result)
	}
}

func TestInitializeConvertsPanicsToFailures(t *testing.T) {
	processor := &testProcessor{name: "panic", initialize: func(context.Context) error {
		panic("broken setup")
	}}
	chain := New()
	if err := chain.Add(processor); err != nil {
		t.Fatal(err)
	}

	failures := chain.Initialize(context.Background())
	if len(failures) != 1 || failures[0].Processor != processor {
		t.Fatalf("initialization failures = %#v", failures)
	}
	if got, want := failures[0].Err.Error(), "panic: broken setup"; got != want {
		t.Fatalf("panic error = %q, want %q", got, want)
	}
	if processor.initCalls != 1 {
		t.Fatalf("initialization calls = %d, want 1", processor.initCalls)
	}
}

func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func TestKeywordSpamFilter(t *testing.T) {
	filter := NewKeywordSpamFilter("buy now", "free money", "")

	result, err := filter.Process(context.Background(), &Message{Data: []byte("Subject: BUY NOW\r\n\r\nLimited offer")})
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision != Reject || result.Reason != "spam keyword detected: buy now" {
		t.Fatalf("unexpected spam result: %#v", result)
	}

	result, err = filter.Process(context.Background(), &Message{Data: []byte("Subject: project update\r\n\r\nThe deployment is complete")})
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision != Accept {
		t.Fatalf("clean message result: %#v", result)
	}
}

func TestKeywordSpamFilterContextAndNilMessage(t *testing.T) {
	filter := NewKeywordSpamFilter("spam")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := filter.Process(ctx, &Message{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("got error %v, want context.Canceled", err)
	}
	if _, err := filter.Process(context.Background(), nil); err == nil {
		t.Fatal("nil message unexpectedly accepted")
	}
}
