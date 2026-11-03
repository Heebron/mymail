package plugins

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
)

type testProcessor struct {
	name             string
	result           Result
	initErr          error
	initialize       func(context.Context) error
	initializeConfig func(context.Context, map[string]string) error
	mutate           func(*Message)
	processErr       error
	mu               sync.Mutex
	initCalls        int
	calls            int
}

func (p *testProcessor) Name() string { return p.name }
func (p *testProcessor) Initialize(ctx context.Context, settings map[string]string) error {
	p.mu.Lock()
	p.initCalls++
	p.mu.Unlock()
	if p.initializeConfig != nil {
		return p.initializeConfig(ctx, settings)
	}
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
	return p.result, p.processErr
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

func TestChainLogsPluginInitializationAndActivity(t *testing.T) {
	var logs bytes.Buffer
	processor := &testProcessor{name: "example", result: Result{Decision: Accept}}
	failed := &testProcessor{name: "broken", initErr: errors.New("unavailable")}
	chain := New()
	chain.SetLogger(slog.New(slog.NewTextHandler(&logs, nil)))
	if err := chain.Add(processor); err != nil {
		t.Fatal(err)
	}
	if err := chain.Add(failed); err != nil {
		t.Fatal(err)
	}
	if failures := chain.Initialize(context.Background()); len(failures) != 1 {
		t.Fatalf("initialization failures = %#v", failures)
	}
	if result := chain.Process(context.Background(), &Message{Data: []byte("message")}); result.Decision != Accept {
		t.Fatalf("processing result = %#v", result)
	}

	output := logs.String()
	for _, expected := range []string{
		`msg="plugin initialization started" plugin=example`,
		`msg="plugin initialized" plugin=example`,
		`msg="plugin initialization failed" plugin=broken error=unavailable`,
		`msg="plugin processing started" plugin=example bytes=7`,
		`msg="plugin processing completed" plugin=example decision=accept`,
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("plugin logs missing %q: %s", expected, output)
		}
	}
}

func TestInitializePassesMatchingPluginSettings(t *testing.T) {
	var received map[string]string
	processor := &testProcessor{
		name: "configured",
		initializeConfig: func(_ context.Context, settings map[string]string) error {
			received = settings
			return nil
		},
	}
	unconfigured := &testProcessor{name: "unconfigured"}
	chain := New()
	if err := chain.Add(processor); err != nil {
		t.Fatal(err)
	}
	if err := chain.Add(unconfigured); err != nil {
		t.Fatal(err)
	}
	configured := []PluginConfig{
		{Name: "configured", Config: map[string]string{"endpoint": "https://example.test", "token": "secret"}},
	}
	if failures := chain.Initialize(context.Background(), configured); len(failures) != 0 {
		t.Fatalf("initialization failures = %#v", failures)
	}
	if got, want := received, map[string]string{"endpoint": "https://example.test", "token": "secret"}; !equalStringMap(got, want) {
		t.Fatalf("configured settings = %#v, want %#v", got, want)
	}
}

func TestInitializePassesNilToUnconfiguredProcessor(t *testing.T) {
	var received map[string]string
	processor := &testProcessor{
		name: "unconfigured",
		initializeConfig: func(_ context.Context, settings map[string]string) error {
			received = settings
			return nil
		},
	}
	chain := New()
	if err := chain.Add(processor); err != nil {
		t.Fatal(err)
	}
	configured := []PluginConfig{{Name: "different", Config: map[string]string{"key": "value"}}}
	if failures := chain.Initialize(context.Background(), configured); len(failures) != 0 {
		t.Fatalf("initialization failures = %#v", failures)
	}
	if received != nil {
		t.Fatalf("unconfigured settings = %#v, want nil", received)
	}
}

func TestInitializeClonesPluginSettings(t *testing.T) {
	configuredSettings := map[string]string{"token": "secret"}
	processor := &testProcessor{
		name: "configured",
		initializeConfig: func(_ context.Context, settings map[string]string) error {
			settings["token"] = "changed"
			return nil
		},
	}
	chain := New()
	if err := chain.Add(processor); err != nil {
		t.Fatal(err)
	}
	configured := []PluginConfig{{Name: "configured", Config: configuredSettings}}
	if failures := chain.Initialize(context.Background(), configured); len(failures) != 0 {
		t.Fatalf("initialization failures = %#v", failures)
	}
	if configuredSettings["token"] != "secret" {
		t.Fatalf("configured settings were mutated: %#v", configuredSettings)
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

func TestChainAcceptsAndRestoresMessageAfterProcessorError(t *testing.T) {
	original := []byte("Subject: original\r\n\r\nbody")
	var logs bytes.Buffer
	processor := &testProcessor{
		name:       "broken",
		processErr: errors.New("unavailable"),
		mutate: func(message *Message) {
			message.Data = []byte("changed")
			message.Folder = "Changed"
		},
	}
	chain := New()
	chain.SetLogger(slog.New(slog.NewTextHandler(&logs, nil)))
	if err := chain.Add(processor); err != nil {
		t.Fatal(err)
	}
	message := &Message{Data: append([]byte(nil), original...), Folder: "INBOX"}

	result := chain.Process(context.Background(), message)
	if result.Decision != Accept {
		t.Fatalf("result decision = %v, want accept", result.Decision)
	}
	if result.Err == nil || !errors.Is(result.Err, processor.processErr) {
		t.Fatalf("result error = %v, want wrapped processor error", result.Err)
	}
	if !bytes.Equal(message.Data, original) {
		t.Fatalf("message data = %q, want %q", message.Data, original)
	}
	if message.Folder != "INBOX" {
		t.Fatalf("message folder = %q, want INBOX", message.Folder)
	}
	if !strings.Contains(logs.String(), `msg="plugin processing failed" plugin=broken`) {
		t.Fatalf("plugin failure log missing: %s", logs.String())
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

func equalStringMap(got, want map[string]string) bool {
	if len(got) != len(want) {
		return false
	}
	for key, value := range want {
		if got[key] != value {
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
