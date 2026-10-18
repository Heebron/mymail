package plugins

import (
	"context"
	"errors"
	"sync"
	"testing"
)

type testProcessor struct {
	name   string
	result Result
	mu     sync.Mutex
	calls  int
}

func (p *testProcessor) Name() string { return p.name }
func (p *testProcessor) Process(context.Context, *Message) (Result, error) {
	p.mu.Lock()
	p.calls++
	p.mu.Unlock()
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
