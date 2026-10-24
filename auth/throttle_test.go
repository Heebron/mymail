package auth

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestLimiterBackoffAndResetAfterSuccess(t *testing.T) {
	config := Config{
		MaxAttemptsPerConnection: 5,
		MaxFailuresPerIP:         3,
		MaxFailuresPerAccount:    3,
		BackoffBase:              time.Second,
		BackoffMax:               4 * time.Second,
		FailureWindow:            time.Minute,
	}
	limiter := NewLimiter(config)
	now := time.Unix(100, 0)
	limiter.now = func() time.Time { return now }

	first := limiter.NewConnection("192.0.2.10:2525")
	if err := first.Allow("Alice@example.test"); err != nil {
		t.Fatalf("first authentication attempt blocked: %v", err)
	}
	first.Failure("Alice@example.test")

	second := limiter.NewConnection("192.0.2.10:1143")
	if err := second.Allow("alice@example.test"); !errors.Is(err, ErrBackoff) {
		t.Fatalf("second protocol attempt error = %v, want backoff", err)
	}

	now = now.Add(time.Second)
	if err := second.Allow("alice@example.test"); err != nil {
		t.Fatalf("attempt after backoff blocked: %v", err)
	}
	second.Failure("alice@example.test")
	now = now.Add(time.Second)
	if err := second.Allow("alice@example.test"); !errors.Is(err, ErrBackoff) {
		t.Fatalf("exponential backoff error = %v, want backoff", err)
	}
	now = now.Add(time.Second)
	if err := second.Allow("alice@example.test"); err != nil {
		t.Fatalf("attempt after exponential backoff blocked: %v", err)
	}
	second.Success("alice@example.test")

	third := limiter.NewConnection("192.0.2.10:2525")
	if err := third.Allow("alice@example.test"); err != nil {
		t.Fatalf("successful login did not reset shared limits: %v", err)
	}
}

func TestLimiterFailureReturnsBoundedResponseDelay(t *testing.T) {
	config := Config{
		MaxAttemptsPerConnection: 5,
		MaxFailuresPerIP:         10,
		MaxFailuresPerAccount:    10,
		BackoffBase:              10 * time.Millisecond,
		BackoffMax:               100 * time.Millisecond,
		ResponseDelayMax:         15 * time.Millisecond,
		FailureWindow:            time.Minute,
	}
	limiter := NewLimiter(config)
	now := time.Unix(150, 0)
	limiter.now = func() time.Time { return now }
	connection := limiter.NewConnection("192.0.2.15:2525")

	if delay := connection.Failure("alice@example.test"); delay != 10*time.Millisecond {
		t.Fatalf("first response delay = %v, want 10ms", delay)
	}
	now = now.Add(10 * time.Millisecond)
	if err := connection.Allow("alice@example.test"); err != nil {
		t.Fatalf("attempt after first backoff blocked: %v", err)
	}
	if delay := connection.Failure("alice@example.test"); delay != 15*time.Millisecond {
		t.Fatalf("bounded response delay = %v, want 15ms", delay)
	}
}

func TestLimiterEnforcesConnectionIPAndAccountLimits(t *testing.T) {
	config := Config{
		MaxAttemptsPerConnection: 2,
		MaxFailuresPerIP:         2,
		MaxFailuresPerAccount:    2,
		BackoffBase:              time.Millisecond,
		BackoffMax:               time.Millisecond,
		FailureWindow:            time.Minute,
	}
	limiter := NewLimiter(config)
	now := time.Unix(200, 0)
	limiter.now = func() time.Time { return now }

	connection := limiter.NewConnection("192.0.2.20:2525")
	if err := connection.Allow("alice@example.test"); err != nil {
		t.Fatal(err)
	}
	connection.Failure("alice@example.test")
	if err := connection.Allow("bob@example.test"); !errors.Is(err, ErrBackoff) {
		t.Fatalf("IP limit error = %v, want backoff", err)
	}

	now = now.Add(time.Millisecond)
	otherIP := limiter.NewConnection("192.0.2.21:2525")
	if err := otherIP.Allow("alice@example.test"); err != nil {
		t.Fatal(err)
	}
	otherIP.Failure("alice@example.test")
	if err := limiter.NewConnection("192.0.2.22:2525").Allow("alice@example.test"); !errors.Is(err, ErrBackoff) {
		t.Fatalf("account limit error = %v, want backoff", err)
	}

	if err := connection.Allow("new@example.test"); !errors.Is(err, ErrConnectionLimit) {
		t.Fatalf("connection limit error = %v, want connection limit", err)
	}
}

func TestLimiterLogsMitigationDecisions(t *testing.T) {
	var logs bytes.Buffer
	config := DefaultConfig()
	config.BackoffBase = time.Second
	config.BackoffMax = time.Second
	config.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	limiter := NewLimiter(config)
	now := time.Unix(300, 0)
	limiter.now = func() time.Time { return now }

	connection := limiter.NewConnection("192.0.2.30:2525")
	if err := connection.Allow("alice@example.test"); err != nil {
		t.Fatal(err)
	}
	connection.Failure("alice@example.test")
	if err := limiter.NewConnection("192.0.2.31:2525").Allow("alice@example.test"); !errors.Is(err, ErrBackoff) {
		t.Fatalf("backoff error = %v", err)
	}
	now = now.Add(time.Second)
	connection.Success("alice@example.test")

	output := logs.String()
	for _, decision := range []string{"decision=allow", "decision=backoff", "authentication throttle failure", "authentication throttle reset", "retry_after=1s"} {
		if !strings.Contains(output, decision) {
			t.Fatalf("logs omit %q: %s", decision, output)
		}
	}
	if strings.Contains(output, "password") || strings.Contains(output, "changeit") {
		t.Fatalf("logs contain credential material: %s", output)
	}
}
