// Package auth contains shared authentication controls.
package auth

import (
	"errors"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"
)

var (
	// ErrBackoff indicates that authentication is temporarily blocked for the
	// connection's source IP or account.
	ErrBackoff = errors.New("authentication temporarily blocked")
	// ErrConnectionLimit indicates that the connection has used all allowed
	// authentication attempts.
	ErrConnectionLimit = errors.New("authentication connection limit exceeded")
)

// Config controls the shared SMTP and IMAP authentication limiter.
type Config struct {
	// MaxAttemptsPerConnection is the maximum number of checks on one
	// connection.
	MaxAttemptsPerConnection int `yaml:"max_attempts_per_connection"`
	// MaxFailuresPerIP is the failure threshold tracked for each source IP.
	MaxFailuresPerIP int `yaml:"max_failures_per_ip"`
	// MaxFailuresPerAccount is the failure threshold tracked for each account.
	MaxFailuresPerAccount int `yaml:"max_failures_per_account"`
	// BackoffBase is the delay after the first failed authentication.
	BackoffBase time.Duration `yaml:"backoff_base"`
	// BackoffMax is the largest delay used after a failed authentication.
	BackoffMax time.Duration `yaml:"backoff_max"`
	// ResponseDelayMax caps the delay returned to the protocol server.
	ResponseDelayMax time.Duration `yaml:"response_delay_max"`
	// FailureWindow is how long failure state remains active without a new
	// failure.
	FailureWindow time.Duration `yaml:"failure_window"`
	// Logger receives structured throttle decisions. It is not serialized.
	Logger *slog.Logger `yaml:"-"`
}

// DefaultConfig returns the default authentication-throttling limits.
func DefaultConfig() Config {
	return Config{
		MaxAttemptsPerConnection: 5,
		MaxFailuresPerIP:         20,
		MaxFailuresPerAccount:    10,
		BackoffBase:              time.Second,
		BackoffMax:               time.Minute,
		ResponseDelayMax:         time.Second,
		FailureWindow:            15 * time.Minute,
	}
}

// Limiter tracks authentication failures by connection, source IP, and
// normalized account name. It is safe for concurrent use.
type Limiter struct {
	config   Config
	logger   *slog.Logger
	now      func() time.Time
	mu       sync.Mutex
	ips      map[string]failureState
	accounts map[string]failureState
}

type failureState struct {
	failures     int
	lastFailure  time.Time
	blockedUntil time.Time
}

// NewLimiter creates a limiter. Non-positive limits use their default values;
// BackoffMax is raised to BackoffBase when necessary.
func NewLimiter(config Config) *Limiter {
	defaults := DefaultConfig()
	if config.MaxAttemptsPerConnection <= 0 {
		config.MaxAttemptsPerConnection = defaults.MaxAttemptsPerConnection
	}
	if config.MaxFailuresPerIP <= 0 {
		config.MaxFailuresPerIP = defaults.MaxFailuresPerIP
	}
	if config.MaxFailuresPerAccount <= 0 {
		config.MaxFailuresPerAccount = defaults.MaxFailuresPerAccount
	}
	if config.BackoffBase <= 0 {
		config.BackoffBase = defaults.BackoffBase
	}
	if config.BackoffMax <= 0 {
		config.BackoffMax = defaults.BackoffMax
	}
	if config.ResponseDelayMax <= 0 {
		config.ResponseDelayMax = defaults.ResponseDelayMax
	}
	if config.FailureWindow <= 0 {
		config.FailureWindow = defaults.FailureWindow
	}
	if config.BackoffMax < config.BackoffBase {
		config.BackoffMax = config.BackoffBase
	}
	return &Limiter{
		config:   config,
		logger:   config.Logger,
		now:      time.Now,
		ips:      make(map[string]failureState),
		accounts: make(map[string]failureState),
	}
}

// Connection tracks authentication attempts made on one network connection.
type Connection struct {
	limiter  *Limiter
	ip       string
	attempts int
}

// NewConnection creates a connection tracker for a remote address.
func (l *Limiter) NewConnection(remoteAddr string) *Connection {
	return &Connection{limiter: l, ip: normalizeIP(remoteAddr)}
}

// Allow reports whether another authentication check may run.
func (c *Connection) Allow(account string) error {
	if c == nil || c.limiter == nil {
		return nil
	}
	l := c.limiter
	account = normalizeAccount(account)
	l.mu.Lock()
	defer l.mu.Unlock()
	c.attempts++
	if c.attempts > l.config.MaxAttemptsPerConnection {
		l.log("authentication throttle decision", "remote_addr", c.ip, "account", account, "decision", "connection_limit", "attempt", c.attempts)
		return ErrConnectionLimit
	}
	now := l.now()
	ipState, ipOK := l.activeState(l.ips, c.ip, now)
	accountState, accountOK := l.activeState(l.accounts, account, now)
	blockedBy := make([]string, 0, 2)
	if ipOK && now.Before(ipState.blockedUntil) {
		blockedBy = append(blockedBy, "ip")
	}
	if accountOK && now.Before(accountState.blockedUntil) {
		blockedBy = append(blockedBy, "account")
	}
	if len(blockedBy) > 0 {
		retryAfter := time.Duration(0)
		for _, state := range []failureState{ipState, accountState} {
			if remaining := state.blockedUntil.Sub(now); remaining > 0 && (retryAfter == 0 || remaining < retryAfter) {
				retryAfter = remaining
			}
		}
		l.log("authentication throttle decision", "remote_addr", c.ip, "account", account, "decision", "backoff", "blocked_by", blockedBy, "retry_after", retryAfter, "attempt", c.attempts)
		return ErrBackoff
	}
	l.log("authentication throttle decision", "remote_addr", c.ip, "account", account, "decision", "allow", "attempt", c.attempts)
	return nil
}

// Failure records a failed authentication and returns the bounded response
// delay that the protocol server should apply.
func (c *Connection) Failure(account string) time.Duration {
	if c == nil || c.limiter == nil {
		return 0
	}
	l := c.limiter
	account = normalizeAccount(account)
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	ipState := l.recordFailure(l.ips, c.ip, l.config.MaxFailuresPerIP, now)
	accountState := l.recordFailure(l.accounts, account, l.config.MaxFailuresPerAccount, now)
	l.log("authentication throttle failure", "remote_addr", c.ip, "account", account, "ip_failures", ipState.failures, "account_failures", accountState.failures, "ip_backoff", ipState.blockedUntil.Sub(now), "account_backoff", accountState.blockedUntil.Sub(now))
	return l.responseDelay(now, ipState, accountState)
}

// Success clears failure state for the connection's source IP and account.
func (c *Connection) Success(account string) {
	if c == nil || c.limiter == nil {
		return
	}
	l := c.limiter
	account = normalizeAccount(account)
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.ips, c.ip)
	delete(l.accounts, account)
	l.log("authentication throttle reset", "remote_addr", c.ip, "account", account, "reason", "successful authentication")
}

func (l *Limiter) log(message string, args ...any) {
	if l.logger != nil {
		l.logger.Info(message, args...)
	}
}

func (l *Limiter) activeState(states map[string]failureState, key string, now time.Time) (failureState, bool) {
	if key == "" {
		return failureState{}, false
	}
	state, ok := states[key]
	if !ok {
		return failureState{}, false
	}
	if now.Sub(state.lastFailure) >= l.config.FailureWindow {
		delete(states, key)
		return failureState{}, false
	}
	return state, true
}

func (l *Limiter) recordFailure(states map[string]failureState, key string, maxFailures int, now time.Time) failureState {
	if key == "" {
		return failureState{}
	}
	state, ok := l.activeState(states, key, now)
	if !ok {
		state.lastFailure = now
	}
	state.failures++
	state.lastFailure = now
	backoff := l.config.BackoffBase
	if state.failures >= maxFailures {
		backoff = l.config.BackoffMax
	} else {
		for attempt := 1; attempt < state.failures; attempt++ {
			backoff *= 2
			if backoff >= l.config.BackoffMax {
				backoff = l.config.BackoffMax
				break
			}
		}
	}
	state.blockedUntil = now.Add(backoff)
	states[key] = state
	return state
}

func (l *Limiter) responseDelay(now time.Time, states ...failureState) time.Duration {
	delay := time.Duration(0)
	for _, state := range states {
		if remaining := state.blockedUntil.Sub(now); remaining > delay {
			delay = remaining
		}
	}
	if delay > l.config.ResponseDelayMax {
		return l.config.ResponseDelayMax
	}
	return delay
}

func normalizeAccount(account string) string {
	return strings.ToLower(strings.TrimSpace(account))
}

func normalizeIP(remoteAddr string) string {
	remoteAddr = strings.TrimSpace(remoteAddr)
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	return remoteAddr
}
