// Command mymail runs the combined SMTP and IMAP daemon.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/mail"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"

	"mymail/auth"
	"mymail/config"
	"mymail/imap"
	"mymail/logging"
	"mymail/maildir"
	"mymail/plugins"
	"mymail/smtp"
)

var (
	version = "devel"
	builtOn = "unknown"
)

type configLogUser struct {
	Mailbox           string   `json:"mailbox,omitempty"`
	Aliases           []string `json:"aliases,omitempty"`
	HasPassword       bool     `json:"has_password"`
	HasPasswordSHA256 bool     `json:"has_password_sha256"`
}

func configLogUsers(users map[string]config.User) map[string]configLogUser {
	loggedUsers := make(map[string]configLogUser, len(users))
	for username, user := range users {
		loggedUsers[username] = configLogUser{
			Mailbox:           user.Mailbox,
			Aliases:           user.Aliases,
			HasPassword:       user.Password != "",
			HasPasswordSHA256: user.PasswordSHA256 != "",
		}
	}
	return loggedUsers
}

func logConfigUsers(logger *slog.Logger, users map[string]config.User) {
	loggedUsers := configLogUsers(users)
	usernames := make([]string, 0, len(loggedUsers))
	for username := range loggedUsers {
		usernames = append(usernames, username)
	}
	sort.Strings(usernames)
	for _, username := range usernames {
		user := loggedUsers[username]
		logger.Info("configuration user",
			"username", username,
			"mailbox", user.Mailbox,
			"aliases", user.Aliases,
			"has_password", user.HasPassword,
			"has_password_sha256", user.HasPasswordSHA256,
		)
	}
}

func main() {
	configPath := flag.String("config", "/etc/mymail/config.yaml", "path to the YAML configuration")
	showVersion := flag.Bool("version", false, "print the MyMail version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}

	asyncHandler := logging.NewAsyncHandler(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}), logging.DefaultQueueSize)
	defer asyncHandler.Close()
	logger := slog.New(asyncHandler)
	logger.Info("daemon started", "version", version, "builtOn", builtOn)
	fatal := func(message string, args ...any) {
		logger.Error(message, args...)
		asyncHandler.Close()
		os.Exit(1)
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		fatal("configuration failed", "error", err)
	}
	logger.Info("configuration loaded", "path", *configPath)
	logger.Info("configuration listeners",
		"smtp_listen", cfg.SMTPListen,
		"smtp_tls_listen", cfg.SMTPTLSListen,
		"imap_listen", cfg.IMAPListen,
		"imap_tls_listen", cfg.IMAPTLSListen,
	)
	logger.Info("configuration TLS",
		"tls_cert_file", cfg.TLSCertFile,
		"tls_key_file", cfg.TLSKeyFile,
		"smtp_require_starttls", cfg.SMTPRequireSTARTTLS,
		"imap_require_starttls", cfg.IMAPRequireSTARTTLS,
	)
	logger.Info("configuration storage",
		"maildir_root", cfg.MaildirRoot,
		"hostname", cfg.Hostname,
	)
	logConfigUsers(logger, cfg.Users)
	var tlsConfig *tls.Config
	if cfg.TLSCertFile != "" || cfg.TLSKeyFile != "" {
		certificate, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			fatal("TLS certificate initialization failed", "error", err)
		}
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{certificate},
			MinVersion:   tls.VersionTLS12,
		}
	}
	store, err := maildir.New(cfg.MaildirRoot)
	if err != nil {
		fatal("maildir initialization failed", "error", err)
	}
	mailboxes := make(map[string]bool)
	for username := range cfg.Users {
		mailbox, ok := cfg.Resolve(username)
		if !ok {
			continue
		}
		if !mailboxes[mailbox] {
			if err := store.Ensure(mailbox); err != nil {
				fatal("mailbox initialization failed", "user", username, "error", err)
			}
			mailboxes[mailbox] = true
		}
	}

	resolve := func(address string) (string, bool) {
		address = strings.TrimSpace(address)
		if parsed, parseErr := mail.ParseAddress(address); parseErr == nil {
			address = parsed.Address
		}
		if mailbox, ok := cfg.Resolve(address); ok {
			return mailbox, true
		}
		if at := strings.IndexByte(address, '@'); at > 0 {
			return cfg.Resolve(address[:at])
		}
		return "", false
	}
	localDomain := func(domain string) bool {
		return cfg.IsLocalDomain(domain)
	}
	authenticate := func(username, password string) bool {
		if cfg.Authenticate(username, password) {
			return true
		}
		if at := strings.IndexByte(username, '@'); at > 0 {
			return cfg.Authenticate(username[:at], password)
		}
		return false
	}

	processors := plugins.New()
	authConfig := auth.DefaultConfig()
	authConfig.Logger = logger
	authLimiter := auth.NewLimiter(authConfig)
	newSMTPServer := func(addr string, config *tls.Config) *smtp.Server {
		return &smtp.Server{
			Addr: addr, TLSConfig: config, StartTLSConfig: tlsConfig, RequireSTARTTLS: cfg.SMTPRequireSTARTTLS, Hostname: cfg.Hostname, Store: store,
			Processors: processors, Resolve: resolve, LocalDomain: localDomain, Authenticate: authenticate, AuthLimiter: authLimiter, Logger: logger,
		}
	}
	newIMAPServer := func(addr string, config *tls.Config) *imap.Server {
		return &imap.Server{
			Addr: addr, TLSConfig: config, StartTLSConfig: tlsConfig, RequireSTARTTLS: cfg.IMAPRequireSTARTTLS, Hostname: cfg.Hostname, Store: store,
			Resolve: func(username string) (string, bool) {
				if mailbox, ok := cfg.Resolve(username); ok {
					return mailbox, true
				}
				if at := strings.IndexByte(username, '@'); at > 0 {
					return cfg.Resolve(username[:at])
				}
				return "", false
			},
			Authenticate: authenticate, AuthLimiter: authLimiter, Logger: logger,
		}
	}
	smtpServers := []*smtp.Server{newSMTPServer(cfg.SMTPListen, nil)}
	if cfg.SMTPTLSListen != "" {
		smtpServers = append(smtpServers, newSMTPServer(cfg.SMTPTLSListen, tlsConfig.Clone()))
	}
	imapServers := []*imap.Server{newIMAPServer(cfg.IMAPListen, nil)}
	if cfg.IMAPTLSListen != "" {
		imapServers = append(imapServers, newIMAPServer(cfg.IMAPTLSListen, tlsConfig.Clone()))
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	listenerCount := len(smtpServers) + len(imapServers)
	errorsCh := make(chan error, listenerCount)
	for _, server := range smtpServers {
		go func() { errorsCh <- server.ListenAndServe(ctx) }()
	}
	for _, server := range imapServers {
		go func() { errorsCh <- server.ListenAndServe(ctx) }()
	}
	var firstErr error
	for range listenerCount {
		if err := <-errorsCh; err != nil && !errors.Is(err, context.Canceled) && firstErr == nil {
			firstErr = err
			cancel()
		}
	}
	if firstErr != nil {
		fatal("daemon stopped with error", "error", firstErr)
	}
	logger.Info("daemon stopped")
}
