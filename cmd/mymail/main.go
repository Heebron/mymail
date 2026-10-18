// Command mymail runs the combined SMTP and IMAP daemon.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"log/slog"
	"net/mail"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"mymail/config"
	"mymail/imap"
	"mymail/maildir"
	"mymail/plugins"
	"mymail/smtp"
)

func main() {
	configPath := flag.String("config", "/etc/mymail/config.yaml", "path to the YAML configuration")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Error("configuration failed", "error", err)
		os.Exit(1)
	}
	var tlsConfig *tls.Config
	if cfg.SMTPTLSListen != "" || cfg.IMAPTLSListen != "" {
		certificate, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			logger.Error("TLS certificate initialization failed", "error", err)
			os.Exit(1)
		}
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{certificate},
			MinVersion:   tls.VersionTLS12,
		}
	}
	store, err := maildir.New(cfg.MaildirRoot)
	if err != nil {
		logger.Error("maildir initialization failed", "error", err)
		os.Exit(1)
	}
	mailboxes := make(map[string]bool)
	for username := range cfg.Users {
		mailbox, ok := cfg.Resolve(username)
		if !ok {
			continue
		}
		if !mailboxes[mailbox] {
			if err := store.Ensure(mailbox); err != nil {
				logger.Error("mailbox initialization failed", "user", username, "error", err)
				os.Exit(1)
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
	newSMTPServer := func(addr string, config *tls.Config) *smtp.Server {
		return &smtp.Server{
			Addr: addr, TLSConfig: config, Hostname: cfg.Hostname, Store: store,
			Processors: processors, Resolve: resolve, LocalDomain: localDomain, Authenticate: authenticate, Logger: logger,
		}
	}
	newIMAPServer := func(addr string, config *tls.Config) *imap.Server {
		return &imap.Server{
			Addr: addr, TLSConfig: config, Hostname: cfg.Hostname, Store: store,
			Resolve: func(username string) (string, bool) {
				if mailbox, ok := cfg.Resolve(username); ok {
					return mailbox, true
				}
				if at := strings.IndexByte(username, '@'); at > 0 {
					return cfg.Resolve(username[:at])
				}
				return "", false
			},
			Authenticate: authenticate, Logger: logger,
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
		logger.Error("daemon stopped with error", "error", firstErr)
		os.Exit(1)
	}
	logger.Info("daemon stopped")
}
