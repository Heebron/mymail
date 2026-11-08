// Command mymail runs the combined SMTP and IMAP daemon.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/mail"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"mymail/auth"
	"mymail/config"
	"mymail/dkim"
	"mymail/health"
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

func logCleartextPasswordWarnings(logger *slog.Logger, users map[string]config.User) {
	usernames := make([]string, 0, len(users))
	for username, user := range users {
		if user.Password != "" {
			usernames = append(usernames, username)
		}
	}
	sort.Strings(usernames)
	for _, username := range usernames {
		logger.Warn("configuration user uses cleartext password", "username", username)
	}
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

func certificateSANs(cert *x509.Certificate) []string {
	if cert == nil {
		return []string{}
	}
	sans := make([]string, 0, len(cert.DNSNames)+len(cert.IPAddresses)+len(cert.EmailAddresses)+len(cert.URIs))
	for _, name := range cert.DNSNames {
		if trimmed := strings.TrimSpace(name); trimmed != "" {
			sans = append(sans, trimmed)
		}
	}
	for _, ip := range cert.IPAddresses {
		if len(ip) > 0 {
			sans = append(sans, ip.String())
		}
	}
	for _, email := range cert.EmailAddresses {
		if trimmed := strings.TrimSpace(email); trimmed != "" {
			sans = append(sans, trimmed)
		}
	}
	for _, uri := range cert.URIs {
		if uri != nil && uri.String() != "" {
			sans = append(sans, uri.String())
		}
	}
	return sans
}

const certExpiryWarningThreshold = 30 * 24 * time.Hour

func checkTLSCertificateExpiration(logger *slog.Logger, cert *x509.Certificate, certFile string, now time.Time) (bool, time.Duration) {
	if cert == nil {
		return false, 0
	}
	expiresIn := cert.NotAfter.Sub(now)
	if expiresIn <= certExpiryWarningThreshold {
		if logger != nil {
			daysRemaining := int(expiresIn / (24 * time.Hour))
			logger.Warn("TLS certificate expires soon",
				"tls_cert_file", certFile,
				"subject_dn", cert.Subject.String(),
				"not_after", cert.NotAfter.UTC().Format(time.RFC3339),
				"expires_in", expiresIn.Round(time.Second).String(),
				"days_remaining", daysRemaining,
			)
		}
		return true, expiresIn
	}
	return false, expiresIn
}

func logTLSCertificate(logger *slog.Logger, cert *tls.Certificate, certFile string) (string, []string, error) {
	if cert == nil || len(cert.Certificate) == 0 {
		return "", nil, errors.New("empty certificate chain")
	}
	if cert.Leaf == nil {
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return "", nil, err
		}
		cert.Leaf = leaf
	}
	subjectDN := cert.Leaf.Subject.String()
	sans := certificateSANs(cert.Leaf)
	if logger != nil {
		logger.Info("TLS certificate loaded",
			"tls_cert_file", certFile,
			"subject_dn", subjectDN,
			"subject_alt_names", sans,
			"not_after", cert.Leaf.NotAfter.UTC().Format(time.RFC3339),
		)
		checkTLSCertificateExpiration(logger, cert.Leaf, certFile, time.Now())
	}
	return subjectDN, sans, nil
}

func registerConfiguredPlugins(processors *plugins.Chain, configured []config.PluginConfig) error {
	if processors == nil {
		return errors.New("nil processor chain")
	}
	for _, pluginConfig := range configured {
		var processor plugins.Processor
		switch pluginConfig.Name {
		case "spamd":
			processor = plugins.NewSpamdClient("")
		default:
			return fmt.Errorf("unsupported plugin %q", pluginConfig.Name)
		}
		if err := processors.Add(processor); err != nil {
			return fmt.Errorf("register plugin %q: %w", pluginConfig.Name, err)
		}
	}
	return nil
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
		"smtp_cleartext_listen", cfg.SMTPCleartextListen,
		"imap_listen", cfg.IMAPListen,
		"imap_tls_listen", cfg.IMAPTLSListen,
	)
	logger.Info("configuration TLS",
		"tls_cert_file", cfg.TLSCertFile,
		"tls_key_file", cfg.TLSKeyFile,
		"smtp_require_starttls", cfg.SMTPRequireSTARTTLS,
		"imap_require_starttls", cfg.IMAPRequireSTARTTLS,
	)
	logger.Info("configuration authentication throttling",
		"max_attempts_per_connection", cfg.AuthThrottle.MaxAttemptsPerConnection,
		"max_failures_per_ip", cfg.AuthThrottle.MaxFailuresPerIP,
		"max_failures_per_account", cfg.AuthThrottle.MaxFailuresPerAccount,
		"backoff_base", cfg.AuthThrottle.BackoffBase,
		"backoff_max", cfg.AuthThrottle.BackoffMax,
		"response_delay_max", cfg.AuthThrottle.ResponseDelayMax,
		"failure_window", cfg.AuthThrottle.FailureWindow,
	)
	logger.Info("configuration storage",
		"maildir_root", cfg.MaildirRoot,
		"hostname", cfg.Hostname,
	)
	logger.Info("configuration DKIM",
		"domain", cfg.DKIM.Domain,
		"private_key", cfg.DKIM.PrivateKey,
		"public_key", cfg.DKIM.PublicKey,
		"selector", cfg.DKIM.Selector,
		"enabled", cfg.HasDKIM(),
	)
	logCleartextPasswordWarnings(logger, cfg.Users)
	logConfigUsers(logger, cfg.Users)
	var tlsConfig *tls.Config
	if cfg.TLSCertFile != "" || cfg.TLSKeyFile != "" {
		certificate, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			fatal("TLS certificate initialization failed", "error", err)
		}
		if _, _, err := logTLSCertificate(logger, &certificate, cfg.TLSCertFile); err != nil {
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
		return cfg.Authenticate(username, password)
	}

	processors := plugins.New()
	processors.SetLogger(logger)
	if err := registerConfiguredPlugins(processors, cfg.Plugins); err != nil {
		fatal("plugin registration failed", "error", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	shutdownSignals := make(chan os.Signal, 1)
	signal.Notify(shutdownSignals, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(shutdownSignals)
	defer cancel()
	go func() {
		select {
		case shutdownSignal := <-shutdownSignals:
			logger.Info("shutdown signal received", "signal", shutdownSignal.String())
			cancel()
		case <-ctx.Done():
		}
	}()
	processors.Initialize(ctx, cfg.Plugins)
	authConfig := cfg.AuthThrottle
	authConfig.Logger = logger
	authLimiter := auth.NewLimiter(authConfig)
	var dkimSigner func(msg []byte) ([]byte, error)
	if cfg.HasDKIM() {
		signer, err := dkim.NewSigner(cfg.DKIM.Domain, cfg.DKIM.Selector, cfg.DKIM.PrivateKey, cfg.DKIM.PublicKey)
		if err != nil {
			fatal("DKIM initialization failed", "error", err)
		}
		signer.SetLogger(logger)
		dkimSigner = signer.Sign
		logger.Info("DKIM key pair validated", "domain", cfg.DKIM.Domain, "selector", signer.Selector())
		logger.Info("DKIM signing enabled", "domain", cfg.DKIM.Domain, "selector", signer.Selector())
	} else {
		logger.Info("DKIM signing disabled")
	}
	newSMTPServer := func(addr string, startTLSConfig *tls.Config, requireSTARTTLS bool) *smtp.Server {
		return &smtp.Server{
			Addr: addr, StartTLSConfig: startTLSConfig, RequireSTARTTLS: requireSTARTTLS, Hostname: cfg.Hostname, Store: store,
			Processors: processors, Resolve: resolve, LocalDomain: localDomain, DKIMSigner: dkimSigner, Authenticate: authenticate, AuthLimiter: authLimiter, Logger: logger,
		}
	}
	newIMAPServer := func(addr string, config *tls.Config) *imap.Server {
		return &imap.Server{
			Addr: addr, TLSConfig: config, StartTLSConfig: tlsConfig, RequireSTARTTLS: cfg.IMAPRequireSTARTTLS, Hostname: cfg.Hostname, Version: version, Store: store,
			Resolve: func(username string) (string, bool) {
				return cfg.Resolve(username)
			},
			Authenticate: authenticate, AuthLimiter: authLimiter, Logger: logger,
		}
	}
	smtpServers := []*smtp.Server{newSMTPServer(cfg.SMTPListen, tlsConfig, cfg.SMTPRequireSTARTTLS)}
	if cfg.SMTPCleartextListen != "" {
		smtpServers = append(smtpServers, newSMTPServer(cfg.SMTPCleartextListen, nil, false))
	}
	imapServers := []*imap.Server{newIMAPServer(cfg.IMAPListen, nil)}
	if cfg.IMAPTLSListen != "" {
		imapServers = append(imapServers, newIMAPServer(cfg.IMAPTLSListen, tlsConfig.Clone()))
	}

	status := health.New(len(smtpServers), len(imapServers))
	for _, server := range smtpServers {
		server.OnReady = status.MarkSMTPReady
	}
	for _, server := range imapServers {
		server.OnReady = status.MarkIMAPReady
	}
	status.PluginsInitialized()
	healthServer := &http.Server{Addr: cfg.HealthListen, Handler: status}
	healthListener, err := net.Listen("tcp", cfg.HealthListen)
	if err != nil {
		fatal("health listener failed", "address", cfg.HealthListen, "error", err)
	}
	listenerCount := len(smtpServers) + len(imapServers) + 1
	errorsCh := make(chan error, listenerCount)
	var serviceWG sync.WaitGroup
	for _, server := range smtpServers {
		serviceWG.Add(1)
		go func(server *smtp.Server) {
			defer serviceWG.Done()
			errorsCh <- server.ListenAndServe(ctx)
		}(server)
	}
	for _, server := range imapServers {
		serviceWG.Add(1)
		go func(server *imap.Server) {
			defer serviceWG.Done()
			errorsCh <- server.ListenAndServe(ctx)
		}(server)
	}
	go func() {
		if err := healthServer.Serve(healthListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errorsCh <- err
			return
		}
		errorsCh <- nil
	}()
	go func() {
		<-ctx.Done()
		logger.Info("shutdown started")
		status.BeginShutdown()
		logger.Info("shutdown readiness disabled")
		serviceWG.Wait()
		logger.Info("protocol servers stopped")
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		logger.Info("health server shutdown started", "timeout", 5*time.Second)
		if err := healthServer.Shutdown(shutdownCtx); err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				logger.Warn("health server shutdown timed out", "timeout", 5*time.Second, "error", err)
			} else {
				logger.Error("health server shutdown failed", "error", err)
			}
		} else {
			logger.Info("health server stopped")
		}
	}()
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
