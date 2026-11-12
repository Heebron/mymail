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
	"mymail/split"
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
	HasPasswordHash   bool     `json:"has_password_hash"`
}

func configLogUsers(users map[string]config.User) map[string]configLogUser {
	loggedUsers := make(map[string]configLogUser, len(users))
	for username, user := range users {
		loggedUsers[username] = configLogUser{
			Mailbox:           user.Mailbox,
			Aliases:           user.Aliases,
			HasPassword:       user.Password != "",
			HasPasswordSHA256: user.PasswordSHA256 != "",
			HasPasswordHash:   user.PasswordHash != "",
		}
	}
	return loggedUsers
}

func logSHA256PasswordWarnings(logger *slog.Logger, users map[string]config.User) {
	usernames := make([]string, 0, len(users))
	for username, user := range users {
		if user.PasswordSHA256 != "" {
			usernames = append(usernames, username)
		}
	}
	sort.Strings(usernames)
	for _, username := range usernames {
		logger.Warn("configuration user uses unsalted SHA-256 password hash; migrate to password_hash", "username", username)
	}
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
			"has_password_hash", user.HasPasswordHash,
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

func loadSplitTLSConfig(cfg *config.Config, logger *slog.Logger) (*tls.Config, error) {
	certFile, keyFile := cfg.SplitCertificateFiles()
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load split TLS certificate: %w", err)
	}
	if certFile != cfg.TLSCertFile || keyFile != cfg.TLSKeyFile {
		if _, _, err := logTLSCertificate(logger, &certificate, certFile); err != nil {
			return nil, fmt.Errorf("log split TLS certificate: %w", err)
		}
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
	}
	if cfg.SplitCACertFile != "" {
		caData, err := os.ReadFile(cfg.SplitCACertFile)
		if err != nil {
			return nil, fmt.Errorf("read split CA certificate: %w", err)
		}
		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(caData) {
			return nil, errors.New("parse split CA certificate: no certificates found")
		}
		tlsConfig.ClientCAs = caPool
		tlsConfig.RootCAs = caPool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return tlsConfig, nil
}

func registerConfiguredPlugins(processors *plugins.Chain, configured []config.PluginConfig, logger *slog.Logger) error {
	if processors == nil {
		return errors.New("nil processor chain")
	}
	for _, pluginConfig := range configured {
		var processor plugins.Processor
		switch pluginConfig.Name {
		case "spamd":
			processor = plugins.NewSpamdClient("")
		case "dmarc":
			processor = plugins.NewDMARCReportProcessor(logger)
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
	splitEnabled := cfg.SplitMode == "on"
	// In remote-only split mode, log only what is relevant to that role.
	isRemoteOnly := splitEnabled && cfg.IsSplitRemote() && !cfg.IsSplitLocal()

	logger.Info("configuration listeners",
		"smtp_listen", cfg.SMTPListen,
		"smtp_cleartext_listen", cfg.SMTPCleartextListen,
		"smtp_tls_listen", cfg.SMTPTLSListen,
	)
	relayNetwork := cfg.SMTPRelayNetwork
	if relayNetwork == "" {
		relayNetwork = "tcp"
	}
	logger.Info("configuration SMTP relay", "hostname", cfg.Hostname, "relay_network", relayNetwork)
	if !isRemoteOnly {
		logger.Info("configuration IMAP listeners",
			"imap_listen", cfg.IMAPListen,
			"imap_tls_listen", cfg.IMAPTLSListen,
		)
	}
	logger.Info("configuration TLS",
		"tls_cert_file", cfg.TLSCertFile,
		"tls_key_file", cfg.TLSKeyFile,
	)
	if !isRemoteOnly {
		logger.Info("configuration IMAP TLS",
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
		logSHA256PasswordWarnings(logger, cfg.Users)
		logConfigUsers(logger, cfg.Users)
	}

	// Split mode logging.
	splitModeLabel := "off"
	if splitEnabled {
		splitTLSCertFile, _ := cfg.SplitCertificateFiles()
		if cfg.IsSplitRemote() && cfg.IsSplitLocal() {
			splitModeLabel = "local,remote"
		} else if cfg.IsSplitRemote() {
			splitModeLabel = "remote"
		} else if cfg.IsSplitLocal() {
			splitModeLabel = "local"
		}
		if cfg.IsSplitRemote() && cfg.IsSplitLocal() {
			logger.Info("configuration split mode",
				"mode", splitModeLabel,
				"listen", cfg.SplitListen,
				"connect", cfg.SplitConnect,
				"connect_ip", cfg.SplitConnectIP,
				"tls_cert_file", splitTLSCertFile,
				"insecure_skip_verify", cfg.SplitInsecureSkipVerify,
				"ignore_server_name", cfg.SplitIgnoreServerName,
			)
		} else if cfg.IsSplitRemote() {
			logger.Info("configuration split mode",
				"mode", splitModeLabel,
				"listen", cfg.SplitListen,
				"tls_cert_file", splitTLSCertFile,
			)
		} else if cfg.IsSplitLocal() {
			logger.Info("configuration split mode",
				"mode", splitModeLabel,
				"connect", cfg.SplitConnect,
				"connect_ip", cfg.SplitConnectIP,
				"tls_cert_file", splitTLSCertFile,
				"insecure_skip_verify", cfg.SplitInsecureSkipVerify,
				"ignore_server_name", cfg.SplitIgnoreServerName,
			)
		}
	}

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
	// A remote-only instance serves the SMTP certificate sent by the local over
	// the split link. A configured tls_cert_file is used until one arrives.
	var peerCertificates *peerCertificateStore
	if isRemoteOnly {
		peerCertificates = newPeerCertificateStore(cfg.Hostname, logger)
		if tlsConfig != nil {
			peerCertificates.SetCertificate(&tlsConfig.Certificates[0])
			logger.Info("SMTP TLS certificate from tls_cert_file will be replaced when the split local sends one")
		} else {
			logger.Info("SMTP TLS waiting for a certificate from the split local")
		}
		tlsConfig = &tls.Config{
			GetCertificate: peerCertificates.GetCertificate,
			MinVersion:     tls.VersionTLS12,
		}
	}

	var splitTLSConfig *tls.Config
	if splitEnabled {
		splitTLSConfig, err = loadSplitTLSConfig(&cfg, logger)
		if err != nil {
			fatal("split TLS certificate initialization failed", "error", err)
		}
	}
	var store *maildir.Store
	if !splitEnabled || !cfg.IsSplitRemote() {
		var err error
		store, err = maildir.New(cfg.MaildirRoot)
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
	if err := registerConfiguredPlugins(processors, cfg.Plugins, logger); err != nil {
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
	if !isRemoteOnly {
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
	}
	// --- Split mode: set up the TLS link between local and remote sides. ---
	var splitClient *split.Client
	if splitEnabled && cfg.IsSplitLocal() {
		clientTLSConfig := splitTLSConfig.Clone()
		if cfg.SplitInsecureSkipVerify {
			clientTLSConfig.InsecureSkipVerify = true
			logger.Warn("split remote certificate verification disabled", "address", cfg.SplitConnect)
		}
		if cfg.SplitIgnoreServerName && !cfg.SplitInsecureSkipVerify {
			logger.Warn("split remote hostname verification disabled; certificate chain still verified", "address", cfg.SplitConnect)
		}
		splitClient = &split.Client{
			Addr:             cfg.SplitConnect,
			ConnectIP:        cfg.SplitConnectIP,
			TLSConfig:        clientTLSConfig,
			IgnoreServerName: cfg.SplitIgnoreServerName,
			Logger:           logger,
			Version:          version,
		}
	}

	// Remote-side mailbox cache: populated dynamically when the local connects.
	// The remote uses this to decide which incoming SMTP recipients should be
	// forwarded back to the local side.
	var remoteMailboxesMu sync.Mutex
	var remoteMailboxes map[string]bool // address -> true

	newSMTPServer := func(addr string, implicitTLSConfig, startTLSConfig *tls.Config, requireSTARTTLS, requireTLSForAuth bool) *smtp.Server {
		srv := &smtp.Server{
			Addr: addr, TLSConfig: implicitTLSConfig, StartTLSConfig: startTLSConfig, RequireSTARTTLS: requireSTARTTLS, RequireTLSForAuth: requireTLSForAuth, Hostname: cfg.Hostname, RelayNetwork: cfg.SMTPRelayNetwork, Store: store,
			Processors: processors, Resolve: resolve, LocalDomain: localDomain, DKIMSigner: dkimSigner, Authenticate: authenticate, AuthLimiter: authLimiter, Logger: logger,
		}
		if peerCertificates != nil {
			srv.TLSAvailable = peerCertificates.Available
		}
		// Remote role: resolve uses the dynamic mailbox cache from the local side.
		if splitEnabled && cfg.IsSplitRemote() {
			srv.Resolve = func(address string) (string, bool) {
				remoteMailboxesMu.Lock()
				defer remoteMailboxesMu.Unlock()
				return resolveRemoteMailbox(remoteMailboxes, address)
			}
			srv.LocalDomain = func(domain string) bool {
				// Remote considers a domain local if any cached mailbox belongs to it.
				remoteMailboxesMu.Lock()
				defer remoteMailboxesMu.Unlock()
				if remoteMailboxes == nil {
					return false
				}
				domain = strings.ToLower(strings.TrimSuffix(domain, "."))
				for addr := range remoteMailboxes {
					if at := strings.IndexByte(addr, '@'); at > 0 {
						if strings.TrimSuffix(addr[at+1:], ".") == domain {
							return true
						}
					}
				}
				return false
			}
		}
		return srv
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
	smtpServers := []*smtp.Server{newSMTPServer(cfg.SMTPListen, nil, tlsConfig, true, false)}
	if cfg.SMTPCleartextListen != "" {
		smtpServers = append(smtpServers, newSMTPServer(cfg.SMTPCleartextListen, nil, tlsConfig, false, true))
	}
	if cfg.SMTPTLSListen != "" {
		smtpServers = append(smtpServers, newSMTPServer(cfg.SMTPTLSListen, tlsConfig.Clone(), nil, false, false))
	}
	if splitClient != nil {
		splitClient.Deliver = func(ctx context.Context, req split.SendRequest) error {
			return smtpServers[0].DeliverLocal(ctx, req.From, req.Recipient, req.Data)
		}
		splitClient.Submit = func(ctx context.Context, req split.SendRequest) error {
			return smtpServers[0].Submit(ctx, req.From, req.Recipient, req.Data)
		}
		splitClient.Authenticate = func(ctx context.Context, username, password string) (bool, error) {
			return authenticate(username, password), nil
		}
	}

	// Split server: only created when this instance listens for split connections
	// (remote role). The local role only connects out, it doesn't listen.
	var splitSrv *split.Server
	if splitEnabled && cfg.IsSplitRemote() {
		// Build the split server Deliver callback.
		// Remote side: receives mail from local for external SMTP relay.
		splitDeliver := func(ctx context.Context, req split.SendRequest) error {
			server := smtpServers[0]
			return server.Relay(ctx, req.From, req.Recipient, req.Data)
		}
		splitSrv = &split.Server{
			Addr:             cfg.SplitListen,
			TLSConfig:        splitTLSConfig.Clone(),
			Logger:           logger,
			Deliver:          splitDeliver,
			ExpectedClientDN: cfg.SplitLocalClientDN,
			Version:          version,
		}
		if peerCertificates != nil {
			splitSrv.OnTLSCertificate = peerCertificates.Set
		}
	}

	// Wire split forwarding into SMTP servers.
	if splitEnabled && cfg.IsSplitLocal() {
		for _, srv := range smtpServers {
			// Local side: forward non-local mail to remote when connected;
			// fall back to direct MX relay when the remote is not connected.
			srv.SplitForward = func(ctx context.Context, from, recipient string, data []byte, fallback func(context.Context, string, string, []byte) error) error {
				if splitClient.IsConnected() {
					logger.Info("split forwarding to remote", "sender", from, "recipient", recipient, "message_id", smtp.MessageID(data))
					data = srv.SignDKIM(from, recipient, data)
					return splitClient.Send(ctx, split.SendRequest{
						From:      from,
						Recipient: recipient,
						Data:      data,
					})
				}
				logger.Info("split remote not connected, falling back to MX relay", "recipient", recipient)
				return fallback(ctx, from, recipient, data)
			}
		}
	} else if splitEnabled && cfg.IsSplitRemote() {
		for _, srv := range smtpServers {
			// Remote side: forward mail for local mailboxes back to local
			// over the accepted split connection. External mail is submitted
			// through the local side so it is DKIM-signed before relay.
			srv.AuthenticateContext = func(ctx context.Context, username, password string) (bool, error) {
				authCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
				defer cancel()
				ok, err := splitSrv.Authenticate(authCtx, username, password)
				if errors.Is(err, split.ErrAuthRejected) {
					return false, nil
				}
				return ok, err
			}
			srv.SplitForward = func(ctx context.Context, from, recipient string, data []byte, fallback func(context.Context, string, string, []byte) error) error {
				if _, ok := srv.Resolve(recipient); !ok {
					submitCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
					defer cancel()
					return splitSrv.Submit(submitCtx, split.SendRequest{From: from, Recipient: recipient, Data: data})
				}
				return splitSrv.Send(ctx, split.SendRequest{From: from, Recipient: recipient, Data: data})
			}
		}
	}

	// Remote-side split callbacks: manage mailbox cache and SMTP forwarding.
	if splitEnabled && cfg.IsSplitRemote() {
		splitSrv.OnMailboxList = func(addresses []string) {
			remoteMailboxesMu.Lock()
			remoteMailboxes = make(map[string]bool, len(addresses))
			for _, addr := range addresses {
				remoteMailboxes[strings.ToLower(strings.TrimSpace(addr))] = true
			}
			remoteMailboxesMu.Unlock()
			logger.Info("remote mailbox cache refreshed", "count", len(addresses))
		}
		splitSrv.OnConnected = func() {
			logger.Info("local connected to remote, resuming SMTP")
		}
		splitSrv.OnDisconnected = func() {
			remoteMailboxesMu.Lock()
			remoteMailboxes = nil
			remoteMailboxesMu.Unlock()
			logger.Info("local disconnected from remote, clearing mailbox cache")
		}
	}

	// Local-side: after connecting, send the mailbox list to the remote.
	if splitEnabled && cfg.IsSplitLocal() {
		// Collect all local mailbox addresses (user + aliases).
		localMailboxAddresses := make([]string, 0, len(cfg.Users))
		for username, user := range cfg.Users {
			localMailboxAddresses = append(localMailboxAddresses, username)
			for _, alias := range user.Aliases {
				localMailboxAddresses = append(localMailboxAddresses, alias)
			}
		}
		// When the background reconnect loop establishes a connection, send the
		// mailbox list to the remote.
		splitClient.OnConnected = func() {
			logger.Info("split connected, sending mailbox list to remote")
			if err := splitClient.SendMailboxList(localMailboxAddresses); err != nil {
				logger.Error("split mailbox list send failed", "error", err)
			}
			// Send the SMTP certificate in the background so an older remote that
			// never answers cannot delay the reconnect loop.
			go func() {
				if err := sendSplitTLSCertificate(&cfg, splitClient.SendTLSCertificate, logger); err != nil {
					logger.Warn("split TLS certificate send failed; the remote must use its own tls_cert_file", "tls_cert_file", cfg.TLSCertFile, "error", err)
				}
			}()
		}
		splitClient.OnDisconnected = func() {
			logger.Info("split disconnected from remote")
		}
		// Start the background reconnect loop (retries every 10 seconds).
		splitClient.Start(ctx)
	}

	var imapServers []*imap.Server
	if !splitEnabled || !cfg.IsSplitRemote() {
		imapServers = []*imap.Server{newIMAPServer(cfg.IMAPListen, nil)}
		if cfg.IMAPTLSListen != "" {
			imapServers = append(imapServers, newIMAPServer(cfg.IMAPTLSListen, tlsConfig.Clone()))
		}
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
	if splitSrv != nil {
		listenerCount++ // split server
	}
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
	if splitEnabled && splitSrv != nil {
		serviceWG.Add(1)
		go func() {
			defer serviceWG.Done()
			errorsCh <- splitSrv.ListenAndServe(ctx)
		}()
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
		// Wait for the split client background goroutine to exit, with a timeout
		// so that a stuck dial or handshake does not hold up the entire shutdown.
		if splitClient != nil {
			doneCh := make(chan struct{})
			go func() {
				splitClient.Wait()
				close(doneCh)
			}()
			select {
			case <-doneCh:
				logger.Info("split client stopped")
			case <-time.After(5 * time.Second):
				logger.Warn("split client shutdown timed out, forcing exit")
			}
		}
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

func resolveRemoteMailbox(mailboxes map[string]bool, address string) (string, bool) {
	if mailboxes == nil {
		return "", false
	}
	address = strings.ToLower(strings.TrimSpace(address))
	if mailbox, ok := findRemoteMailbox(mailboxes, address); ok {
		return mailbox, true
	}
	if stripped, ok := config.StripTrainingPrefix(address); ok {
		return findRemoteMailbox(mailboxes, stripped)
	}
	return "", false
}

func findRemoteMailbox(mailboxes map[string]bool, address string) (string, bool) {
	if mailboxes[address] {
		return address, true
	}
	if at := strings.IndexByte(address, '@'); at > 0 {
		if mailboxes[address[:at]] {
			return address[:at], true
		}
	}
	return "", false
}
