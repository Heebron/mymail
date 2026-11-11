// Package config loads the daemon's YAML configuration.
package config

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
	"mymail/auth"
	"mymail/dkim"
	"mymail/plugins"
)

// User contains one login account, its mailbox mapping, and aliases.
type User struct {
	// Password is a cleartext password. Prefer PasswordHash in deployments.
	Password string `yaml:"password,omitempty"`
	// PasswordSHA256 is a lowercase hexadecimal SHA-256 password hash.
	PasswordSHA256 string `yaml:"password_sha256,omitempty"`
	// PasswordHash is a bcrypt password hash.
	PasswordHash string `yaml:"password_hash,omitempty"`
	// Mailbox is the directory name below maildir_root. It defaults to the
	// configured username.
	Mailbox string `yaml:"mailbox,omitempty"`
	// Aliases route additional recipient addresses to this user's mailbox.
	Aliases []string `yaml:"aliases,omitempty"`
}

// PluginConfig names one configured plugin and its optional initialization
// settings.
type PluginConfig = plugins.PluginConfig

// DKIMConfig contains configuration settings for outbound DKIM message signing.
type DKIMConfig struct {
	// Domain is the domain used in DKIM signatures for outgoing email.
	Domain string `yaml:"domain,omitempty"`
	// PrivateKey is the private key (or file path) used to sign outgoing email.
	PrivateKey string `yaml:"private_key,omitempty"`
	// PublicKey is the public key (or file path / DNS TXT record) for DKIM configuration.
	PublicKey string `yaml:"public_key,omitempty"`
	// Selector is the selector name used in DKIM signatures.
	Selector string `yaml:"selector,omitempty"`
	// PrivateKeyFile is an alias for private_key.
	PrivateKeyFile string `yaml:"private_key_file,omitempty"`
	// PublicKeyFile is an alias for public_key.
	PublicKeyFile string `yaml:"public_key_file,omitempty"`
}

// HasDKIM reports whether all four required DKIM configuration items
// (domain, private key, public key, and selector) are present.
func (d DKIMConfig) HasDKIM() bool {
	return strings.TrimSpace(d.Domain) != "" &&
		strings.TrimSpace(d.PrivateKey) != "" &&
		strings.TrimSpace(d.PublicKey) != "" &&
		strings.TrimSpace(d.Selector) != ""
}

// Config is the validated YAML configuration for the MyMail daemon.
type Config struct {
	// SMTPListen is the SMTP submission listener address. It always requires
	// STARTTLS before authentication or message submission.
	SMTPListen string `yaml:"smtp_listen"`
	// SMTPCleartextListen is the optional cleartext SMTP listener address.
	SMTPCleartextListen string `yaml:"smtp_cleartext_listen,omitempty"`
	// SMTPTLSListen is the optional implicit-TLS SMTP listener address.
	SMTPTLSListen string `yaml:"smtp_tls_listen,omitempty"`
	// SMTPRelayNetwork selects the network used for outbound MX connections.
	SMTPRelayNetwork string `yaml:"smtp_relay_network,omitempty"`
	// IMAPListen is the cleartext IMAP listener address, optionally with
	// STARTTLS.
	IMAPListen string `yaml:"imap_listen"`
	// IMAPTLSListen is the optional implicit-TLS IMAP listener address.
	IMAPTLSListen string `yaml:"imap_tls_listen,omitempty"`
	// IMAPRequireSTARTTLS requires TLS before IMAP authentication.
	IMAPRequireSTARTTLS bool `yaml:"imap_require_starttls,omitempty"`
	// TLSCertFile and TLSKeyFile identify the certificate pair used by TLS
	// listeners.
	TLSCertFile string `yaml:"tls_cert_file,omitempty"`
	TLSKeyFile  string `yaml:"tls_key_file,omitempty"`
	// AuthThrottle configures shared authentication limits.
	AuthThrottle auth.Config `yaml:"auth_throttle"`
	// MaildirRoot contains the per-user Maildir directories.
	MaildirRoot string `yaml:"maildir_root"`
	// Hostname is used in protocol greetings and outbound SMTP EHLO.
	Hostname string `yaml:"hostname"`
	// HealthListen is the address serving /healthz and /readyz.
	HealthListen string `yaml:"health_listen"`
	// DKIM configures outbound DKIM message signing.
	DKIM DKIMConfig `yaml:"dkim,omitempty"`
	// Plugins contains plugin names and their initialization settings.
	Plugins []PluginConfig `yaml:"plugins,omitempty"`
	// Users maps login addresses to mailbox and authentication settings.
	Users map[string]User `yaml:"users"`
	// SplitMode enables split operation when set to "on". In split mode the
	// daemon runs as either the "local" side (behind the ISP firewall, serving
	// IMAP) or the "remote" side (in cloud infrastructure, handling external
	// SMTP delivery). The two sides communicate over a TLS link.
	SplitMode string `yaml:"split_mode,omitempty"`
	// SplitListen is the TCP address the split TLS listener binds to. When set,
	// this instance acts as the "remote" side (accepts connections from the
	// local side). Either split_listen or split_connect is required when
	// split_mode is "on"; both can be set for full bidirectional operation.
	SplitListen string `yaml:"split_listen,omitempty"`
	// SplitTLSCertFile and SplitTLSKeyFile identify the certificate pair used
	// on the split link. When omitted, the main TLS certificate pair is used.
	SplitTLSCertFile string `yaml:"split_tls_cert_file,omitempty"`
	SplitTLSKeyFile  string `yaml:"split_tls_key_file,omitempty"`
	// SplitConnect is the TCP address of the peer split server. When set, this
	// instance acts as the "local" side (connects to the remote to forward
	// non-local mail). A local-only instance works normally even when the
	// remote is unreachable, falling back to direct MX relay.
	SplitConnect string `yaml:"split_connect,omitempty"`
	// SplitConnectIP overrides DNS resolution for the host in SplitConnect,
	// while SplitConnect's hostname remains the TLS server name.
	SplitConnectIP string `yaml:"split_connect_ip,omitempty"`
	// SplitCACertFile is the CA certificate file used to verify client
	// certificates accepted by the split listener and the peer's certificate on
	// the split link.
	SplitCACertFile string `yaml:"split_ca_cert_file,omitempty"`
	// SplitInsecureSkipVerify disables certificate verification for the remote
	// peer on the local side's outbound split connection.
	SplitInsecureSkipVerify bool `yaml:"split_insecure_skip_verify,omitempty"`
	// SplitIgnoreServerName skips only hostname verification for the remote
	// peer on the local side's outbound split connection. Certificate chain
	// verification remains enabled.
	SplitIgnoreServerName bool `yaml:"split_ignore_server_name,omitempty"`
	// SplitLocalClientDN is the expected X.509 subject DN of the local side's
	// client certificate. When set on the remote, the split connection is
	// rejected unless the connecting client's certificate subject matches
	// exactly. This provides an additional layer of authentication beyond
	// mutual TLS.
	SplitLocalClientDN string `yaml:"split_local_client_dn,omitempty"`
}

// Defaults returns the configuration defaults used before YAML values are
// applied.
func Defaults() Config {
	return Config{
		SMTPListen:          "0.0.0.0:587",
		SMTPCleartextListen: "0.0.0.0:25",
		IMAPListen:          "0.0.0.0:1143",
		AuthThrottle:        auth.DefaultConfig(),
		MaildirRoot:         "/var/lib/mymail",
		Hostname:            "localhost",
		HealthListen:        "0.0.0.0:8080",
		Plugins:             []PluginConfig{},
		Users:               make(map[string]User),
	}
}

// Load reads, expands, and validates a YAML configuration file.
func Load(path string) (Config, error) {
	config := Defaults()
	data, err := os.ReadFile(path)
	if err != nil {
		return config, fmt.Errorf("read config: %w", err)
	}
	if err := yaml.Unmarshal(data, &config); err != nil {
		return config, fmt.Errorf("parse config: %w", err)
	}
	config.expandEnvironment()
	if err := config.Validate(); err != nil {
		return config, err
	}
	return config, nil
}

func (c *Config) expandEnvironment() {
	c.SMTPListen = expandEnvironment(c.SMTPListen)
	c.SMTPCleartextListen = expandEnvironment(c.SMTPCleartextListen)
	c.SMTPTLSListen = expandEnvironment(c.SMTPTLSListen)
	c.SMTPRelayNetwork = expandEnvironment(c.SMTPRelayNetwork)
	c.IMAPListen = expandEnvironment(c.IMAPListen)
	c.IMAPTLSListen = expandEnvironment(c.IMAPTLSListen)
	c.TLSCertFile = expandEnvironment(c.TLSCertFile)
	c.TLSKeyFile = expandEnvironment(c.TLSKeyFile)
	c.SplitTLSCertFile = expandEnvironment(c.SplitTLSCertFile)
	c.SplitTLSKeyFile = expandEnvironment(c.SplitTLSKeyFile)
	c.MaildirRoot = expandEnvironment(c.MaildirRoot)
	c.Hostname = expandEnvironment(c.Hostname)
	c.HealthListen = expandEnvironment(c.HealthListen)
	c.DKIM.Domain = expandEnvironment(c.DKIM.Domain)
	c.DKIM.PrivateKey = expandEnvironment(c.DKIM.PrivateKey)
	c.DKIM.PublicKey = expandEnvironment(c.DKIM.PublicKey)
	c.DKIM.Selector = expandEnvironment(c.DKIM.Selector)
	c.DKIM.PrivateKeyFile = expandEnvironment(c.DKIM.PrivateKeyFile)
	c.DKIM.PublicKeyFile = expandEnvironment(c.DKIM.PublicKeyFile)
	if c.DKIM.PrivateKey == "" && c.DKIM.PrivateKeyFile != "" {
		c.DKIM.PrivateKey = c.DKIM.PrivateKeyFile
	}
	if c.DKIM.PublicKey == "" && c.DKIM.PublicKeyFile != "" {
		c.DKIM.PublicKey = c.DKIM.PublicKeyFile
	}
	c.SplitMode = expandEnvironment(c.SplitMode)
	c.SplitListen = expandEnvironment(c.SplitListen)
	c.SplitConnect = expandEnvironment(c.SplitConnect)
	c.SplitConnectIP = expandEnvironment(c.SplitConnectIP)
	c.SplitCACertFile = expandEnvironment(c.SplitCACertFile)
	c.SplitLocalClientDN = expandEnvironment(c.SplitLocalClientDN)
	for username, user := range c.Users {
		user.Password = expandEnvironment(user.Password)
		user.PasswordSHA256 = expandEnvironment(user.PasswordSHA256)
		user.PasswordHash = expandPasswordHashEnvironment(user.PasswordHash)
		user.Mailbox = expandEnvironment(user.Mailbox)
		for index, alias := range user.Aliases {
			user.Aliases[index] = expandEnvironment(alias)
		}
		c.Users[username] = user
	}
	for index := range c.Plugins {
		for key, value := range c.Plugins[index].Config {
			c.Plugins[index].Config[key] = expandEnvironment(value)
		}
	}
}

func expandEnvironment(value string) string {
	return os.Expand(value, func(key string) string {
		if expanded, ok := os.LookupEnv(key); ok {
			return expanded
		}
		return "${" + key + "}"
	})
}

func expandPasswordHashEnvironment(value string) string {
	if strings.HasPrefix(value, "$2a$") || strings.HasPrefix(value, "$2b$") || strings.HasPrefix(value, "$2y$") {
		return value
	}
	return expandEnvironment(value)
}

// HasDKIM reports whether all four required DKIM configuration items
// (domain, private key, public key, and selector) are present.
func (c *Config) HasDKIM() bool {
	return c.DKIM.HasDKIM()
}

// Validate checks listener, TLS, authentication, mailbox, and user settings.
func (c *Config) Validate() error {
	c.SMTPRelayNetwork = strings.ToLower(strings.TrimSpace(c.SMTPRelayNetwork))
	switch c.SMTPRelayNetwork {
	case "", "tcp", "tcp4", "tcp6":
	default:
		return errors.New("smtp_relay_network must be tcp, tcp4, or tcp6")
	}
	splitEnabled := strings.TrimSpace(c.SplitMode) == "on"
	remoteOnly := splitEnabled && c.IsSplitRemote() && !c.IsSplitLocal()
	if splitEnabled {
		if err := validateSplitConfig(c); err != nil {
			return err
		}
	}
	if !remoteOnly && strings.TrimSpace(c.SMTPTLSListen) != "" && (strings.TrimSpace(c.TLSCertFile) == "" || strings.TrimSpace(c.TLSKeyFile) == "") {
		return errors.New("smtp_tls_listen requires tls_cert_file and tls_key_file")
	}
	if splitEnabled && c.IsSplitRemote() {
		// Remote side does not need IMAP; only SMTP is required.
		if strings.TrimSpace(c.SMTPListen) == "" {
			return errors.New("smtp_listen is required for split remote role")
		}
	} else {
		if strings.TrimSpace(c.SMTPListen) == "" || strings.TrimSpace(c.IMAPListen) == "" {
			return errors.New("smtp_listen and imap_listen are required")
		}
	}
	hasTLSListener := strings.TrimSpace(c.IMAPTLSListen) != "" || strings.TrimSpace(c.SMTPTLSListen) != ""
	hasTLSFiles := strings.TrimSpace(c.TLSCertFile) != "" || strings.TrimSpace(c.TLSKeyFile) != ""
	hasTLSCertAndKey := strings.TrimSpace(c.TLSCertFile) != "" && strings.TrimSpace(c.TLSKeyFile) != ""
	if hasTLSFiles && !hasTLSCertAndKey {
		return errors.New("tls_cert_file and tls_key_file must be configured together")
	}
	if !remoteOnly && (hasTLSListener || c.IMAPRequireSTARTTLS) && !hasTLSCertAndKey {
		return errors.New("tls_cert_file and tls_key_file must be configured together")
	}
	if !remoteOnly && strings.TrimSpace(c.SMTPListen) != "" && !hasTLSCertAndKey {
		return errors.New("smtp_listen requires tls_cert_file and tls_key_file because STARTTLS is always required")
	}
	if strings.TrimSpace(c.Hostname) == "" {
		return errors.New("hostname is required")
	}
	if splitEnabled && c.IsSplitRemote() {
		if err := validateRemoteHostname(c.Hostname); err != nil {
			return err
		}
	}
	if !splitEnabled || !c.IsSplitRemote() {
		if strings.TrimSpace(c.MaildirRoot) == "" {
			return errors.New("maildir_root is required")
		}
	}
	hasDKIMDomain := strings.TrimSpace(c.DKIM.Domain) != ""
	hasDKIMPriv := strings.TrimSpace(c.DKIM.PrivateKey) != ""
	hasDKIMPub := strings.TrimSpace(c.DKIM.PublicKey) != ""
	hasDKIMSelector := strings.TrimSpace(c.DKIM.Selector) != ""
	hasAnyDKIM := hasDKIMDomain || hasDKIMPriv || hasDKIMPub || hasDKIMSelector
	hasAllDKIM := hasDKIMDomain && hasDKIMPriv && hasDKIMPub && hasDKIMSelector
	if splitEnabled && c.IsSplitRemote() && !c.IsSplitLocal() && hasAnyDKIM {
		return errors.New("remote role should not configure dkim; the local side signs outgoing mail")
	}
	if hasAnyDKIM && !hasAllDKIM {
		return errors.New("dkim domain, private_key, public_key, and selector must be configured together")
	}
	if c.HasDKIM() {
		privKey, err := dkim.LoadPrivateKey(c.DKIM.PrivateKey)
		if err != nil {
			return fmt.Errorf("dkim private key: %w", err)
		}
		pubKey, err := dkim.LoadPublicKey(c.DKIM.PublicKey)
		if err != nil {
			return fmt.Errorf("dkim public key: %w", err)
		}
		if err := dkim.ValidateKeyPair(privKey, pubKey); err != nil {
			return fmt.Errorf("dkim key pair: %w", err)
		}
	}
	if err := validateAuthThrottle(c.AuthThrottle); err != nil {
		return err
	}
	pluginNames := make(map[string]struct{}, len(c.Plugins))
	for index := range c.Plugins {
		plugin := &c.Plugins[index]
		name := strings.TrimSpace(plugin.Name)
		if name == "" {
			return fmt.Errorf("plugins[%d] has an empty plugin name", index)
		}
		plugin.Name = name
		if _, exists := pluginNames[name]; exists {
			return fmt.Errorf("plugin %q is configured more than once", name)
		}
		pluginNames[name] = struct{}{}
	}
	if splitEnabled && c.IsSplitRemote() && !c.IsSplitLocal() {
		if len(c.Users) > 0 {
			return errors.New("remote role should not define users; they are learned dynamically from the local side")
		}
	} else if len(c.Users) == 0 {
		return errors.New("at least one user is required")
	}
	primaryUsers := make(map[string]string, len(c.Users))
	for username := range c.Users {
		primaryUsers[strings.ToLower(strings.TrimSpace(username))] = username
	}
	aliases := make(map[string]string)
	mailboxOwners := make(map[string]string, len(c.Users))
	for username, user := range c.Users {
		if strings.TrimSpace(username) == "" || strings.ContainsAny(username, "/\\") {
			return fmt.Errorf("invalid username %q", username)
		}
		if user.Password == "" && user.PasswordSHA256 == "" && user.PasswordHash == "" {
			return fmt.Errorf("user %q has no password", username)
		}
		if user.PasswordHash != "" {
			if _, err := bcrypt.Cost([]byte(user.PasswordHash)); err != nil {
				return fmt.Errorf("user %q has invalid bcrypt password_hash: %w", username, err)
			}
		}
		if user.Mailbox != "" && strings.ContainsAny(user.Mailbox, "/\\\r\n") {
			return fmt.Errorf("user %q has invalid mailbox", username)
		}
		mailbox := strings.TrimSpace(mailboxFor(username, user))
		if owner, ok := mailboxOwners[mailbox]; ok {
			return fmt.Errorf("users %q and %q use the same mailbox %q", owner, username, mailbox)
		}
		mailboxOwners[mailbox] = username
		for _, alias := range user.Aliases {
			alias = strings.TrimSpace(alias)
			if alias == "" || strings.ContainsAny(alias, "/\\") {
				return fmt.Errorf("user %q has invalid alias %q", username, alias)
			}
			key := strings.ToLower(alias)
			if owner, ok := primaryUsers[key]; ok && owner != username {
				return fmt.Errorf("alias %q for user %q conflicts with user %q", alias, username, owner)
			}
			if owner, ok := aliases[key]; ok && owner != username {
				return fmt.Errorf("alias %q is assigned to both %q and %q", alias, owner, username)
			}
			aliases[key] = username
		}
	}
	return nil
}

func validateRemoteHostname(hostname string) error {
	name := strings.TrimSuffix(strings.TrimSpace(hostname), ".")
	lowerName := strings.ToLower(name)
	if lowerName == "localhost" || lowerName == "localhost.localdomain" || strings.HasSuffix(lowerName, ".localhost") || net.ParseIP(name) != nil || !strings.Contains(name, ".") {
		return fmt.Errorf("hostname must be the remote's public fully qualified domain name (got %q); it is sent in EHLO and should match the remote IP's reverse DNS", hostname)
	}
	return nil
}

// IsSplitRemote reports whether this instance acts as the remote side
// (accepts split connections). It is true when split_listen is configured.
func (c *Config) IsSplitRemote() bool {
	return strings.TrimSpace(c.SplitListen) != ""
}

// IsSplitLocal reports whether this instance acts as the local side
// (initiates split connections). It is true when split_connect is configured.
func (c *Config) IsSplitLocal() bool {
	return strings.TrimSpace(c.SplitConnect) != ""
}

// SplitCertificateFiles returns the split TLS certificate pair when set,
// otherwise it falls back to the main TLS certificate pair.
func (c *Config) SplitCertificateFiles() (certFile, keyFile string) {
	if strings.TrimSpace(c.SplitTLSCertFile) != "" || strings.TrimSpace(c.SplitTLSKeyFile) != "" {
		return c.SplitTLSCertFile, c.SplitTLSKeyFile
	}
	return c.TLSCertFile, c.TLSKeyFile
}

func validateSplitConfig(c *Config) error {
	listen := strings.TrimSpace(c.SplitListen)
	connect := strings.TrimSpace(c.SplitConnect)
	connectIP := strings.TrimSpace(c.SplitConnectIP)
	if c.SplitInsecureSkipVerify && connect == "" {
		return errors.New("split_insecure_skip_verify requires split_connect")
	}
	if c.SplitIgnoreServerName && connect == "" {
		return errors.New("split_ignore_server_name requires split_connect")
	}
	if connectIP != "" {
		if connect == "" {
			return errors.New("split_connect_ip requires split_connect")
		}
		host, port, err := net.SplitHostPort(connect)
		if err != nil || host == "" || port == "" {
			return errors.New("split_connect must be a hostname:port when split_connect_ip is set")
		}
		if net.ParseIP(host) != nil {
			return errors.New("split_connect must use a hostname, not an IP address, when split_connect_ip is set")
		}
		if (strings.HasPrefix(connectIP, "[") || strings.HasSuffix(connectIP, "]")) &&
			!(strings.HasPrefix(connectIP, "[") && strings.HasSuffix(connectIP, "]")) {
			return errors.New("split_connect_ip must be a valid IP address")
		}
		if strings.HasPrefix(connectIP, "[") {
			connectIP = strings.TrimSuffix(strings.TrimPrefix(connectIP, "["), "]")
		}
		if net.ParseIP(connectIP) == nil {
			return errors.New("split_connect_ip must be a valid IP address")
		}
	}
	if listen == "" && connect == "" {
		return errors.New("split_listen or split_connect is required when split_mode is 'on'")
	}
	if listen != "" && strings.TrimSpace(c.SplitCACertFile) == "" {
		return errors.New("split_listen requires split_ca_cert_file to authenticate local client certificates")
	}
	splitCertFile := strings.TrimSpace(c.SplitTLSCertFile)
	splitKeyFile := strings.TrimSpace(c.SplitTLSKeyFile)
	if (splitCertFile == "") != (splitKeyFile == "") {
		return errors.New("split_tls_cert_file and split_tls_key_file must be configured together")
	}
	certFile, keyFile := c.SplitCertificateFiles()
	if strings.TrimSpace(certFile) == "" || strings.TrimSpace(keyFile) == "" {
		return errors.New("split mode requires split_tls_cert_file and split_tls_key_file, or tls_cert_file and tls_key_file")
	}
	return nil
}

func validateAuthThrottle(throttle auth.Config) error {
	if throttle.MaxAttemptsPerConnection == 0 && throttle.MaxFailuresPerIP == 0 && throttle.MaxFailuresPerAccount == 0 && throttle.BackoffBase == 0 && throttle.BackoffMax == 0 && throttle.ResponseDelayMax == 0 && throttle.FailureWindow == 0 {
		return nil
	}
	if throttle.MaxAttemptsPerConnection <= 0 {
		return errors.New("auth_throttle.max_attempts_per_connection must be greater than zero")
	}
	if throttle.MaxFailuresPerIP <= 0 {
		return errors.New("auth_throttle.max_failures_per_ip must be greater than zero")
	}
	if throttle.MaxFailuresPerAccount <= 0 {
		return errors.New("auth_throttle.max_failures_per_account must be greater than zero")
	}
	if throttle.BackoffBase <= 0 {
		return errors.New("auth_throttle.backoff_base must be greater than zero")
	}
	if throttle.BackoffMax <= 0 {
		return errors.New("auth_throttle.backoff_max must be greater than zero")
	}
	if throttle.ResponseDelayMax <= 0 {
		return errors.New("auth_throttle.response_delay_max must be greater than zero")
	}
	if throttle.FailureWindow <= 0 {
		return errors.New("auth_throttle.failure_window must be greater than zero")
	}
	if throttle.BackoffMax < throttle.BackoffBase {
		return errors.New("auth_throttle.backoff_max must be at least backoff_base")
	}
	return nil
}

// Resolve maps a login or recipient address, including aliases, to a mailbox.
// It also supports 'spam-' and 'ham-' prefixes on the local-part of configured
// user addresses or aliases (for example, spam-kpratt@thepratts.info).
func (c *Config) Resolve(username string) (string, bool) {
	if mailbox, ok := c.resolveDirect(username); ok {
		return mailbox, true
	}
	if stripped, ok := stripSpamHamPrefix(username); ok {
		if mailbox, ok := c.resolveDirect(stripped); ok {
			return mailbox, true
		}
	}
	return "", false
}

func (c *Config) resolveDirect(username string) (string, bool) {
	user, ok := c.findUser(username)
	if ok {
		return mailboxFor(username, user), true
	}
	normalized := strings.ToLower(strings.TrimSpace(username))
	for configured, user := range c.Users {
		for _, alias := range user.Aliases {
			if strings.ToLower(strings.TrimSpace(alias)) == normalized {
				return mailboxFor(configured, user), true
			}
		}
	}
	return "", false
}

func stripSpamHamPrefix(address string) (string, bool) {
	address = strings.TrimSpace(address)
	localPart, domain, hasDomain := strings.Cut(address, "@")
	lowerLocal := strings.ToLower(localPart)
	var strippedLocal string
	if strings.HasPrefix(lowerLocal, "spam-") {
		strippedLocal = localPart[5:]
	} else if strings.HasPrefix(lowerLocal, "ham-") {
		strippedLocal = localPart[4:]
	} else {
		return "", false
	}
	if strippedLocal == "" {
		return "", false
	}
	if hasDomain {
		return strippedLocal + "@" + domain, true
	}
	return strippedLocal, true
}

// IsLocalDomain reports whether domain belongs to the configured host, users,
// or aliases.
func (c *Config) IsLocalDomain(domain string) bool {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if domain == "" {
		return false
	}
	if strings.TrimSuffix(strings.ToLower(strings.TrimSpace(c.Hostname)), ".") == domain {
		return true
	}
	for username := range c.Users {
		_, configuredDomain, ok := strings.Cut(strings.ToLower(strings.TrimSpace(username)), "@")
		if ok && strings.TrimSuffix(configuredDomain, ".") == domain {
			return true
		}
	}
	for _, user := range c.Users {
		for _, alias := range user.Aliases {
			_, aliasDomain, ok := strings.Cut(strings.ToLower(strings.TrimSpace(alias)), "@")
			if ok && strings.TrimSuffix(aliasDomain, ".") == domain {
				return true
			}
		}
	}
	return false
}

// Authenticate verifies a user's bcrypt, cleartext, or SHA-256 password.
func (c *Config) Authenticate(username, password string) bool {
	user, ok := c.findUser(username)
	if !ok {
		_ = bcrypt.CompareHashAndPassword(dummyBcryptPasswordHash(), []byte(password))
		return false
	}
	if user.PasswordHash != "" {
		return bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)) == nil
	}
	if user.Password != "" {
		configuredHash := sha256.Sum256([]byte(user.Password))
		providedHash := sha256.Sum256([]byte(password))
		return subtle.ConstantTimeCompare(configuredHash[:], providedHash[:]) == 1
	}
	configuredHash, err := hex.DecodeString(user.PasswordSHA256)
	var expected [sha256.Size]byte
	if err == nil {
		copy(expected[:], configuredHash)
	}
	providedHash := sha256.Sum256([]byte(password))
	matched := subtle.ConstantTimeCompare(expected[:], providedHash[:]) == 1
	return err == nil && len(configuredHash) == sha256.Size && matched
}

var (
	dummyBcryptHashOnce sync.Once
	dummyBcryptHash     []byte
)

func dummyBcryptPasswordHash() []byte {
	dummyBcryptHashOnce.Do(func() {
		dummyBcryptHash, _ = bcrypt.GenerateFromPassword([]byte("mymail-unknown-user-dummy-password"), bcrypt.DefaultCost)
	})
	return dummyBcryptHash
}

func (c *Config) findUser(username string) (User, bool) {
	username = strings.ToLower(strings.TrimSpace(username))
	for configured, user := range c.Users {
		if strings.ToLower(strings.TrimSpace(configured)) == username {
			return user, true
		}
	}
	return User{}, false
}

func mailboxFor(username string, user User) string {
	mailbox := user.Mailbox
	if mailbox == "" {
		mailbox = strings.ToLower(strings.TrimSpace(username))
	}
	return mailbox
}
