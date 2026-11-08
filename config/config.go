// Package config loads the daemon's YAML configuration.
package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
	"mymail/auth"
	"mymail/dkim"
	"mymail/plugins"
)

// User contains one login account, its mailbox mapping, and aliases.
type User struct {
	// Password is a cleartext password. Prefer PasswordSHA256 in deployments.
	Password string `yaml:"password,omitempty"`
	// PasswordSHA256 is a lowercase hexadecimal SHA-256 password hash.
	PasswordSHA256 string `yaml:"password_sha256,omitempty"`
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
	// SMTPListen is the STARTTLS-capable SMTP listener address.
	SMTPListen string `yaml:"smtp_listen"`
	// SMTPCleartextListen is the optional cleartext SMTP listener address.
	SMTPCleartextListen string `yaml:"smtp_cleartext_listen,omitempty"`
	// SMTPRequireSTARTTLS requires TLS before SMTP authentication or MAIL.
	SMTPRequireSTARTTLS bool `yaml:"smtp_require_starttls,omitempty"`
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
	c.IMAPListen = expandEnvironment(c.IMAPListen)
	c.IMAPTLSListen = expandEnvironment(c.IMAPTLSListen)
	c.TLSCertFile = expandEnvironment(c.TLSCertFile)
	c.TLSKeyFile = expandEnvironment(c.TLSKeyFile)
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
	for username, user := range c.Users {
		user.Password = expandEnvironment(user.Password)
		user.PasswordSHA256 = expandEnvironment(user.PasswordSHA256)
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

// HasDKIM reports whether all four required DKIM configuration items
// (domain, private key, public key, and selector) are present.
func (c *Config) HasDKIM() bool {
	return c.DKIM.HasDKIM()
}

// Validate checks listener, TLS, authentication, mailbox, and user settings.
func (c *Config) Validate() error {
	if strings.TrimSpace(c.SMTPListen) == "" || strings.TrimSpace(c.IMAPListen) == "" {
		return errors.New("smtp_listen and imap_listen are required")
	}
	hasTLSListener := strings.TrimSpace(c.IMAPTLSListen) != ""
	hasTLSFiles := strings.TrimSpace(c.TLSCertFile) != "" || strings.TrimSpace(c.TLSKeyFile) != ""
	if (hasTLSListener || hasTLSFiles || c.SMTPRequireSTARTTLS || c.IMAPRequireSTARTTLS) && (strings.TrimSpace(c.TLSCertFile) == "" || strings.TrimSpace(c.TLSKeyFile) == "") {
		return errors.New("tls_cert_file and tls_key_file must be configured together")
	}
	if strings.TrimSpace(c.MaildirRoot) == "" || strings.TrimSpace(c.Hostname) == "" {
		return errors.New("maildir_root and hostname are required")
	}
	hasDKIMDomain := strings.TrimSpace(c.DKIM.Domain) != ""
	hasDKIMPriv := strings.TrimSpace(c.DKIM.PrivateKey) != ""
	hasDKIMPub := strings.TrimSpace(c.DKIM.PublicKey) != ""
	hasDKIMSelector := strings.TrimSpace(c.DKIM.Selector) != ""
	hasAnyDKIM := hasDKIMDomain || hasDKIMPriv || hasDKIMPub || hasDKIMSelector
	hasAllDKIM := hasDKIMDomain && hasDKIMPriv && hasDKIMPub && hasDKIMSelector
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
	if len(c.Users) == 0 {
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
		if user.Password == "" && user.PasswordSHA256 == "" {
			return fmt.Errorf("user %q has no password", username)
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

// Authenticate verifies a user's cleartext or SHA-256 password.
func (c *Config) Authenticate(username, password string) bool {
	user, ok := c.findUser(username)
	if !ok {
		return false
	}
	if user.Password != "" {
		return user.Password == password
	}
	hash := sha256.Sum256([]byte(password))
	return strings.EqualFold(user.PasswordSHA256, hex.EncodeToString(hash[:]))
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
