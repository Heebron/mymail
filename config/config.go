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
)

type User struct {
	Password       string `yaml:"password,omitempty"`
	PasswordSHA256 string `yaml:"password_sha256,omitempty"`
	Mailbox        string `yaml:"mailbox,omitempty"`
}

type Config struct {
	SMTPListen    string          `yaml:"smtp_listen"`
	SMTPTLSListen string          `yaml:"smtp_tls_listen,omitempty"`
	IMAPListen    string          `yaml:"imap_listen"`
	IMAPTLSListen string          `yaml:"imap_tls_listen,omitempty"`
	TLSCertFile   string          `yaml:"tls_cert_file,omitempty"`
	TLSKeyFile    string          `yaml:"tls_key_file,omitempty"`
	MaildirRoot   string          `yaml:"maildir_root"`
	Hostname      string          `yaml:"hostname"`
	Users         map[string]User `yaml:"users"`
}

func Defaults() Config {
	return Config{
		SMTPListen:  "0.0.0.0:2525",
		IMAPListen:  "0.0.0.0:1143",
		MaildirRoot: "/var/lib/mymail",
		Hostname:    "localhost",
		Users:       make(map[string]User),
	}
}

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
	c.SMTPTLSListen = expandEnvironment(c.SMTPTLSListen)
	c.IMAPListen = expandEnvironment(c.IMAPListen)
	c.IMAPTLSListen = expandEnvironment(c.IMAPTLSListen)
	c.TLSCertFile = expandEnvironment(c.TLSCertFile)
	c.TLSKeyFile = expandEnvironment(c.TLSKeyFile)
	c.MaildirRoot = expandEnvironment(c.MaildirRoot)
	c.Hostname = expandEnvironment(c.Hostname)
	for username, user := range c.Users {
		user.Password = expandEnvironment(user.Password)
		user.PasswordSHA256 = expandEnvironment(user.PasswordSHA256)
		user.Mailbox = expandEnvironment(user.Mailbox)
		c.Users[username] = user
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

func (c *Config) Validate() error {
	if strings.TrimSpace(c.SMTPListen) == "" || strings.TrimSpace(c.IMAPListen) == "" {
		return errors.New("smtp_listen and imap_listen are required")
	}
	hasTLSListener := strings.TrimSpace(c.SMTPTLSListen) != "" || strings.TrimSpace(c.IMAPTLSListen) != ""
	hasTLSFiles := strings.TrimSpace(c.TLSCertFile) != "" || strings.TrimSpace(c.TLSKeyFile) != ""
	if hasTLSListener && (strings.TrimSpace(c.TLSCertFile) == "" || strings.TrimSpace(c.TLSKeyFile) == "") {
		return errors.New("tls_cert_file and tls_key_file are required when a TLS listener is configured")
	}
	if hasTLSFiles && !hasTLSListener {
		return errors.New("a TLS listener is required when TLS certificate files are configured")
	}
	if strings.TrimSpace(c.MaildirRoot) == "" || strings.TrimSpace(c.Hostname) == "" {
		return errors.New("maildir_root and hostname are required")
	}
	if len(c.Users) == 0 {
		return errors.New("at least one user is required")
	}
	for username, user := range c.Users {
		if strings.TrimSpace(username) == "" || strings.ContainsAny(username, "/\\") {
			return fmt.Errorf("invalid username %q", username)
		}
		if user.Password == "" && user.PasswordSHA256 == "" {
			return fmt.Errorf("user %q has no password", username)
		}
		if user.Mailbox != "" && strings.ContainsAny(user.Mailbox, "/\\") {
			return fmt.Errorf("user %q has invalid mailbox", username)
		}
	}
	return nil
}

func (c *Config) Resolve(username string) (string, bool) {
	user, ok := c.findUser(username)
	if !ok {
		return "", false
	}
	mailbox := user.Mailbox
	if mailbox == "" {
		mailbox = strings.Split(strings.ToLower(strings.TrimSpace(username)), "@")[0]
	}
	return mailbox, true
}

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
	return false
}

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
	if strings.Contains(username, "@") {
		return User{}, false
	}
	var match User
	matches := 0
	for configured, user := range c.Users {
		local, _, hasDomain := strings.Cut(strings.ToLower(strings.TrimSpace(configured)), "@")
		if hasDomain && local == username {
			match = user
			matches++
		}
	}
	return match, matches == 1
}
