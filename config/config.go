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
	Password       string   `yaml:"password,omitempty"`
	PasswordSHA256 string   `yaml:"password_sha256,omitempty"`
	Mailbox        string   `yaml:"mailbox,omitempty"`
	Aliases        []string `yaml:"aliases,omitempty"`
}

type Config struct {
	SMTPListen          string          `yaml:"smtp_listen"`
	SMTPCleartextListen string          `yaml:"smtp_cleartext_listen,omitempty"`
	SMTPRequireSTARTTLS bool            `yaml:"smtp_require_starttls,omitempty"`
	IMAPListen          string          `yaml:"imap_listen"`
	IMAPTLSListen       string          `yaml:"imap_tls_listen,omitempty"`
	IMAPRequireSTARTTLS bool            `yaml:"imap_require_starttls,omitempty"`
	TLSCertFile         string          `yaml:"tls_cert_file,omitempty"`
	TLSKeyFile          string          `yaml:"tls_key_file,omitempty"`
	MaildirRoot         string          `yaml:"maildir_root"`
	Hostname            string          `yaml:"hostname"`
	Users               map[string]User `yaml:"users"`
}

func Defaults() Config {
	return Config{
		SMTPListen:          "0.0.0.0:587",
		SMTPCleartextListen: "0.0.0.0:25",
		IMAPListen:          "0.0.0.0:1143",
		MaildirRoot:         "/var/lib/mymail",
		Hostname:            "localhost",
		Users:               make(map[string]User),
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
	c.SMTPCleartextListen = expandEnvironment(c.SMTPCleartextListen)
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
		for index, alias := range user.Aliases {
			user.Aliases[index] = expandEnvironment(alias)
		}
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
	hasTLSListener := strings.TrimSpace(c.IMAPTLSListen) != ""
	hasTLSFiles := strings.TrimSpace(c.TLSCertFile) != "" || strings.TrimSpace(c.TLSKeyFile) != ""
	if (hasTLSListener || hasTLSFiles || c.SMTPRequireSTARTTLS || c.IMAPRequireSTARTTLS) && (strings.TrimSpace(c.TLSCertFile) == "" || strings.TrimSpace(c.TLSKeyFile) == "") {
		return errors.New("tls_cert_file and tls_key_file must be configured together")
	}
	if strings.TrimSpace(c.MaildirRoot) == "" || strings.TrimSpace(c.Hostname) == "" {
		return errors.New("maildir_root and hostname are required")
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
		if user.Mailbox != "" && strings.ContainsAny(user.Mailbox, "/\\") {
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

func (c *Config) Resolve(username string) (string, bool) {
	user, ok := c.findUser(username)
	if ok {
		return mailboxFor(username, user), true
	}
	username = strings.ToLower(strings.TrimSpace(username))
	for configured, user := range c.Users {
		for _, alias := range user.Aliases {
			if strings.ToLower(strings.TrimSpace(alias)) == username {
				return mailboxFor(configured, user), true
			}
		}
	}
	return "", false
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
