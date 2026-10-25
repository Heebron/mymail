package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	contents := []byte(`smtp_listen: 127.0.0.1:2525
smtp_cleartext_listen: 127.0.0.1:25
smtp_require_starttls: true
imap_listen: 127.0.0.1:1143
imap_tls_listen: 127.0.0.1:1993
imap_require_starttls: true
tls_cert_file: /etc/mymail/tls.crt
tls_key_file: /etc/mymail/tls.key
auth_throttle:
  max_attempts_per_connection: 7
  max_failures_per_ip: 23
  max_failures_per_account: 11
  backoff_base: 2s
  backoff_max: 90s
  response_delay_max: 3s
  failure_window: 20m
maildir_root: /var/lib/mymail
hostname: mail.example.test
plugins:
  - name: test-plugin
    config:
      endpoint: https://plugin.example.test
      token: configured-token
users:
  Alice@Example.Test:
    password: secret
    aliases:
      - alias@example.test
`)
	if err := os.WriteFile(path, contents, 0600); err != nil {
		t.Fatal(err)
	}

	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got.SMTPListen != "127.0.0.1:2525" || got.SMTPCleartextListen != "127.0.0.1:25" || got.IMAPListen != "127.0.0.1:1143" {
		t.Fatalf("listeners = %#v", got)
	}
	if got.IMAPTLSListen != "127.0.0.1:1993" {
		t.Fatalf("TLS listeners = %#v", got)
	}
	if !got.SMTPRequireSTARTTLS || !got.IMAPRequireSTARTTLS {
		t.Fatalf("required STARTTLS settings = %#v", got)
	}
	if got.TLSCertFile != "/etc/mymail/tls.crt" || got.TLSKeyFile != "/etc/mymail/tls.key" {
		t.Fatalf("TLS certificate files = %#v", got)
	}
	if got.AuthThrottle.MaxAttemptsPerConnection != 7 || got.AuthThrottle.MaxFailuresPerIP != 23 || got.AuthThrottle.MaxFailuresPerAccount != 11 || got.AuthThrottle.BackoffBase != 2*time.Second || got.AuthThrottle.BackoffMax != 90*time.Second || got.AuthThrottle.ResponseDelayMax != 3*time.Second || got.AuthThrottle.FailureWindow != 20*time.Minute {
		t.Fatalf("authentication throttling = %#v", got.AuthThrottle)
	}
	if got.MaildirRoot != "/var/lib/mymail" || got.Hostname != "mail.example.test" {
		t.Fatalf("server settings = %#v", got)
	}
	if len(got.Plugins) != 1 || got.Plugins[0].Name != "test-plugin" || got.Plugins[0].Config["endpoint"] != "https://plugin.example.test" || got.Plugins[0].Config["token"] != "configured-token" {
		t.Fatalf("plugins = %#v", got.Plugins)
	}
	if !got.Authenticate("alice@example.test", "secret") {
		t.Fatal("Authenticate() rejected valid YAML credentials")
	}
	if got.Authenticate("alice", "secret") {
		t.Fatal("Authenticate() accepted the local username for a full-address account")
	}
	if mailbox, ok := got.Resolve("alice@example.test"); !ok || mailbox != "alice@example.test" {
		t.Fatalf("Resolve() = %q, %t", mailbox, ok)
	}
	if mailbox, ok := got.Resolve("alice"); ok {
		t.Fatalf("Resolve() accepted local username with mailbox %q", mailbox)
	}
	if mailbox, ok := got.Resolve("alias@example.test"); !ok || mailbox != "alice@example.test" {
		t.Fatalf("Resolve() for alias = %q, %t", mailbox, ok)
	}
}

func TestLoadYAMLPluginConfigurationIsOptionalAndOrdered(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	contents := []byte(`plugins:
  - name: first-plugin
  - name: second-plugin
    config:
      endpoint: https://plugin.example.test
users:
  alice@example.test:
    password: secret
`)
	if err := os.WriteFile(path, contents, 0600); err != nil {
		t.Fatal(err)
	}

	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(got.Plugins) != 2 {
		t.Fatalf("plugin count = %d, want 2", len(got.Plugins))
	}
	if got.Plugins[0].Name != "first-plugin" || got.Plugins[0].Config != nil {
		t.Fatalf("first plugin = %#v, want name with nil config", got.Plugins[0])
	}
	if got.Plugins[1].Name != "second-plugin" || got.Plugins[1].Config["endpoint"] != "https://plugin.example.test" {
		t.Fatalf("second plugin = %#v", got.Plugins[1])
	}
}

func TestAuthenticateRequiresFullEmailAddress(t *testing.T) {
	config := Config{Users: map[string]User{
		"alice@example.test": {Password: "secret"},
	}}
	tests := []struct {
		name     string
		username string
		password string
		want     bool
	}{
		{name: "full email", username: "alice@example.test", password: "secret", want: true},
		{name: "case insensitive full email", username: "ALICE@EXAMPLE.TEST", password: "secret", want: true},
		{name: "local part", username: "alice", password: "secret", want: false},
		{name: "different email", username: "alice@example.org", password: "secret", want: false},
		{name: "wrong password", username: "alice@example.test", password: "wrong", want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := config.Authenticate(test.username, test.password); got != test.want {
				t.Fatalf("Authenticate(%q, %q) = %t, want %t", test.username, test.password, got, test.want)
			}
		})
	}
}

func TestDefaultsUseSMTPSubmissionSTARTTLSPort(t *testing.T) {
	config := Defaults()
	if config.SMTPListen != "0.0.0.0:587" {
		t.Fatalf("SMTP default listener = %q, want 0.0.0.0:587", config.SMTPListen)
	}
	if config.SMTPCleartextListen != "0.0.0.0:25" {
		t.Fatalf("SMTP cleartext listener = %q, want 0.0.0.0:25", config.SMTPCleartextListen)
	}
	if config.AuthThrottle.MaxAttemptsPerConnection != 5 || config.AuthThrottle.MaxFailuresPerIP != 20 || config.AuthThrottle.MaxFailuresPerAccount != 10 || config.AuthThrottle.BackoffBase != time.Second || config.AuthThrottle.BackoffMax != time.Minute || config.AuthThrottle.ResponseDelayMax != time.Second || config.AuthThrottle.FailureWindow != 15*time.Minute {
		t.Fatalf("authentication throttling defaults = %#v", config.AuthThrottle)
	}
}

func TestValidateRejectsInvalidAuthThrottle(t *testing.T) {
	tests := []struct {
		name   string
		adjust func(*Config)
	}{
		{
			name: "zero attempts",
			adjust: func(config *Config) {
				config.AuthThrottle.MaxAttemptsPerConnection = 0
			},
		},
		{
			name: "maximum below base",
			adjust: func(config *Config) {
				config.AuthThrottle.BackoffMax = time.Second
				config.AuthThrottle.BackoffBase = 2 * time.Second
			},
		},
		{
			name: "zero response delay",
			adjust: func(config *Config) {
				config.AuthThrottle.ResponseDelayMax = 0
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := Defaults()
			config.MaildirRoot = t.TempDir()
			config.Users = map[string]User{"alice@example.test": {Password: "secret"}}
			test.adjust(&config)
			if err := config.Validate(); err == nil {
				t.Fatal("Validate() accepted invalid authentication throttling")
			}
		})
	}
}

func TestResolveAliasesToSharedMailbox(t *testing.T) {
	config := Config{
		Hostname: "leopard.thepratts.info",
		Users: map[string]User{
			"kpratt@leopard.thepratts.info": {
				Password: "changeit",
				Mailbox:  "kpratt",
				Aliases:  []string{"kenpratt@comcast.net", "kpratt@thepratts.info", "stashcan@comcast.net"},
			},
		},
	}
	for _, address := range []string{"kenpratt@comcast.net", "kpratt@thepratts.info", "stashcan@comcast.net"} {
		if mailbox, ok := config.Resolve(address); !ok || mailbox != "kpratt" {
			t.Fatalf("Resolve(%q) = %q, %t; want kpratt, true", address, mailbox, ok)
		}
	}
	for _, domain := range []string{"comcast.net", "thepratts.info"} {
		if !config.IsLocalDomain(domain) {
			t.Fatalf("IsLocalDomain(%q) = false", domain)
		}
	}
	if config.Authenticate("kenpratt@comcast.net", "changeit") {
		t.Fatal("alias unexpectedly authenticated as a primary user")
	}
}

func TestValidateRejectsDuplicateAliases(t *testing.T) {
	config := Config{
		SMTPListen:  "127.0.0.1:2525",
		IMAPListen:  "127.0.0.1:1143",
		MaildirRoot: t.TempDir(),
		Hostname:    "mail.example.test",
		Users: map[string]User{
			"alice@example.test": {Password: "secret", Aliases: []string{"shared@example.test"}},
			"bob@example.test":   {Password: "secret", Aliases: []string{"SHARED@example.test"}},
		},
	}
	if err := config.Validate(); err == nil {
		t.Fatal("Validate() accepted duplicate aliases")
	}
}

func TestValidateRejectsInvalidPlugins(t *testing.T) {
	base := Config{
		SMTPListen:  "127.0.0.1:2525",
		IMAPListen:  "127.0.0.1:1143",
		MaildirRoot: t.TempDir(),
		Hostname:    "mail.example.test",
		Users: map[string]User{
			"alice@example.test": {Password: "secret"},
		},
	}
	for _, test := range []struct {
		name    string
		plugins []PluginConfig
	}{
		{name: "empty name", plugins: []PluginConfig{{Config: map[string]string{"key": "value"}}}},
		{name: "duplicate name", plugins: []PluginConfig{{Name: "same"}, {Name: "same"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := base
			config.Plugins = test.plugins
			if err := config.Validate(); err == nil {
				t.Fatal("Validate() accepted invalid plugins")
			}
		})
	}
}

func TestValidateRejectsDuplicateMailboxes(t *testing.T) {
	tests := []struct {
		name  string
		users map[string]User
	}{
		{
			name: "explicit mailbox",
			users: map[string]User{
				"alice@example.test": {Password: "secret", Mailbox: "shared"},
				"bob@example.test":   {Password: "secret", Mailbox: "shared"},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := Config{
				SMTPListen:  "127.0.0.1:2525",
				IMAPListen:  "127.0.0.1:1143",
				MaildirRoot: t.TempDir(),
				Hostname:    "mail.example.test",
				Users:       test.users,
			}
			if err := config.Validate(); err == nil {
				t.Fatal("Validate() accepted users sharing a mailbox")
			}
		})
	}
}

func TestLoadYAMLEnvironmentExpansion(t *testing.T) {
	t.Setenv("MYMAIL_SMTP_LISTEN", "127.0.0.1:3525")
	t.Setenv("MYMAIL_SMTP_CLEARTEXT_LISTEN", "127.0.0.1:3025")
	t.Setenv("MYMAIL_IMAP_LISTEN", "127.0.0.1:2143")
	t.Setenv("MYMAIL_IMAP_TLS_LISTEN", "127.0.0.1:2993")
	t.Setenv("MYMAIL_ROOT", t.TempDir())
	t.Setenv("MYMAIL_HOSTNAME", "mail.test")
	t.Setenv("MYMAIL_TLS_CERT", "/etc/mymail/mail.crt")
	t.Setenv("MYMAIL_TLS_KEY", "/etc/mymail/mail.key")
	t.Setenv("MYMAIL_PASSWORD", "secret-from-environment")
	t.Setenv("MYMAIL_MAILBOX", "alice-from-environment")
	t.Setenv("MYMAIL_ALIAS", "alias-from-environment@example.test")
	t.Setenv("MYMAIL_PLUGIN_ENDPOINT", "https://expanded.example.test")
	t.Setenv("MYMAIL_PLUGIN_TOKEN", "expanded-token")
	path := filepath.Join(t.TempDir(), "config.yaml")
	contents := []byte(`smtp_listen: ${MYMAIL_SMTP_LISTEN}
smtp_cleartext_listen: ${MYMAIL_SMTP_CLEARTEXT_LISTEN}
imap_listen: ${MYMAIL_IMAP_LISTEN}
imap_tls_listen: ${MYMAIL_IMAP_TLS_LISTEN}
tls_cert_file: ${MYMAIL_TLS_CERT}
tls_key_file: ${MYMAIL_TLS_KEY}
maildir_root: ${MYMAIL_ROOT}/mymail
hostname: ${MYMAIL_HOSTNAME}
plugins:
  - name: test-plugin
    config:
      endpoint: ${MYMAIL_PLUGIN_ENDPOINT}
      token: ${MYMAIL_PLUGIN_TOKEN}
users:
  alice@example.test:
    password: ${MYMAIL_PASSWORD}
    mailbox: ${MYMAIL_MAILBOX}
    aliases:
      - ${MYMAIL_ALIAS}
  bob@example.test:
    password: ${MYMAIL_UNDEFINED}
`)
	if err := os.WriteFile(path, contents, 0600); err != nil {
		t.Fatal(err)
	}

	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got.SMTPListen != "127.0.0.1:3525" || got.SMTPCleartextListen != "127.0.0.1:3025" || got.IMAPListen != "127.0.0.1:2143" {
		t.Fatalf("listeners = %#v", got)
	}
	if got.IMAPTLSListen != "127.0.0.1:2993" {
		t.Fatalf("TLS listeners = %#v", got)
	}
	if got.TLSCertFile != "/etc/mymail/mail.crt" || got.TLSKeyFile != "/etc/mymail/mail.key" {
		t.Fatalf("TLS certificate files = %#v", got)
	}
	if got.MaildirRoot != os.Getenv("MYMAIL_ROOT")+"/mymail" || got.Hostname != "mail.test" {
		t.Fatalf("server settings = %#v", got)
	}
	pluginSettings := got.Plugins[0].Config
	if pluginSettings["endpoint"] != "https://expanded.example.test" || pluginSettings["token"] != "expanded-token" {
		t.Fatalf("expanded plugin settings = %#v", pluginSettings)
	}
	if !got.Authenticate("alice@example.test", "secret-from-environment") {
		t.Fatal("Authenticate() rejected expanded password")
	}
	if mailbox, ok := got.Resolve("alice@example.test"); !ok || mailbox != "alice-from-environment" {
		t.Fatalf("Resolve() = %q, %t", mailbox, ok)
	}
	if mailbox, ok := got.Resolve("alias-from-environment@example.test"); !ok || mailbox != "alice-from-environment" {
		t.Fatalf("Resolve() for expanded alias = %q, %t", mailbox, ok)
	}
	if got.Users["bob@example.test"].Password != "${MYMAIL_UNDEFINED}" {
		t.Fatalf("undefined variable = %q", got.Users["bob@example.test"].Password)
	}
}

func TestLoadYAMLValidationError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("smtp_listen: :2525\n"), 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := Load(path); err == nil {
		t.Fatal("Load() succeeded for an invalid YAML configuration")
	}
}

func TestIsLocalDomain(t *testing.T) {
	config := Config{Hostname: "mail.example.test", Users: map[string]User{
		"alice@example.test": {Password: "secret"},
		"bob":                {Password: "secret"},
	}}
	for _, domain := range []string{"example.test", "mail.example.test", "EXAMPLE.TEST."} {
		if !config.IsLocalDomain(domain) {
			t.Fatalf("IsLocalDomain(%q) = false", domain)
		}
	}
	if config.IsLocalDomain("external.test") {
		t.Fatal("IsLocalDomain(external.test) = true")
	}
}

func TestLoadYAMLTLSValidationError(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "missing certificate",
			body: "imap_tls_listen: 127.0.0.1:1993\n",
		},
		{
			name: "missing key",
			body: "tls_cert_file: /etc/mymail/tls.crt\nimap_tls_listen: 127.0.0.1:1993\n",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			contents := []byte("smtp_listen: 127.0.0.1:2525\nimap_listen: 127.0.0.1:1143\nmaildir_root: /tmp/mymail\nhostname: mail.example.test\nusers:\n  alice@example.test:\n    password: secret\n" + test.body)
			if err := os.WriteFile(path, contents, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil {
				t.Fatal("Load() succeeded for an invalid TLS configuration")
			}
		})
	}
}

func TestValidateAllowsTLSForSTARTTLSOnly(t *testing.T) {
	config := Config{
		SMTPListen:  "127.0.0.1:2525",
		IMAPListen:  "127.0.0.1:1143",
		TLSCertFile: "/etc/mymail/tls.crt",
		TLSKeyFile:  "/etc/mymail/tls.key",
		MaildirRoot: t.TempDir(),
		Hostname:    "mail.example.test",
		Users:       map[string]User{"alice@example.test": {Password: "secret"}},
	}
	if err := config.Validate(); err != nil {
		t.Fatalf("Validate() rejected STARTTLS-only certificate configuration: %v", err)
	}
}

func TestValidateRequiresTLSFilesForRequiredSTARTTLS(t *testing.T) {
	for _, field := range []string{"smtp_require_starttls", "imap_require_starttls"} {
		t.Run(field, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			contents := []byte("smtp_listen: 127.0.0.1:2525\nimap_listen: 127.0.0.1:1143\nmaildir_root: /tmp/mymail\nhostname: mail.example.test\nusers:\n  alice@example.test:\n    password: secret\n" + field + ": true\n")
			if err := os.WriteFile(path, contents, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil {
				t.Fatal("Load() succeeded without TLS certificate files")
			}
		})
	}
}
