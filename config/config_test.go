package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func TestLoadYAML(t *testing.T) {
	t.Setenv("MYMAIL_SPLIT_CERT", "/etc/mymail/split.crt")
	t.Setenv("MYMAIL_SPLIT_KEY", "/etc/mymail/split.key")
	path := filepath.Join(t.TempDir(), "config.yaml")
	contents := []byte(`smtp_listen: 127.0.0.1:2525
smtp_cleartext_listen: 127.0.0.1:25
smtp_tls_listen: 127.0.0.1:2465
imap_listen: 127.0.0.1:1143
imap_tls_listen: 127.0.0.1:1993
imap_require_starttls: true
tls_cert_file: /etc/mymail/tls.crt
tls_key_file: /etc/mymail/tls.key
split_tls_cert_file: ${MYMAIL_SPLIT_CERT}
split_tls_key_file: ${MYMAIL_SPLIT_KEY}
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
	if got.SMTPListen != "127.0.0.1:2525" || got.SMTPCleartextListen != "127.0.0.1:25" || got.SMTPTLSListen != "127.0.0.1:2465" || got.IMAPListen != "127.0.0.1:1143" {
		t.Fatalf("listeners = %#v", got)
	}
	if got.IMAPTLSListen != "127.0.0.1:1993" {
		t.Fatalf("TLS listeners = %#v", got)
	}
	if !got.IMAPRequireSTARTTLS {
		t.Fatalf("required IMAP STARTTLS setting = %t", got.IMAPRequireSTARTTLS)
	}
	if got.TLSCertFile != "/etc/mymail/tls.crt" || got.TLSKeyFile != "/etc/mymail/tls.key" {
		t.Fatalf("TLS certificate files = %#v", got)
	}
	if got.SplitTLSCertFile != "/etc/mymail/split.crt" || got.SplitTLSKeyFile != "/etc/mymail/split.key" {
		t.Fatalf("split TLS certificate files = %q, %q", got.SplitTLSCertFile, got.SplitTLSKeyFile)
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

func TestExampleConfigLoadsWithPasswordHashEnvironment(t *testing.T) {
	firstHash, err := bcrypt.GenerateFromPassword([]byte("alice-secret"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	secondHash, err := bcrypt.GenerateFromPassword([]byte("bob-secret"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("MYMAIL_USER_4821_PASSWORD_HASH", string(firstHash))
	t.Setenv("MYMAIL_BOB_PASSWORD_HASH", string(secondHash))

	cfg, err := Load(filepath.Join("..", "config.example.yaml"))
	if err != nil {
		t.Fatalf("Load(config.example.yaml) = %v", err)
	}
	if cfg.Users["user-4821@mail.example.test"].PasswordHash != string(firstHash) {
		t.Fatal("example config did not expand the user-4821 bcrypt hash")
	}
	if cfg.Users["bob@mail.example.test"].PasswordHash != string(secondHash) {
		t.Fatal("example config did not expand the bob bcrypt hash")
	}
}

func TestSplitExampleConfigsLoad(t *testing.T) {
	passwordHash, err := bcrypt.GenerateFromPassword([]byte("split-example-secret"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("MYMAIL_USER_PASSWORD_HASH", string(passwordHash))

	local, err := Load(filepath.Join("..", "config-split-local.yaml"))
	if err != nil {
		t.Fatalf("Load(config-split-local.yaml) = %v", err)
	}
	if !local.IsSplitLocal() || local.IsSplitRemote() {
		t.Fatalf("local split roles = local:%t remote:%t, want local only", local.IsSplitLocal(), local.IsSplitRemote())
	}
	if local.SplitConnect == "" || !local.SplitIgnoreServerName || local.SplitTLSCertFile == "" || local.SplitTLSKeyFile == "" {
		t.Fatalf("local split settings are incomplete: %#v", local)
	}
	if len(local.Users) == 0 || local.Users["user@example.test"].PasswordHash != string(passwordHash) {
		t.Fatalf("local example user/password hash not loaded: %#v", local.Users)
	}
	if local.TLSCertFile == "" || local.TLSKeyFile == "" || local.SplitCACertFile == "" {
		t.Fatalf("local example must configure the public TLS pair and the split CA: %#v", local)
	}

	remote, err := Load(filepath.Join("..", "config-split-remote.yaml"))
	if err != nil {
		t.Fatalf("Load(config-split-remote.yaml) = %v", err)
	}
	if !remote.IsSplitRemote() || remote.IsSplitLocal() {
		t.Fatalf("remote split roles = local:%t remote:%t, want remote only", remote.IsSplitLocal(), remote.IsSplitRemote())
	}
	if remote.SplitCACertFile == "" {
		t.Fatal("remote example has no split_ca_cert_file")
	}
	if len(remote.Users) != 0 {
		t.Fatalf("remote example must not configure users, got %#v", remote.Users)
	}
	if remote.TLSCertFile != "" || remote.TLSKeyFile != "" {
		t.Fatalf("remote example should receive its SMTP certificate from the local, got tls_cert_file=%q tls_key_file=%q", remote.TLSCertFile, remote.TLSKeyFile)
	}
	if remote.SplitTLSCertFile == "" || remote.SplitTLSKeyFile == "" {
		t.Fatal("remote example has no split_tls_cert_file/split_tls_key_file for its split listener")
	}
}

func TestValidateRemoteOnlyDoesNotRequirePublicTLSCertificate(t *testing.T) {
	remote := func() Config {
		return Config{
			SMTPListen:       "0.0.0.0:587",
			SMTPTLSListen:    "0.0.0.0:465",
			Hostname:         "smtp.remote.example.test",
			SplitMode:        "on",
			SplitListen:      "0.0.0.0:1783",
			SplitCACertFile:  "split-ca.crt",
			SplitTLSCertFile: "split-server.crt",
			SplitTLSKeyFile:  "split-server.key",
		}
	}

	cfg := remote()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() remote without tls_cert_file error = %v, want success", err)
	}

	cfg = remote()
	cfg.TLSCertFile = "tls.crt"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "tls_cert_file and tls_key_file must be configured together") {
		t.Fatalf("Validate() remote with tls_cert_file only error = %v, want pairing error", err)
	}

	cfg = remote()
	cfg.SplitTLSCertFile = ""
	cfg.SplitTLSKeyFile = ""
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "split_tls_cert_file") {
		t.Fatalf("Validate() remote without any certificate error = %v, want split certificate requirement", err)
	}
}

func TestValidateSplitLocalStillRequiresPublicTLSCertificate(t *testing.T) {
	cfg := Config{
		SMTPListen:       "0.0.0.0:587",
		IMAPListen:       "0.0.0.0:143",
		MaildirRoot:      t.TempDir(),
		Hostname:         "mail.example.test",
		SplitMode:        "on",
		SplitConnect:     "remote.example.test:1783",
		SplitTLSCertFile: "split-client.crt",
		SplitTLSKeyFile:  "split-client.key",
		Users:            map[string]User{"user@example.test": {Password: "example-password"}},
	}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "smtp_listen requires tls_cert_file and tls_key_file") {
		t.Fatalf("Validate() local without tls_cert_file error = %v, want TLS requirement", err)
	}
}

func TestValidateRemoteRoleRejectsConfiguredUsers(t *testing.T) {
	remote, err := Load(filepath.Join("..", "config-split-remote.yaml"))
	if err != nil {
		t.Fatalf("Load(config-split-remote.yaml) = %v", err)
	}
	remote.Users["user@example.test"] = User{Password: "example-password", Mailbox: "user"}

	err = remote.Validate()
	if err == nil || !strings.Contains(err.Error(), "remote role should not define users") {
		t.Fatalf("Validate() error = %v, want remote users rejection", err)
	}
}

func TestValidateSplitConfigInsecureSkipVerifyRequiresConnect(t *testing.T) {
	cfg := Config{
		SplitListen:             "127.0.0.1:1783",
		SplitInsecureSkipVerify: true,
	}
	err := validateSplitConfig(&cfg)
	if err == nil || !strings.Contains(err.Error(), "split_insecure_skip_verify requires split_connect") {
		t.Fatalf("validateSplitConfig() error = %v, want split_connect requirement", err)
	}
}

func TestValidateSplitConfigIgnoreServerNameRequiresConnect(t *testing.T) {
	cfg := Config{SplitIgnoreServerName: true}
	if err := validateSplitConfig(&cfg); err == nil || !strings.Contains(err.Error(), "split_ignore_server_name requires split_connect") {
		t.Fatalf("validateSplitConfig() error = %v, want split_connect requirement", err)
	}

	cfg.SplitConnect = "remote.example.test:1783"
	cfg.TLSCertFile = "tls.crt"
	cfg.TLSKeyFile = "tls.key"
	if err := validateSplitConfig(&cfg); err != nil {
		t.Fatalf("validateSplitConfig() with split_connect error = %v, want success", err)
	}
}

func TestSplitCertificateFilesUsesConfiguredPairOrMainPair(t *testing.T) {
	cfg := Config{TLSCertFile: "main.crt", TLSKeyFile: "main.key"}
	if certFile, keyFile := cfg.SplitCertificateFiles(); certFile != "main.crt" || keyFile != "main.key" {
		t.Fatalf("SplitCertificateFiles() fallback = %q, %q, want main TLS pair", certFile, keyFile)
	}

	cfg.SplitTLSCertFile = "split.crt"
	cfg.SplitTLSKeyFile = "split.key"
	if certFile, keyFile := cfg.SplitCertificateFiles(); certFile != "split.crt" || keyFile != "split.key" {
		t.Fatalf("SplitCertificateFiles() configured = %q, %q, want split TLS pair", certFile, keyFile)
	}
}

func TestValidateSplitConfigSplitTLSCertificatePair(t *testing.T) {
	cfg := Config{SplitConnect: "remote.example.test:1783"}
	if err := validateSplitConfig(&cfg); err == nil || !strings.Contains(err.Error(), "split mode requires split_tls_cert_file and split_tls_key_file, or tls_cert_file and tls_key_file") {
		t.Fatalf("validateSplitConfig() error = %v, want split TLS certificate requirement", err)
	}

	cfg = Config{
		SplitConnect:     "remote.example.test:1783",
		TLSCertFile:      "tls.crt",
		TLSKeyFile:       "tls.key",
		SplitTLSCertFile: "split.crt",
	}
	if err := validateSplitConfig(&cfg); err == nil || !strings.Contains(err.Error(), "split_tls_cert_file and split_tls_key_file must be configured together") {
		t.Fatalf("validateSplitConfig() error = %v, want paired split certificate requirement", err)
	}

	cfg.SplitTLSCertFile = ""
	cfg.SplitTLSKeyFile = "split.key"
	if err := validateSplitConfig(&cfg); err == nil || !strings.Contains(err.Error(), "split_tls_cert_file and split_tls_key_file must be configured together") {
		t.Fatalf("validateSplitConfig() error = %v, want paired split key requirement", err)
	}

	cfg.SplitTLSCertFile = "split.crt"
	if err := validateSplitConfig(&cfg); err != nil {
		t.Fatalf("validateSplitConfig() with main and split pairs error = %v, want success", err)
	}

	cfg.TLSCertFile = ""
	cfg.TLSKeyFile = ""
	if err := validateSplitConfig(&cfg); err != nil {
		t.Fatalf("validateSplitConfig() with split pair only error = %v, want success", err)
	}
}

func TestValidateSplitListenerRequiresCACert(t *testing.T) {
	cfg := Config{
		SplitListen: "127.0.0.1:1783",
		TLSCertFile: "tls.crt",
		TLSKeyFile:  "tls.key",
	}
	if err := validateSplitConfig(&cfg); err == nil || !strings.Contains(err.Error(), "split_ca_cert_file") {
		t.Fatalf("validateSplitConfig() error = %v, want split_ca_cert_file requirement", err)
	}

	cfg.SplitCACertFile = "split-ca.crt"
	if err := validateSplitConfig(&cfg); err != nil {
		t.Fatalf("validateSplitConfig() with CA error = %v, want success", err)
	}
}

func TestPasswordHashAuthenticatesAndValidationChecks(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("correct horse"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Defaults()
	cfg.Hostname = "smtp.example.test"
	cfg.TLSCertFile = "tls.crt"
	cfg.TLSKeyFile = "tls.key"
	cfg.MaildirRoot = t.TempDir()
	cfg.Users = map[string]User{"alice@example.test": {PasswordHash: string(hash)}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() with valid bcrypt hash = %v", err)
	}
	if !cfg.Authenticate("alice@example.test", "correct horse") {
		t.Fatal("Authenticate() rejected the correct bcrypt password")
	}
	if cfg.Authenticate("alice@example.test", "wrong horse") {
		t.Fatal("Authenticate() accepted an incorrect bcrypt password")
	}

	cfg.Users["alice@example.test"] = User{PasswordHash: "not-a-bcrypt-hash"}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "invalid bcrypt password_hash") {
		t.Fatalf("Validate() with malformed bcrypt hash = %v, want invalid hash error", err)
	}
}

func TestPasswordHashEnvironmentExpansion(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	literal := string(hash)
	t.Setenv("MYMAIL_TEST_PASSWORD_HASH", literal)

	cfg := Config{Users: map[string]User{
		"literal@example.test":  {PasswordHash: literal},
		"expanded@example.test": {PasswordHash: "${MYMAIL_TEST_PASSWORD_HASH}"},
	}}
	cfg.expandEnvironment()
	if got := cfg.Users["literal@example.test"].PasswordHash; got != literal {
		t.Fatalf("literal bcrypt hash expanded to %q, want unchanged hash", got)
	}
	if got := cfg.Users["expanded@example.test"].PasswordHash; got != literal {
		t.Fatalf("environment bcrypt hash = %q, want expanded hash", got)
	}
}

func TestAuthenticateAcceptsUppercaseSHA256(t *testing.T) {
	hash := sha256.Sum256([]byte("secret"))
	cfg := Config{Users: map[string]User{
		"alice@example.test": {PasswordSHA256: strings.ToUpper(hex.EncodeToString(hash[:]))},
	}}
	if !cfg.Authenticate("alice@example.test", "secret") {
		t.Fatal("Authenticate() rejected uppercase SHA-256 hash")
	}
}

func TestValidateDKIMOnlyOnSplitLocalSide(t *testing.T) {
	remote := Defaults()
	remote.SplitMode = "on"
	remote.SplitListen = "127.0.0.1:1783"
	remote.SplitCACertFile = "split-ca.crt"
	remote.Hostname = "smtp.example.test"
	remote.TLSCertFile = "tls.crt"
	remote.TLSKeyFile = "tls.key"
	remote.DKIM.Domain = "example.test"
	err := remote.Validate()
	if err == nil || !strings.Contains(err.Error(), "remote role should not configure dkim") {
		t.Fatalf("remote Validate() error = %v, want DKIM role restriction", err)
	}

	privateKey, publicKey := generateTestRSAKey(t)
	combined := Defaults()
	combined.SplitMode = "on"
	combined.SplitListen = "127.0.0.1:1783"
	combined.SplitConnect = "127.0.0.1:1784"
	combined.SplitCACertFile = "split-ca.crt"
	combined.Hostname = "smtp.example.test"
	combined.TLSCertFile = "tls.crt"
	combined.TLSKeyFile = "tls.key"
	combined.MaildirRoot = t.TempDir()
	combined.Users = map[string]User{"alice@example.test": {Password: "secret"}}
	combined.DKIM = DKIMConfig{
		Domain:     "example.test",
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		Selector:   "default",
	}
	if err := combined.Validate(); err != nil {
		t.Fatalf("combined local,remote Validate() error = %v", err)
	}
}

func TestValidateRemoteHostname(t *testing.T) {
	newRemoteConfig := func(hostname string) Config {
		cfg := Defaults()
		cfg.SplitMode = "on"
		cfg.SplitListen = "127.0.0.1:1783"
		cfg.SplitCACertFile = "split-ca.crt"
		cfg.TLSCertFile = "tls.crt"
		cfg.TLSKeyFile = "tls.key"
		cfg.Hostname = hostname
		return cfg
	}

	for _, hostname := range []string{"localhost", "LOCALHOST", "mail.localhost", "localhost.localdomain", "127.0.0.1", "::1", "mailhost"} {
		t.Run("reject_"+hostname, func(t *testing.T) {
			cfg := newRemoteConfig(hostname)
			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), "hostname must be the remote's public fully qualified domain name") {
				t.Fatalf("Validate() error = %v, want remote hostname validation error", err)
			}
		})
	}

	for _, hostname := range []string{"smtp.example.test", "smtp.example.test."} {
		t.Run("accept_"+hostname, func(t *testing.T) {
			cfg := newRemoteConfig(hostname)
			if err := cfg.Validate(); err != nil {
				t.Fatalf("Validate() error = %v, want valid remote hostname", err)
			}
		})
	}

	local := Defaults()
	local.TLSCertFile = "tls.crt"
	local.TLSKeyFile = "tls.key"
	local.Users = map[string]User{"alice@example.test": {Password: "secret"}}
	if err := local.Validate(); err != nil {
		t.Fatalf("non-split Validate() with default localhost hostname error = %v", err)
	}
}

func TestValidateSMTPRelayNetwork(t *testing.T) {
	for _, tt := range []struct {
		value string
		want  string
	}{
		{value: "", want: ""},
		{value: "tcp", want: "tcp"},
		{value: "tcp4", want: "tcp4"},
		{value: "TCP6", want: "tcp6"},
		{value: " TCP4 ", want: "tcp4"},
	} {
		t.Run(tt.value, func(t *testing.T) {
			cfg := Defaults()
			cfg.TLSCertFile = "tls.crt"
			cfg.TLSKeyFile = "tls.key"
			cfg.Users = map[string]User{"alice@example.test": {Password: "secret"}}
			cfg.SMTPRelayNetwork = tt.value
			if err := cfg.Validate(); err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
			if cfg.SMTPRelayNetwork != tt.want {
				t.Fatalf("SMTPRelayNetwork = %q, want %q", cfg.SMTPRelayNetwork, tt.want)
			}
		})
	}

	for _, value := range []string{"udp", "ipv4"} {
		t.Run("reject_"+value, func(t *testing.T) {
			cfg := Defaults()
			cfg.SMTPRelayNetwork = value
			if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "smtp_relay_network must be tcp, tcp4, or tcp6") {
				t.Fatalf("Validate() error = %v, want invalid relay network error", err)
			}
		})
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
smtp_listen: 127.0.0.1:2525
tls_cert_file: /etc/mymail/tls.crt
tls_key_file: /etc/mymail/tls.key
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
			config.TLSCertFile = "tls.crt"
			config.TLSKeyFile = "tls.key"
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
	testSender := os.Getenv("MYMAIL_TEST_SENDER")
	if testSender == "" {
		t.Fatal("MYMAIL_TEST_SENDER must be set before running tests")
	}
	testUsername := os.Getenv("MYMAIL_TEST_USERNAME")
	if testUsername == "" {
		t.Fatal("MYMAIL_TEST_USERNAME must be set before running tests")
	}
	testAddress := os.Getenv("MYMAIL_TEST_ADDRESS")
	if testAddress == "" {
		t.Fatal("MYMAIL_TEST_ADDRESS must be set before running tests")
	}
	_, testDomain, ok := strings.Cut(testAddress, "@")
	if !ok || testDomain == "" {
		t.Fatalf("MYMAIL_TEST_ADDRESS = %q, want an email address", testAddress)
	}
	alias := "alias@" + testDomain
	config := Config{
		Hostname: testDomain,
		Users: map[string]User{
			testAddress: {
				Password: "changeit",
				Mailbox:  testUsername,
				Aliases:  []string{testSender, alias},
			},
		},
	}
	for _, address := range []string{testSender, alias} {
		if mailbox, ok := config.Resolve(address); !ok || mailbox != testUsername {
			t.Fatalf("Resolve(%q) = %q, %t; want %s, true", address, mailbox, ok, testUsername)
		}
	}
	// Verify spam- and ham- prefixes resolve to the same mailbox
	senderLocalPart, senderDomain, hasSenderDomain := strings.Cut(testSender, "@")
	aliasLocalPart, aliasDomain, hasAliasDomain := strings.Cut(alias, "@")

	var prefixedAddresses []string
	prefixedAddresses = append(prefixedAddresses, "spam-"+testAddress, "ham-"+testAddress)
	if hasSenderDomain {
		prefixedAddresses = append(prefixedAddresses, "spam-"+senderLocalPart+"@"+senderDomain, "ham-"+senderLocalPart+"@"+senderDomain)
	}
	if hasAliasDomain {
		prefixedAddresses = append(prefixedAddresses, "spam-"+aliasLocalPart+"@"+aliasDomain, "ham-"+aliasLocalPart+"@"+aliasDomain)
	}
	for _, address := range prefixedAddresses {
		if mailbox, ok := config.Resolve(address); !ok || mailbox != testUsername {
			t.Fatalf("Resolve(%q) = %q, %t; want %s, true", address, mailbox, ok, testUsername)
		}
	}
	for _, domain := range []string{testDomain} {
		if !config.IsLocalDomain(domain) {
			t.Fatalf("IsLocalDomain(%q) = false", domain)
		}
	}
	if config.Authenticate(testSender, "changeit") {
		t.Fatal("alias unexpectedly authenticated as a primary user")
	}
}

func TestValidateRejectsDuplicateAliases(t *testing.T) {
	config := Config{
		SMTPListen:  "127.0.0.1:2525",
		IMAPListen:  "127.0.0.1:1143",
		TLSCertFile: "/etc/mymail/tls.crt",
		TLSKeyFile:  "/etc/mymail/tls.key",
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
		TLSCertFile: "/etc/mymail/tls.crt",
		TLSKeyFile:  "/etc/mymail/tls.key",
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
				TLSCertFile: "/etc/mymail/tls.crt",
				TLSKeyFile:  "/etc/mymail/tls.key",
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

func TestValidateRejectsMailboxControlCharacters(t *testing.T) {
	for _, mailbox := range []string{"alice\nUser: attacker", "alice\rUser: attacker"} {
		t.Run(fmt.Sprintf("%q", mailbox), func(t *testing.T) {
			config := Config{
				SMTPListen:  "127.0.0.1:2525",
				IMAPListen:  "127.0.0.1:1143",
				TLSCertFile: "/etc/mymail/tls.crt",
				TLSKeyFile:  "/etc/mymail/tls.key",
				MaildirRoot: t.TempDir(),
				Hostname:    "mail.example.test",
				Users: map[string]User{
					"alice@example.test": {Password: "secret", Mailbox: mailbox},
				},
			}
			if err := config.Validate(); err == nil {
				t.Fatal("Validate() accepted mailbox control characters")
			}
		})
	}
}

func TestLoadYAMLEnvironmentExpansion(t *testing.T) {
	t.Setenv("MYMAIL_SMTP_LISTEN", "127.0.0.1:3525")
	t.Setenv("MYMAIL_SMTP_CLEARTEXT_LISTEN", "127.0.0.1:3025")
	t.Setenv("MYMAIL_SMTP_TLS_LISTEN", "127.0.0.1:3465")
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
smtp_tls_listen: ${MYMAIL_SMTP_TLS_LISTEN}
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
	if got.SMTPListen != "127.0.0.1:3525" || got.SMTPCleartextListen != "127.0.0.1:3025" || got.SMTPTLSListen != "127.0.0.1:3465" || got.IMAPListen != "127.0.0.1:2143" {
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
		{
			name: "smtp tls listener requires certificate",
			body: "smtp_tls_listen: 127.0.0.1:2465\n",
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

func TestValidateSMTPListenRequiresTLSFiles(t *testing.T) {
	config := Config{
		SMTPListen:  "127.0.0.1:2525",
		IMAPListen:  "127.0.0.1:1143",
		MaildirRoot: t.TempDir(),
		Hostname:    "mail.example.test",
		Users:       map[string]User{"alice@example.test": {Password: "secret"}},
	}
	if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "smtp_listen requires tls_cert_file and tls_key_file") {
		t.Fatalf("Validate() error = %v, want smtp_listen TLS requirement", err)
	}
}

func TestValidateIMAPRequireSTARTTLSRequiresTLSFiles(t *testing.T) {
	config := Config{
		SMTPListen:          "127.0.0.1:2525",
		IMAPListen:          "127.0.0.1:1143",
		IMAPRequireSTARTTLS: true,
		MaildirRoot:         t.TempDir(),
		Hostname:            "mail.example.test",
		Users:               map[string]User{"alice@example.test": {Password: "secret"}},
	}
	if err := config.Validate(); err == nil {
		t.Fatal("Validate() succeeded without TLS certificate files")
	}
}

func TestValidateSMTPTLSListenRequiresTLSFiles(t *testing.T) {
	config := Config{SMTPTLSListen: "127.0.0.1:2465"}
	if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "smtp_tls_listen requires tls_cert_file and tls_key_file") {
		t.Fatalf("Validate() error = %v, want smtp_tls_listen TLS requirement", err)
	}
}

func generateTestRSAKey(t *testing.T) (string, string) {
	t.Helper()
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	privDER := x509.MarshalPKCS1PrivateKey(privKey)
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privDER,
	})
	pubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDER,
	})
	return string(privPEM), string(pubPEM)
}

func TestLoadYAMLDKIMConfiguration(t *testing.T) {
	privPEM, pubPEM := generateTestRSAKey(t)
	tmpDir := t.TempDir()
	privFile := filepath.Join(tmpDir, "dkim.key")
	pubFile := filepath.Join(tmpDir, "dkim.pub")
	if err := os.WriteFile(privFile, []byte(privPEM), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pubFile, []byte(pubPEM), 0644); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(tmpDir, "config.yaml")
	contents := []byte(fmt.Sprintf(`smtp_listen: 127.0.0.1:2525
imap_listen: 127.0.0.1:1143
tls_cert_file: /etc/mymail/tls.crt
tls_key_file: /etc/mymail/tls.key
maildir_root: %s/mail
hostname: mail.thepratts.info
dkim:
  domain: thepratts.info
  private_key: %s
  public_key: %s
  selector: default2026
users:
  alice@thepratts.info:
    password: secret
`, tmpDir, privFile, pubFile))

	if err := os.WriteFile(path, contents, 0600); err != nil {
		t.Fatal(err)
	}

	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if got.DKIM.Domain != "thepratts.info" {
		t.Errorf("DKIM.Domain = %q, want thepratts.info", got.DKIM.Domain)
	}
	if got.DKIM.PrivateKey != privFile {
		t.Errorf("DKIM.PrivateKey = %q, want %q", got.DKIM.PrivateKey, privFile)
	}
	if got.DKIM.PublicKey != pubFile {
		t.Errorf("DKIM.PublicKey = %q, want %q", got.DKIM.PublicKey, pubFile)
	}
	if got.DKIM.Selector != "default2026" {
		t.Errorf("DKIM.Selector = %q, want default2026", got.DKIM.Selector)
	}
	if !got.HasDKIM() {
		t.Error("HasDKIM() = false, want true")
	}
}

func TestValidateDKIMConfigurationMustBeConfiguredTogether(t *testing.T) {
	privPEM, pubPEM := generateTestRSAKey(t)
	tests := []struct {
		name       string
		domain     string
		privateKey string
		publicKey  string
		selector   string
	}{
		{
			name:   "only domain",
			domain: "thepratts.info",
		},
		{
			name:       "only private key",
			privateKey: privPEM,
		},
		{
			name:      "only public key",
			publicKey: pubPEM,
		},
		{
			name:     "only selector",
			selector: "default",
		},
		{
			name:       "domain and private key without public key and selector",
			domain:     "thepratts.info",
			privateKey: privPEM,
		},
		{
			name:      "domain and public key without private key and selector",
			domain:    "thepratts.info",
			publicKey: pubPEM,
		},
		{
			name:       "private and public key without domain and selector",
			privateKey: privPEM,
			publicKey:  pubPEM,
		},
		{
			name:       "domain, private key, and public key without selector",
			domain:     "thepratts.info",
			privateKey: privPEM,
			publicKey:  pubPEM,
		},
		{
			name:       "domain, private key, and selector without public key",
			domain:     "thepratts.info",
			privateKey: privPEM,
			selector:   "default",
		},
		{
			name:      "domain, public key, and selector without private key",
			domain:    "thepratts.info",
			publicKey: pubPEM,
			selector:  "default",
		},
		{
			name:       "private key, public key, and selector without domain",
			privateKey: privPEM,
			publicKey:  pubPEM,
			selector:   "default",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.TLSCertFile = "tls.crt"
			cfg.TLSKeyFile = "tls.key"
			cfg.MaildirRoot = t.TempDir()
			cfg.Hostname = "mail.thepratts.info"
			cfg.Users = map[string]User{"alice@thepratts.info": {Password: "secret"}}
			cfg.DKIM = DKIMConfig{
				Domain:     tt.domain,
				PrivateKey: tt.privateKey,
				PublicKey:  tt.publicKey,
				Selector:   tt.selector,
			}

			if err := cfg.Validate(); err == nil {
				t.Error("Validate() accepted incomplete DKIM configuration")
			}
			if cfg.HasDKIM() {
				t.Error("HasDKIM() = true for incomplete configuration")
			}
		})
	}
}

func TestValidateDKIMRejectsInvalidKeys(t *testing.T) {
	_, pubPEM := generateTestRSAKey(t)
	cfg := Defaults()
	cfg.TLSCertFile = "tls.crt"
	cfg.TLSKeyFile = "tls.key"
	cfg.MaildirRoot = t.TempDir()
	cfg.Hostname = "mail.thepratts.info"
	cfg.Users = map[string]User{"alice@thepratts.info": {Password: "secret"}}
	cfg.DKIM = DKIMConfig{
		Domain:     "thepratts.info",
		PrivateKey: "invalid-private-key-data",
		PublicKey:  pubPEM,
		Selector:   "default",
	}

	if err := cfg.Validate(); err == nil {
		t.Error("Validate() accepted invalid DKIM private key")
	}
}

func TestValidateDKIMRejectsMismatchedKeys(t *testing.T) {
	privPEM1, _ := generateTestRSAKey(t)
	_, pubPEM2 := generateTestRSAKey(t)

	cfg := Defaults()
	cfg.TLSCertFile = "tls.crt"
	cfg.TLSKeyFile = "tls.key"
	cfg.MaildirRoot = t.TempDir()
	cfg.Hostname = "mail.thepratts.info"
	cfg.Users = map[string]User{"alice@thepratts.info": {Password: "secret"}}
	cfg.DKIM = DKIMConfig{
		Domain:     "thepratts.info",
		PrivateKey: privPEM1,
		PublicKey:  pubPEM2,
		Selector:   "default",
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() accepted mismatched DKIM key pair")
	}
	if !strings.Contains(err.Error(), "key") {
		t.Errorf("expected error message to mention key mismatch, got: %v", err)
	}
}

func TestLoadYAMLDKIMConfigurationInlinePEM(t *testing.T) {
	privPEM, pubPEM := generateTestRSAKey(t)
	tmpDir := t.TempDir()

	path := filepath.Join(tmpDir, "config.yaml")
	contents := []byte(fmt.Sprintf(`smtp_listen: 127.0.0.1:2525
imap_listen: 127.0.0.1:1143
tls_cert_file: /etc/mymail/tls.crt
tls_key_file: /etc/mymail/tls.key
maildir_root: %s/mail
hostname: mail.thepratts.info
dkim:
  domain: thepratts.info
  private_key: |
%s
  public_key: |
%s
  selector: default2026
users:
  alice@thepratts.info:
    password: secret
`, tmpDir, indentString(privPEM, 4), indentString(pubPEM, 4)))

	if err := os.WriteFile(path, contents, 0600); err != nil {
		t.Fatal(err)
	}

	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !got.HasDKIM() {
		t.Error("HasDKIM() = false, want true")
	}
}

func TestLoadYAMLDKIMConfigurationMissingFileReportsClearError(t *testing.T) {
	_, pubPEM := generateTestRSAKey(t)
	tmpDir := t.TempDir()
	missingFile := filepath.Join(tmpDir, "nonexistent", "dkim.key")

	path := filepath.Join(tmpDir, "config.yaml")
	contents := []byte(fmt.Sprintf(`smtp_listen: 127.0.0.1:2525
imap_listen: 127.0.0.1:1143
tls_cert_file: /etc/mymail/tls.crt
tls_key_file: /etc/mymail/tls.key
maildir_root: %s/mail
hostname: mail.thepratts.info
dkim:
  domain: thepratts.info
  private_key: %s
  public_key: |
%s
  selector: default2026
users:
  alice@thepratts.info:
    password: secret
`, tmpDir, missingFile, indentString(pubPEM, 4)))

	if err := os.WriteFile(path, contents, 0600); err != nil {
		t.Fatal(err)
	}

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected Load() to fail on missing key file, got nil")
	}
	if !strings.Contains(err.Error(), "read private key file") {
		t.Errorf("expected error to mention 'read private key file', got: %v", err)
	}
}

func indentString(s string, spaces int) string {
	pad := strings.Repeat(" ", spaces)
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, line := range lines {
		lines[i] = pad + line
	}
	return strings.Join(lines, "\n")
}
