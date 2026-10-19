package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	contents := []byte(`smtp_listen: 127.0.0.1:2525
smtp_tls_listen: 127.0.0.1:2465
imap_listen: 127.0.0.1:1143
imap_tls_listen: 127.0.0.1:1993
tls_cert_file: /etc/mymail/tls.crt
tls_key_file: /etc/mymail/tls.key
maildir_root: /var/lib/mymail
hostname: mail.example.test
users:
  Alice@Example.Test:
    password: secret
    mailbox: alice
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
	if got.SMTPListen != "127.0.0.1:2525" || got.IMAPListen != "127.0.0.1:1143" {
		t.Fatalf("listeners = %#v", got)
	}
	if got.SMTPTLSListen != "127.0.0.1:2465" || got.IMAPTLSListen != "127.0.0.1:1993" {
		t.Fatalf("TLS listeners = %#v", got)
	}
	if got.TLSCertFile != "/etc/mymail/tls.crt" || got.TLSKeyFile != "/etc/mymail/tls.key" {
		t.Fatalf("TLS certificate files = %#v", got)
	}
	if got.MaildirRoot != "/var/lib/mymail" || got.Hostname != "mail.example.test" {
		t.Fatalf("server settings = %#v", got)
	}
	if !got.Authenticate("alice@example.test", "secret") {
		t.Fatal("Authenticate() rejected valid YAML credentials")
	}
	if !got.Authenticate("alice", "secret") {
		t.Fatal("Authenticate() rejected the local username for a full-address account")
	}
	if mailbox, ok := got.Resolve("alice@example.test"); !ok || mailbox != "alice" {
		t.Fatalf("Resolve() = %q, %t", mailbox, ok)
	}
	if mailbox, ok := got.Resolve("alice"); !ok || mailbox != "alice" {
		t.Fatalf("Resolve() for local username = %q, %t", mailbox, ok)
	}
	if mailbox, ok := got.Resolve("alias@example.test"); !ok || mailbox != "alice" {
		t.Fatalf("Resolve() for alias = %q, %t", mailbox, ok)
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

func TestLoadYAMLEnvironmentExpansion(t *testing.T) {
	t.Setenv("MYMAIL_SMTP_LISTEN", "127.0.0.1:3525")
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
	path := filepath.Join(t.TempDir(), "config.yaml")
	contents := []byte(`smtp_listen: ${MYMAIL_SMTP_LISTEN}
smtp_tls_listen: ${MYMAIL_SMTP_TLS_LISTEN}
imap_listen: ${MYMAIL_IMAP_LISTEN}
imap_tls_listen: ${MYMAIL_IMAP_TLS_LISTEN}
tls_cert_file: ${MYMAIL_TLS_CERT}
tls_key_file: ${MYMAIL_TLS_KEY}
maildir_root: ${MYMAIL_ROOT}/mymail
hostname: ${MYMAIL_HOSTNAME}
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
	if got.SMTPListen != "127.0.0.1:3525" || got.IMAPListen != "127.0.0.1:2143" {
		t.Fatalf("listeners = %#v", got)
	}
	if got.SMTPTLSListen != "127.0.0.1:3465" || got.IMAPTLSListen != "127.0.0.1:2993" {
		t.Fatalf("TLS listeners = %#v", got)
	}
	if got.TLSCertFile != "/etc/mymail/mail.crt" || got.TLSKeyFile != "/etc/mymail/mail.key" {
		t.Fatalf("TLS certificate files = %#v", got)
	}
	if got.MaildirRoot != os.Getenv("MYMAIL_ROOT")+"/mymail" || got.Hostname != "mail.test" {
		t.Fatalf("server settings = %#v", got)
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
			body: "smtp_tls_listen: 127.0.0.1:2465\n",
		},
		{
			name: "missing key",
			body: "tls_cert_file: /etc/mymail/tls.crt\nimap_tls_listen: 127.0.0.1:1993\n",
		},
		{
			name: "certificate without endpoint",
			body: "tls_cert_file: /etc/mymail/tls.crt\ntls_key_file: /etc/mymail/tls.key\n",
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
