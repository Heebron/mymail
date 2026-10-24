package main

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"mymail/config"
)

func TestConfigLogUsersRedactsPasswords(t *testing.T) {
	users := configLogUsers(map[string]config.User{
		"alice@example.test": {
			Password:       "cleartext-secret",
			PasswordSHA256: "hashed-secret",
			Mailbox:        "alice",
			Aliases:        []string{"a@example.test"},
		},
	})

	data, err := json.Marshal(users)
	if err != nil {
		t.Fatal(err)
	}
	output := string(data)
	for _, secret := range []string{"cleartext-secret", "hashed-secret"} {
		if output == "" {
			t.Fatal("config log output is empty")
		}
		if strings.Contains(output, secret) {
			t.Fatalf("config log output contains password %q: %s", secret, output)
		}
	}
	if !strings.Contains(output, `"has_password":true`) || !strings.Contains(output, `"has_password_sha256":true`) {
		t.Fatalf("config log output omits credential presence: %s", output)
	}
}

func TestLogConfigUsersWritesOneRecordPerUser(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))
	logConfigUsers(logger, map[string]config.User{
		"bob@example.test": {
			Password: "bob-secret",
			Mailbox:  "bob",
		},
		"alice@example.test": {
			PasswordSHA256: "alice-secret",
			Mailbox:        "alice",
		},
	})

	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("configuration log record count = %d, want 2: %s", len(lines), output.String())
	}
	for index, wantUsername := range []string{"alice@example.test", "bob@example.test"} {
		var record map[string]any
		if err := json.Unmarshal([]byte(lines[index]), &record); err != nil {
			t.Fatalf("decode configuration log record %d: %v", index, err)
		}
		if record["msg"] != "configuration user" {
			t.Errorf("record %d message = %v, want configuration user", index, record["msg"])
		}
		if record["username"] != wantUsername {
			t.Errorf("record %d username = %v, want %s", index, record["username"], wantUsername)
		}
	}
	for _, secret := range []string{"bob-secret", "alice-secret"} {
		if strings.Contains(output.String(), secret) {
			t.Errorf("configuration log contains password %q: %s", secret, output.String())
		}
	}
}

func TestLogCleartextPasswordWarnings(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))
	logCleartextPasswordWarnings(logger, map[string]config.User{
		"bob@example.test": {
			Password:       "bob-secret",
			PasswordSHA256: "ignored-when-password-is-set",
		},
		"alice@example.test": {
			PasswordSHA256: "alice-secret",
		},
	})

	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("cleartext password warning count = %d, want 1: %s", len(lines), output.String())
	}
	var record map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &record); err != nil {
		t.Fatal(err)
	}
	if record["level"] != "WARN" {
		t.Fatalf("warning level = %v, want WARN", record["level"])
	}
	if record["msg"] != "configuration user uses cleartext password" {
		t.Fatalf("warning message = %v", record["msg"])
	}
	if record["username"] != "bob@example.test" {
		t.Fatalf("warning username = %v", record["username"])
	}
	for _, secret := range []string{"bob-secret", "ignored-when-password-is-set", "alice-secret"} {
		if strings.Contains(output.String(), secret) {
			t.Fatalf("cleartext password warning contains credential material %q: %s", secret, output.String())
		}
	}
}
