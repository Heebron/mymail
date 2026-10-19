package main

import (
	"encoding/json"
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
