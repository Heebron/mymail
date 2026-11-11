package main

import (
	"bytes"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestPasswordHashProducesBcrypt(t *testing.T) {
	hash, err := passwordHash("changeit", bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("changeit")); err != nil {
		t.Fatalf("bcrypt hash does not verify: %v", err)
	}
}

func TestRunReadsPasswordFromStdin(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run(nil, strings.NewReader("changeit\n"), &stdout, &stderr); err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(strings.TrimSpace(stdout.String())), []byte("changeit")); err != nil {
		t.Fatalf("stdout hash does not verify: %v", err)
	}
}

func TestRunRejectsPositionalPassword(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := run([]string{"changeit"}, strings.NewReader(""), &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "standard input") {
		t.Fatalf("run() error = %v, want positional-password rejection", err)
	}
}

func TestRunRejectsEmptyPassword(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := run(nil, strings.NewReader("\n"), &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "must not be empty") {
		t.Fatalf("run() error = %v, want empty-password rejection", err)
	}
}

func TestRunRejectsPasswordsOverBcryptLimit(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := run(nil, strings.NewReader(strings.Repeat("a", 73)), &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "72 bytes") {
		t.Fatalf("run() error = %v, want bcrypt length rejection", err)
	}
}
