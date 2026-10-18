package main

import (
	"net/mail"
	"strings"
	"testing"
)

func TestBuildMessage(t *testing.T) {
	from, err := mail.ParseAddress("kpratt@example.test")
	if err != nil {
		t.Fatal(err)
	}
	to, err := mail.ParseAddress("bob@example.test")
	if err != nil {
		t.Fatal(err)
	}

	message, err := buildMessage(from, to, "Test subject", "hello from mymail-send")
	if err != nil {
		t.Fatal(err)
	}
	content := string(message)
	for _, want := range []string{
		"From: kpratt@example.test\r\n",
		"To: bob@example.test\r\n",
		"Subject: Test subject\r\n",
		"Content-Type: text/plain; charset=UTF-8\r\n",
		"\r\nhello from mymail-send\r\n",
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("message = %q, missing %q", content, want)
		}
	}
}

func TestBuildMessageRejectsHeaderInjection(t *testing.T) {
	from, _ := mail.ParseAddress("kpratt@example.test")
	to, _ := mail.ParseAddress("bob@example.test")
	if _, err := buildMessage(from, to, "bad\r\nBcc: attacker@example.test", "body"); err == nil {
		t.Fatal("buildMessage accepted a subject containing a newline")
	}
}

func TestParseAddressRejectsInvalidAddress(t *testing.T) {
	if _, err := parseAddress("not-an-address", "to"); err == nil {
		t.Fatal("parseAddress accepted an invalid address")
	}
}
