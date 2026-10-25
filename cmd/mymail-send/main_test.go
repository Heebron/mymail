package main

import (
	"net/mail"
	"os"
	"strings"
	"testing"
)

func testAddress(t *testing.T) string {
	t.Helper()
	address := os.Getenv("MYMAIL_TEST_ADDRESS")
	if address == "" {
		t.Fatal("MYMAIL_TEST_ADDRESS must be set before running tests")
	}
	return address
}

func TestBuildMessage(t *testing.T) {
	address := testAddress(t)
	from, err := mail.ParseAddress(address)
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
		"From: " + address + "\r\n",
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

func TestBuildMessageWithRecipients(t *testing.T) {
	from, _ := mail.ParseAddress(testAddress(t))
	to, _ := mail.ParseAddress("bob@example.test")
	cc, _ := mail.ParseAddress("carol@example.test")

	message, err := buildMessageWithRecipients(from, []*mail.Address{to}, []*mail.Address{cc}, "Test subject", "body")
	if err != nil {
		t.Fatal(err)
	}
	content := string(message)
	for _, want := range []string{
		"To: bob@example.test\r\n",
		"Cc: carol@example.test\r\n",
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("message = %q, missing %q", content, want)
		}
	}
	if strings.Contains(content, "Bcc:") {
		t.Fatalf("message unexpectedly contains Bcc header: %q", content)
	}
}

func TestParseAddressesSupportsLists(t *testing.T) {
	addresses, err := parseAddresses([]string{"bob@example.test, Carol <carol@example.test>", "dave@example.test"}, "to")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(addresses), 3; got != want {
		t.Fatalf("parsed %d addresses, want %d", got, want)
	}
}

func TestBuildMessageRejectsHeaderInjection(t *testing.T) {
	from, _ := mail.ParseAddress(testAddress(t))
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
