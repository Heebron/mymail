package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mymail/dkim"
)

func TestRunDefault(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"-bits", "1024"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run failed with code %d, stderr: %s", code, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "Domain:       example.com") {
		t.Errorf("stdout does not contain default domain: %s", out)
	}
	if !strings.Contains(out, "Selector:     default") {
		t.Errorf("stdout does not contain default selector: %s", out)
	}
	if !strings.Contains(out, "default._domainkey.example.com.") {
		t.Errorf("stdout does not contain DNS record name: %s", out)
	}
	if !strings.Contains(out, "-----BEGIN RSA PRIVATE KEY-----") {
		t.Errorf("stdout does not contain PEM private key: %s", out)
	}
	if !strings.Contains(out, "-----BEGIN PUBLIC KEY-----") {
		t.Errorf("stdout does not contain PEM public key: %s", out)
	}
}

func TestRunCustomFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"-domain", "thepratts.info", "-selector", "mail2026", "-bits", "1024"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run failed with code %d, stderr: %s", code, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "Domain:       thepratts.info") {
		t.Errorf("stdout does not contain expected domain: %s", out)
	}
	if !strings.Contains(out, "Selector:     mail2026") {
		t.Errorf("stdout does not contain expected selector: %s", out)
	}
	if !strings.Contains(out, "mail2026._domainkey.thepratts.info.") {
		t.Errorf("stdout does not contain expected DNS record name: %s", out)
	}
}

func TestRunPositionalDomain(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"-bits", "1024", "mycompany.org"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run failed with code %d, stderr: %s", code, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "Domain:       mycompany.org") {
		t.Errorf("stdout does not contain expected domain: %s", out)
	}
	if !strings.Contains(out, "default._domainkey.mycompany.org.") {
		t.Errorf("stdout does not contain expected DNS record name: %s", out)
	}
}

func TestRunInvalidBits(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"-bits", "512"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit code 1 for small bits, got %d", code)
	}
	if !strings.Contains(stderr.String(), "too small") {
		t.Errorf("expected 'too small' in stderr, got: %s", stderr.String())
	}
}

func TestRunJSONOutput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"-domain", "example.org", "-selector", "sig1", "-bits", "1024", "-json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run failed with code %d, stderr: %s", code, stderr.String())
	}

	var res Result
	if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v, raw: %s", err, stdout.String())
	}

	if res.Domain != "example.org" {
		t.Errorf("res.Domain = %q, want 'example.org'", res.Domain)
	}
	if res.Selector != "sig1" {
		t.Errorf("res.Selector = %q, want 'sig1'", res.Selector)
	}
	if res.RecordName != "sig1._domainkey.example.org." {
		t.Errorf("res.RecordName = %q, want 'sig1._domainkey.example.org.'", res.RecordName)
	}
	if !strings.HasPrefix(res.RecordValue, "v=DKIM1; k=rsa; p=") {
		t.Errorf("res.RecordValue does not start with standard prefix: %s", res.RecordValue)
	}

	privKey, err := dkim.ParsePrivateKey([]byte(res.PrivateKeyPEM))
	if err != nil {
		t.Fatalf("failed to parse generated private key: %v", err)
	}
	pubKey, err := dkim.ParsePublicKey([]byte(res.PublicKeyPEM))
	if err != nil {
		t.Fatalf("failed to parse generated public key: %v", err)
	}
	if err := dkim.ValidateKeyPair(privKey, pubKey); err != nil {
		t.Fatalf("key pair mismatch: %v", err)
	}
}

func TestRunQuietMode(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"-domain", "example.org", "-bits", "1024", "-quiet"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run failed with code %d, stderr: %s", code, stderr.String())
	}
	out := strings.TrimSpace(stdout.String())
	if !strings.HasPrefix(out, "v=DKIM1; k=rsa; p=") {
		t.Fatalf("quiet mode output should be DNS TXT record value, got: %s", out)
	}
}

func TestRunFileOutputs(t *testing.T) {
	tmpDir := t.TempDir()
	outDir := filepath.Join(tmpDir, "keys")

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"-domain", "example.com",
		"-selector", "testsel",
		"-bits", "1024",
		"-out", outDir,
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("run failed with code %d, stderr: %s", code, stderr.String())
	}

	privPath := filepath.Join(outDir, "testsel.private.key")
	pubPath := filepath.Join(outDir, "testsel.public.key")
	dnsPath := filepath.Join(outDir, "testsel.dns.txt")

	privInfo, err := os.Stat(privPath)
	if err != nil {
		t.Fatalf("private key file not created: %v", err)
	}
	if perm := privInfo.Mode().Perm(); perm != 0600 {
		t.Errorf("private key permissions = %#o, want 0600", perm)
	}

	if _, err := os.Stat(pubPath); err != nil {
		t.Fatalf("public key file not created: %v", err)
	}
	if _, err := os.Stat(dnsPath); err != nil {
		t.Fatalf("dns txt record file not created: %v", err)
	}

	privKey, err := dkim.LoadPrivateKey(privPath)
	if err != nil {
		t.Fatalf("load private key from file: %v", err)
	}
	pubKey, err := dkim.LoadPublicKey(pubPath)
	if err != nil {
		t.Fatalf("load public key from file: %v", err)
	}
	if err := dkim.ValidateKeyPair(privKey, pubKey); err != nil {
		t.Fatalf("validate loaded key pair: %v", err)
	}

	dnsBytes, err := os.ReadFile(dnsPath)
	if err != nil {
		t.Fatalf("read dns txt file: %v", err)
	}
	pubKeyFromDNS, err := dkim.ParsePublicKey(dnsBytes)
	if err != nil {
		t.Fatalf("parse public key from dns record file: %v", err)
	}
	if err := dkim.ValidateKeyPair(privKey, pubKeyFromDNS); err != nil {
		t.Fatalf("validate key pair with dns record: %v", err)
	}

	// Test signing and verifying an actual message.
	signer, err := dkim.NewSigner("example.com", "testsel", privPath, pubPath)
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}
	msg := []byte("From: user@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nHello World!\r\n")
	signed, err := signer.Sign(msg)
	if err != nil {
		t.Fatalf("sign message: %v", err)
	}

	if err := dkim.Verify(signed, pubKey); err != nil {
		t.Fatalf("verify signed message: %v", err)
	}
}

func TestRunCustomOutputPaths(t *testing.T) {
	tmpDir := t.TempDir()
	privPath := filepath.Join(tmpDir, "custom.priv")
	pubPath := filepath.Join(tmpDir, "custom.pub")
	dnsPath := filepath.Join(tmpDir, "custom.txt")

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"-domain", "mail.example.org",
		"-selector", "custom",
		"-bits", "1024",
		"-priv-out", privPath,
		"-pub-out", pubPath,
		"-dns-out", dnsPath,
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("run failed with code %d, stderr: %s", code, stderr.String())
	}

	privKey, err := dkim.LoadPrivateKey(privPath)
	if err != nil {
		t.Fatalf("load private key: %v", err)
	}
	pubKey, err := dkim.LoadPublicKey(pubPath)
	if err != nil {
		t.Fatalf("load public key: %v", err)
	}
	if err := dkim.ValidateKeyPair(privKey, pubKey); err != nil {
		t.Fatalf("key pair validation: %v", err)
	}
}
