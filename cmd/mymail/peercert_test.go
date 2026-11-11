package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509/pkix"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mymail/config"
)

func writeTestPeerCertificate(t *testing.T, commonName string, dnsNames []string, notAfter time.Time) (certFile, keyFile string, certPEM, keyPEM []byte) {
	t.Helper()
	dir := t.TempDir()
	certFile = filepath.Join(dir, "tls.crt")
	keyFile = filepath.Join(dir, "tls.key")
	certificate := generateTestTLSCertificateWithExpiry(t, pkix.Name{CommonName: commonName}, dnsNames, nil, nil, nil, notAfter)
	writeTestTLSCertificatePair(t, certFile, keyFile, certificate)
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err = os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile, certPEM, keyPEM
}

func servedCommonName(t *testing.T, store *peerCertificateStore) string {
	t.Helper()
	certificate, err := store.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("GetCertificate() error = %v", err)
	}
	return certificate.Leaf.Subject.CommonName
}

func TestPeerCertificateStoreInstallsReceivedCertificate(t *testing.T) {
	var logs bytes.Buffer
	store := newPeerCertificateStore("smtp.example.test", slog.New(slog.NewJSONHandler(&logs, nil)))
	if store.Available() {
		t.Fatal("Available() = true before a certificate was received")
	}
	if _, err := store.GetCertificate(&tls.ClientHelloInfo{}); err == nil {
		t.Fatal("GetCertificate() succeeded before a certificate was received")
	}

	_, _, certPEM, keyPEM := writeTestPeerCertificate(t, "smtp.example.test", []string{"smtp.example.test"}, time.Now().Add(90*24*time.Hour))
	if err := store.Set(certPEM, keyPEM); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	if !store.Available() {
		t.Fatal("Available() = false after a certificate was received")
	}
	if got := servedCommonName(t, store); got != "smtp.example.test" {
		t.Fatalf("served certificate CN = %q, want smtp.example.test", got)
	}
	if !strings.Contains(logs.String(), receivedCertificateLabel) {
		t.Fatalf("received certificate was not logged: %s", logs.String())
	}
	if strings.Contains(logs.String(), "PRIVATE KEY") {
		t.Fatalf("private key material was logged: %s", logs.String())
	}
	if strings.Contains(logs.String(), "does not match hostname") {
		t.Fatalf("matching certificate logged a hostname warning: %s", logs.String())
	}
}

func TestPeerCertificateStoreWarnsOnHostnameMismatch(t *testing.T) {
	var logs bytes.Buffer
	store := newPeerCertificateStore("smtp.example.test", slog.New(slog.NewJSONHandler(&logs, nil)))
	_, _, certPEM, keyPEM := writeTestPeerCertificate(t, "other.example.test", []string{"other.example.test"}, time.Now().Add(90*24*time.Hour))
	if err := store.Set(certPEM, keyPEM); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	if !strings.Contains(logs.String(), "does not match hostname") || !strings.Contains(logs.String(), "other.example.test") {
		t.Fatalf("hostname mismatch was not reported: %s", logs.String())
	}
}

func TestPeerCertificateStoreRejectsInvalidCertificatesAndKeepsCurrent(t *testing.T) {
	store := newPeerCertificateStore("", slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil)))
	_, _, currentCert, currentKey := writeTestPeerCertificate(t, "current.example.test", nil, time.Now().Add(90*24*time.Hour))
	if err := store.Set(currentCert, currentKey); err != nil {
		t.Fatalf("Set(current) error = %v", err)
	}

	_, _, otherCert, otherKey := writeTestPeerCertificate(t, "other.example.test", nil, time.Now().Add(90*24*time.Hour))
	_, _, expiredCert, expiredKey := writeTestPeerCertificate(t, "expired.example.test", nil, time.Now().Add(-30*time.Minute))
	tests := map[string]struct {
		cert, key []byte
		want      string
	}{
		"mismatched key": {cert: otherCert, key: currentKey, want: "invalid TLS certificate or private key"},
		"not PEM":        {cert: []byte("certificate"), key: otherKey, want: "invalid TLS certificate or private key"},
		"expired":        {cert: expiredCert, key: expiredKey, want: "expired"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := store.Set(test.cert, test.key)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Set() error = %v, want %q", err, test.want)
			}
			if got := servedCommonName(t, store); got != "current.example.test" {
				t.Fatalf("served certificate CN = %q after rejection, want current.example.test", got)
			}
		})
	}
}

func TestSendSplitTLSCertificateSendsConfiguredFiles(t *testing.T) {
	certFile, keyFile, certPEM, keyPEM := writeTestPeerCertificate(t, "smtp.example.test", nil, time.Now().Add(90*24*time.Hour))
	cfg := &config.Config{TLSCertFile: certFile, TLSKeyFile: keyFile, SplitConnect: "remote.example.test:1783"}
	var sentCert, sentKey []byte
	err := sendSplitTLSCertificate(cfg, func(cert, key []byte) error {
		sentCert, sentKey = cert, key
		return nil
	}, slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil)))
	if err != nil {
		t.Fatalf("sendSplitTLSCertificate() error = %v", err)
	}
	if !bytes.Equal(sentCert, certPEM) || !bytes.Equal(sentKey, keyPEM) {
		t.Fatal("sendSplitTLSCertificate() did not send the configured certificate and key")
	}

	sendErr := errors.New("remote rejected certificate")
	err = sendSplitTLSCertificate(cfg, func([]byte, []byte) error { return sendErr }, slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil)))
	if !errors.Is(err, sendErr) {
		t.Fatalf("sendSplitTLSCertificate() error = %v, want %v", err, sendErr)
	}
}

func TestSendSplitTLSCertificateSkipsUnverifiedRemote(t *testing.T) {
	certFile, keyFile, _, _ := writeTestPeerCertificate(t, "smtp.example.test", nil, time.Now().Add(90*24*time.Hour))
	cfg := &config.Config{TLSCertFile: certFile, TLSKeyFile: keyFile, SplitConnect: "remote.example.test:1783", SplitInsecureSkipVerify: true}
	var logs bytes.Buffer
	err := sendSplitTLSCertificate(cfg, func([]byte, []byte) error {
		t.Fatal("private key sent to a remote whose certificate is not verified")
		return nil
	}, slog.New(slog.NewJSONHandler(&logs, nil)))
	if err != nil {
		t.Fatalf("sendSplitTLSCertificate() error = %v", err)
	}
	if !strings.Contains(logs.String(), "split_insecure_skip_verify") {
		t.Fatalf("skipped certificate send was not explained: %s", logs.String())
	}
}

func TestSendSplitTLSCertificateReportsUnreadableFiles(t *testing.T) {
	cfg := &config.Config{TLSCertFile: "/missing/tls.crt", TLSKeyFile: "/missing/tls.key"}
	err := sendSplitTLSCertificate(cfg, func([]byte, []byte) error {
		t.Fatal("send called without a readable certificate")
		return nil
	}, slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil)))
	if err == nil || !strings.Contains(err.Error(), "tls_cert_file") {
		t.Fatalf("sendSplitTLSCertificate() error = %v, want tls_cert_file read error", err)
	}
}
