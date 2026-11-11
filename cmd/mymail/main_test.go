package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"mymail/config"
	"mymail/plugins"
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

func TestRegisterConfiguredPlugins(t *testing.T) {
	processors := plugins.New()
	if err := registerConfiguredPlugins(processors, []config.PluginConfig{{Name: "spamd"}}); err != nil {
		t.Fatal(err)
	}

	failures := processors.Initialize(context.Background(), []config.PluginConfig{{
		Name:   "spamd",
		Config: map[string]string{"timeout": "invalid"},
	}})
	if len(failures) != 1 || failures[0].Processor.Name() != "spamd" {
		t.Fatalf("initialization failures = %#v, want one spamd failure", failures)
	}
}

func generateTestTLSCertificate(t *testing.T, subject pkix.Name, dnsNames []string, ips []net.IP, emails []string, uris []*url.URL) tls.Certificate {
	return generateTestTLSCertificateWithExpiry(t, subject, dnsNames, ips, emails, uris, time.Now().Add(90*24*time.Hour))
}

func generateTestTLSCertificateWithExpiry(t *testing.T, subject pkix.Name, dnsNames []string, ips []net.IP, emails []string, uris []*url.URL, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               subject,
		DNSNames:              dnsNames,
		IPAddresses:           ips,
		EmailAddresses:        emails,
		URIs:                  uris,
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}
}

func writeTestTLSCertificatePair(t *testing.T, certFile, keyFile string, certificate tls.Certificate) {
	t.Helper()
	privateKey, ok := certificate.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("test certificate private key has type %T, want *rsa.PrivateKey", certificate.PrivateKey)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadSplitTLSConfigUsesDedicatedCertificate(t *testing.T) {
	tmpDir := t.TempDir()
	mainCertFile := filepath.Join(tmpDir, "main.crt")
	mainKeyFile := filepath.Join(tmpDir, "main.key")
	splitCertFile := filepath.Join(tmpDir, "split.crt")
	splitKeyFile := filepath.Join(tmpDir, "split.key")
	writeTestTLSCertificatePair(t, mainCertFile, mainKeyFile, generateTestTLSCertificate(t, pkix.Name{CommonName: "main.example.test"}, nil, nil, nil, nil))
	writeTestTLSCertificatePair(t, splitCertFile, splitKeyFile, generateTestTLSCertificate(t, pkix.Name{CommonName: "split.example.test"}, nil, nil, nil, nil))

	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))
	tlsConfig, err := loadSplitTLSConfig(&config.Config{
		TLSCertFile:      mainCertFile,
		TLSKeyFile:       mainKeyFile,
		SplitTLSCertFile: splitCertFile,
		SplitTLSKeyFile:  splitKeyFile,
	}, logger)
	if err != nil {
		t.Fatalf("loadSplitTLSConfig() error = %v", err)
	}
	leaf, err := x509.ParseCertificate(tlsConfig.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Subject.CommonName != "split.example.test" {
		t.Fatalf("split certificate CN = %q, want split.example.test", leaf.Subject.CommonName)
	}
	if !strings.Contains(output.String(), splitCertFile) || !strings.Contains(output.String(), "split.example.test") {
		t.Fatalf("dedicated split certificate was not logged: %s", output.String())
	}
}

func TestLoadSplitTLSConfigFallsBackToMainCertificate(t *testing.T) {
	tmpDir := t.TempDir()
	mainCertFile := filepath.Join(tmpDir, "main.crt")
	mainKeyFile := filepath.Join(tmpDir, "main.key")
	writeTestTLSCertificatePair(t, mainCertFile, mainKeyFile, generateTestTLSCertificate(t, pkix.Name{CommonName: "main.example.test"}, nil, nil, nil, nil))

	tlsConfig, err := loadSplitTLSConfig(&config.Config{TLSCertFile: mainCertFile, TLSKeyFile: mainKeyFile}, nil)
	if err != nil {
		t.Fatalf("loadSplitTLSConfig() error = %v", err)
	}
	leaf, err := x509.ParseCertificate(tlsConfig.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Subject.CommonName != "main.example.test" {
		t.Fatalf("fallback certificate CN = %q, want main.example.test", leaf.Subject.CommonName)
	}
}

func TestLoadSplitTLSConfigMissingCertificateReturnsError(t *testing.T) {
	_, err := loadSplitTLSConfig(&config.Config{
		TLSCertFile: "/missing/main.crt",
		TLSKeyFile:  "/missing/main.key",
	}, nil)
	if err == nil {
		t.Fatal("loadSplitTLSConfig() succeeded with missing certificate files")
	}
}

func TestLogTLSCertificate(t *testing.T) {
	subject := pkix.Name{
		CommonName:   "smtp.thepratts.info",
		Organization: []string{"The Pratts"},
		Country:      []string{"US"},
	}
	testURI, err := url.Parse("https://thepratts.info/services/mail")
	if err != nil {
		t.Fatal(err)
	}
	dnsNames := []string{"smtp.thepratts.info", "mail.thepratts.info", "thepratts.us"}
	ips := []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("2001:db8::1")}
	emails := []string{"admin@thepratts.info"}
	uris := []*url.URL{testURI}

	cert := generateTestTLSCertificate(t, subject, dnsNames, ips, emails, uris)

	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))

	subjectDN, sans, err := logTLSCertificate(logger, &cert, "/etc/mymail/tls.crt")
	if err != nil {
		t.Fatalf("logTLSCertificate error = %v", err)
	}
	if !strings.Contains(subjectDN, "CN=smtp.thepratts.info") {
		t.Fatalf("unexpected subjectDN = %q", subjectDN)
	}
	if cert.Leaf == nil {
		t.Fatal("logTLSCertificate did not populate cert.Leaf")
	}

	expectedSANs := []string{
		"smtp.thepratts.info",
		"mail.thepratts.info",
		"thepratts.us",
		"192.0.2.1",
		"2001:db8::1",
		"admin@thepratts.info",
		"https://thepratts.info/services/mail",
	}
	if !reflect.DeepEqual(sans, expectedSANs) {
		t.Fatalf("logTLSCertificate returned sans = %#v, want %#v", sans, expectedSANs)
	}

	var record map[string]any
	if err := json.Unmarshal(output.Bytes(), &record); err != nil {
		t.Fatalf("unmarshal log record: %v\noutput: %s", err, output.String())
	}
	if record["msg"] != "TLS certificate loaded" {
		t.Errorf("log msg = %v, want TLS certificate loaded", record["msg"])
	}
	if record["subject_dn"] != subjectDN {
		t.Errorf("log subject_dn = %v, want %s", record["subject_dn"], subjectDN)
	}
	if record["tls_cert_file"] != "/etc/mymail/tls.crt" {
		t.Errorf("log tls_cert_file = %v, want /etc/mymail/tls.crt", record["tls_cert_file"])
	}
	expectedNotAfter := cert.Leaf.NotAfter.UTC().Format(time.RFC3339)
	if record["not_after"] != expectedNotAfter {
		t.Errorf("log not_after = %v, want %s", record["not_after"], expectedNotAfter)
	}

	if _, ok := record["sans"]; ok {
		t.Errorf("log record should not contain deprecated sans attribute: %#v", record["sans"])
	}

	raw, ok := record["subject_alt_names"]
	if !ok {
		t.Fatal("log record missing key \"subject_alt_names\"")
	}
	rawSlice, ok := raw.([]any)
	if !ok {
		t.Fatalf("log record key \"subject_alt_names\" is not a slice: %#v", raw)
	}
	var strSlice []string
	for _, item := range rawSlice {
		if s, ok := item.(string); ok {
			strSlice = append(strSlice, s)
		}
	}
	if !reflect.DeepEqual(strSlice, expectedSANs) {
		t.Errorf("log record \"subject_alt_names\" = %#v, want %#v", strSlice, expectedSANs)
	}
}

func TestLogTLSCertificateWithoutSANs(t *testing.T) {
	subject := pkix.Name{
		CommonName: "plain.thepratts.info",
	}
	cert := generateTestTLSCertificate(t, subject, nil, nil, nil, nil)

	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))

	subjectDN, sans, err := logTLSCertificate(logger, &cert, "/etc/mymail/plain.crt")
	if err != nil {
		t.Fatalf("logTLSCertificate error = %v", err)
	}
	if !strings.Contains(subjectDN, "CN=plain.thepratts.info") {
		t.Fatalf("unexpected subjectDN = %q", subjectDN)
	}
	if len(sans) != 0 {
		t.Fatalf("expected empty sans, got %#v", sans)
	}

	var record map[string]any
	if err := json.Unmarshal(output.Bytes(), &record); err != nil {
		t.Fatalf("unmarshal log record: %v\noutput: %s", err, output.String())
	}
	if record["subject_dn"] != subjectDN {
		t.Errorf("log subject_dn = %v, want %s", record["subject_dn"], subjectDN)
	}
	expectedNotAfter := cert.Leaf.NotAfter.UTC().Format(time.RFC3339)
	if record["not_after"] != expectedNotAfter {
		t.Errorf("log not_after = %v, want %s", record["not_after"], expectedNotAfter)
	}

	if _, ok := record["sans"]; ok {
		t.Errorf("log record should not contain deprecated sans attribute: %#v", record["sans"])
	}

	raw, ok := record["subject_alt_names"]
	if !ok {
		t.Fatal("log record missing key \"subject_alt_names\"")
	}
	rawSlice, ok := raw.([]any)
	if !ok {
		t.Fatalf("log record key \"subject_alt_names\" is not a slice: %#v", raw)
	}
	if len(rawSlice) != 0 {
		t.Errorf("log record key \"subject_alt_names\" should be empty, got %#v", rawSlice)
	}
}

func TestCertificateSANsHelper(t *testing.T) {
	if sans := certificateSANs(nil); len(sans) != 0 {
		t.Fatalf("certificateSANs(nil) = %#v, want empty", sans)
	}

	uri, _ := url.Parse("spiffe://domain/service")
	cert := &x509.Certificate{
		DNSNames:       []string{"  ", "example.com", ""},
		IPAddresses:    []net.IP{net.ParseIP("10.0.0.1"), nil, []byte{}},
		EmailAddresses: []string{"user@example.com", "  "},
		URIs:           []*url.URL{uri, nil},
	}
	got := certificateSANs(cert)
	want := []string{"example.com", "10.0.0.1", "user@example.com", "spiffe://domain/service"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("certificateSANs = %#v, want %#v", got, want)
	}
}

func TestLogTLSCertificateErrors(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))

	if _, _, err := logTLSCertificate(logger, nil, "cert.crt"); err == nil {
		t.Fatal("logTLSCertificate(nil) should return error")
	}

	emptyCert := &tls.Certificate{}
	if _, _, err := logTLSCertificate(logger, emptyCert, "cert.crt"); err == nil {
		t.Fatal("logTLSCertificate(emptyCert) should return error")
	}

	invalidDERCert := &tls.Certificate{
		Certificate: [][]byte{[]byte("not-valid-der-asn1")},
	}
	if _, _, err := logTLSCertificate(logger, invalidDERCert, "cert.crt"); err == nil {
		t.Fatal("logTLSCertificate(invalidDERCert) should return error")
	}
}

func TestCheckTLSCertificateExpiration_ExpiringSoon(t *testing.T) {
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	subject := pkix.Name{CommonName: "expiring.thepratts.info"}
	notAfter := now.Add(15 * 24 * time.Hour)
	cert := generateTestTLSCertificateWithExpiry(t, subject, nil, nil, nil, nil, notAfter)

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))

	expiring, rem := checkTLSCertificateExpiration(logger, leaf, "/etc/mymail/tls.crt", now)
	if !expiring {
		t.Fatal("expected expiring to be true")
	}
	if rem != 15*24*time.Hour {
		t.Fatalf("unexpected remaining duration: %v", rem)
	}

	var record map[string]any
	if err := json.Unmarshal(output.Bytes(), &record); err != nil {
		t.Fatalf("unmarshal error: %v, output: %s", err, output.String())
	}
	if record["level"] != "WARN" {
		t.Errorf("level = %v, want WARN", record["level"])
	}
	if record["msg"] != "TLS certificate expires soon" {
		t.Errorf("msg = %v, want TLS certificate expires soon", record["msg"])
	}
	if record["tls_cert_file"] != "/etc/mymail/tls.crt" {
		t.Errorf("tls_cert_file = %v", record["tls_cert_file"])
	}
	if !strings.Contains(record["subject_dn"].(string), "CN=expiring.thepratts.info") {
		t.Errorf("subject_dn = %v", record["subject_dn"])
	}
	if record["days_remaining"].(float64) != 15 {
		t.Errorf("days_remaining = %v, want 15", record["days_remaining"])
	}
}

func TestCheckTLSCertificateExpiration_NotExpiring(t *testing.T) {
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	subject := pkix.Name{CommonName: "valid.thepratts.info"}
	notAfter := now.Add(60 * 24 * time.Hour)
	cert := generateTestTLSCertificateWithExpiry(t, subject, nil, nil, nil, nil, notAfter)

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))

	expiring, _ := checkTLSCertificateExpiration(logger, leaf, "/etc/mymail/tls.crt", now)
	if expiring {
		t.Fatal("expected expiring to be false for 60-day certificate")
	}
	if output.Len() != 0 {
		t.Fatalf("expected no log output, got: %s", output.String())
	}
}

func TestCheckTLSCertificateExpiration_Expired(t *testing.T) {
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	subject := pkix.Name{CommonName: "expired.thepratts.info"}
	notAfter := now.Add(-2 * 24 * time.Hour)
	cert := generateTestTLSCertificateWithExpiry(t, subject, nil, nil, nil, nil, notAfter)

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))

	expiring, rem := checkTLSCertificateExpiration(logger, leaf, "/etc/mymail/tls.crt", now)
	if !expiring {
		t.Fatal("expected expiring to be true for expired cert")
	}
	if rem >= 0 {
		t.Fatalf("expected negative duration for expired cert, got: %v", rem)
	}
	if !strings.Contains(output.String(), `"level":"WARN"`) {
		t.Fatalf("expected WARN log for expired cert, got: %s", output.String())
	}
}

func TestCheckTLSCertificateExpiration_Nil(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))
	expiring, rem := checkTLSCertificateExpiration(logger, nil, "file.crt", time.Now())
	if expiring || rem != 0 {
		t.Fatalf("expected false, 0 for nil cert, got %v, %v", expiring, rem)
	}
	if output.Len() != 0 {
		t.Fatalf("expected no output for nil cert, got: %s", output.String())
	}
}

func TestLogTLSCertificate_ExpiringWarning(t *testing.T) {
	subject := pkix.Name{CommonName: "expiring-soon.thepratts.info"}
	cert := generateTestTLSCertificateWithExpiry(t, subject, nil, nil, nil, nil, time.Now().Add(10*24*time.Hour))

	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))

	subjectDN, sans, err := logTLSCertificate(logger, &cert, "/etc/mymail/expiring.crt")
	if err != nil {
		t.Fatalf("logTLSCertificate failed: %v", err)
	}
	if !strings.Contains(subjectDN, "CN=expiring-soon.thepratts.info") {
		t.Errorf("subjectDN = %q", subjectDN)
	}
	if len(sans) != 0 {
		t.Errorf("sans = %#v", sans)
	}

	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 log lines (INFO + WARN), got %d: %s", len(lines), output.String())
	}

	var infoRecord, warnRecord map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &infoRecord); err != nil {
		t.Fatalf("decode info log: %v", err)
	}
	if infoRecord["level"] != "INFO" || infoRecord["msg"] != "TLS certificate loaded" {
		t.Errorf("unexpected info record: %#v", infoRecord)
	}

	if err := json.Unmarshal([]byte(lines[1]), &warnRecord); err != nil {
		t.Fatalf("decode warn log: %v", err)
	}
	if warnRecord["level"] != "WARN" || warnRecord["msg"] != "TLS certificate expires soon" {
		t.Errorf("unexpected warn record: %#v", warnRecord)
	}
	if warnRecord["tls_cert_file"] != "/etc/mymail/expiring.crt" {
		t.Errorf("warn tls_cert_file = %v", warnRecord["tls_cert_file"])
	}
	if warnRecord["days_remaining"].(float64) < 9 || warnRecord["days_remaining"].(float64) > 10 {
		t.Errorf("unexpected days_remaining: %v", warnRecord["days_remaining"])
	}
}
