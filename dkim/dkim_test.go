package dkim

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func generateTestRSAKey(t *testing.T) (*rsa.PrivateKey, string, string) {
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

	return privKey, string(privPEM), string(pubPEM)
}

func TestCanonicalizeBodyRelaxed(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "empty body",
			input:    "",
			expected: "",
		},
		{
			name:     "only whitespace and newlines",
			input:    "   \r\n  \t  \r\n\r\n",
			expected: "",
		},
		{
			name:     "simple text",
			input:    "Hello World\r\n",
			expected: "Hello World\r\n",
		},
		{
			name:     "extra whitespace and trailing empty lines",
			input:    "Hello   World  \r\n\r\nLine 2 \t \r\n\r\n\r\n",
			expected: "Hello World\r\n\r\nLine 2\r\n",
		},
		{
			name:     "unix newlines",
			input:    "Line 1 \nLine 2  \n\n",
			expected: "Line 1\r\nLine 2\r\n",
		},
		{
			name:     "no trailing newline",
			input:    "No trailing newline",
			expected: "No trailing newline\r\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := string(CanonicalizeBodyRelaxed([]byte(tt.input)))
			if got != tt.expected {
				t.Errorf("CanonicalizeBodyRelaxed(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestCanonicalizeHeaderRelaxed(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		value    string
		expected string
	}{
		{
			name:     "simple header",
			key:      "From",
			value:    "alice@example.com",
			expected: "from:alice@example.com\r\n",
		},
		{
			name:     "casing and extra spaces",
			key:      "SubJect",
			value:    "  Hello   World  ",
			expected: "subject:Hello World\r\n",
		},
		{
			name:     "folded continuation line",
			key:      "To",
			value:    "bob@example.com,\r\n  charlie@example.com",
			expected: "to:bob@example.com, charlie@example.com\r\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CanonicalizeHeaderRelaxed(tt.key, tt.value)
			if got != tt.expected {
				t.Errorf("CanonicalizeHeaderRelaxed(%q, %q) = %q, want %q", tt.key, tt.value, got, tt.expected)
			}
		})
	}
}

func TestSignAndVerify(t *testing.T) {
	_, privPEM, pubPEM := generateTestRSAKey(t)

	signer, err := NewSigner("example.com", "default", privPEM, pubPEM)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	signer.now = func() time.Time {
		return time.Unix(1700000000, 0)
	}

	message := []byte("From: alice@example.com\r\n" +
		"To: bob@example.com\r\n" +
		"Subject: Test Message\r\n" +
		"Date: Fri, 17 Nov 2023 00:00:00 +0000\r\n" +
		"Message-ID: <12345@example.com>\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"\r\n" +
		"This is a test message body.\r\n")

	signed, err := signer.Sign(message)
	if err != nil {
		t.Fatalf("signer.Sign: %v", err)
	}

	if !strings.HasPrefix(string(signed), "DKIM-Signature:") {
		t.Fatalf("signed message missing DKIM-Signature header: %s", string(signed))
	}

	// Verify the signature.
	if err := Verify(signed, signer.PublicKey()); err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
}

func TestSignAndVerifyWithFileKeys(t *testing.T) {
	_, privPEM, pubPEM := generateTestRSAKey(t)

	tmpDir := t.TempDir()
	privFile := filepath.Join(tmpDir, "dkim.key")
	pubFile := filepath.Join(tmpDir, "dkim.pub")

	if err := os.WriteFile(privFile, []byte(privPEM), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pubFile, []byte(pubPEM), 0644); err != nil {
		t.Fatal(err)
	}

	signer, err := NewSigner("thepratts.info", "mail2026", privFile, pubFile)
	if err != nil {
		t.Fatalf("NewSigner with files: %v", err)
	}

	if signer.Domain() != "thepratts.info" {
		t.Errorf("domain = %q, want thepratts.info", signer.Domain())
	}
	if signer.Selector() != "mail2026" {
		t.Errorf("selector = %q, want mail2026", signer.Selector())
	}

	msg := []byte("From: ken@thepratts.info\r\nTo: user@remote.test\r\nSubject: Hi\r\n\r\nHello from Linode!")
	signed, err := signer.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if err := Verify(signed, signer.PublicKey()); err != nil {
		t.Fatalf("Verify with file public key failed: %v", err)
	}
}

func TestDNSTXTRecordPublicKeyParsing(t *testing.T) {
	_, privPEM, pubPEM := generateTestRSAKey(t)

	// Extract base64 part of public key.
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		t.Fatal("decode public key pem failed")
	}
	pubB64 := strings.ReplaceAll(string(pubPEM), "-----BEGIN PUBLIC KEY-----", "")
	pubB64 = strings.ReplaceAll(pubB64, "-----END PUBLIC KEY-----", "")
	pubB64 = strings.TrimSpace(pubB64)

	dnsRecord := "v=DKIM1; k=rsa; p=" + pubB64

	signer, err := NewSigner("example.com", "default", privPEM, dnsRecord)
	if err != nil {
		t.Fatalf("NewSigner with DNS TXT record format: %v", err)
	}

	msg := []byte("From: alice@example.com\r\nTo: bob@example.com\r\nSubject: DNS Record Test\r\n\r\nBody text")
	signed, err := signer.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if err := Verify(signed, signer.PublicKey()); err != nil {
		t.Fatalf("Verify with DNS TXT parsed public key failed: %v", err)
	}
}

func TestVerificationFailsOnTamperedBody(t *testing.T) {
	_, privPEM, pubPEM := generateTestRSAKey(t)

	signer, err := NewSigner("example.com", "default", privPEM, pubPEM)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	msg := []byte("From: alice@example.com\r\nTo: bob@example.com\r\nSubject: Original\r\n\r\nOriginal Body")
	signed, err := signer.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Tamper with body.
	tampered := append(signed, []byte(" EXTRA CONTENT")...)
	if err := Verify(tampered, signer.PublicKey()); err == nil {
		t.Fatal("expected verification error on tampered body, got nil")
	}
}

func TestVerificationFailsOnTamperedHeader(t *testing.T) {
	_, privPEM, pubPEM := generateTestRSAKey(t)

	signer, err := NewSigner("example.com", "default", privPEM, pubPEM)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	msg := []byte("From: alice@example.com\r\nTo: bob@example.com\r\nSubject: Original Subject\r\n\r\nBody")
	signed, err := signer.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Tamper with subject header in signed message.
	tampered := []byte(strings.Replace(string(signed), "Subject: Original Subject", "Subject: Tampered Subject", 1))
	if err := Verify(tampered, signer.PublicKey()); err == nil {
		t.Fatal("expected verification error on tampered header, got nil")
	}
}

func TestSignMissingFromHeaderFails(t *testing.T) {
	_, privPEM, pubPEM := generateTestRSAKey(t)

	signer, err := NewSigner("example.com", "default", privPEM, pubPEM)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	msg := []byte("To: bob@example.com\r\nSubject: No From\r\n\r\nBody")
	if _, err := signer.Sign(msg); err == nil {
		t.Fatal("expected error when signing message without From header, got nil")
	}
}

func TestValidateKeyPair(t *testing.T) {
	key1, _, _ := generateTestRSAKey(t)
	key2, _, _ := generateTestRSAKey(t)

	if err := ValidateKeyPair(key1, &key1.PublicKey); err != nil {
		t.Errorf("ValidateKeyPair on matched pair returned error: %v", err)
	}
	if !MatchKeys(key1, &key1.PublicKey) {
		t.Errorf("MatchKeys on matched pair returned false")
	}

	if err := ValidateKeyPair(key1, &key2.PublicKey); err == nil {
		t.Errorf("ValidateKeyPair on mismatched pair expected error, got nil")
	}
	if MatchKeys(key1, &key2.PublicKey) {
		t.Errorf("MatchKeys on mismatched pair returned true")
	}

	if err := ValidateKeyPair(nil, &key1.PublicKey); err == nil {
		t.Errorf("ValidateKeyPair with nil private key expected error, got nil")
	}
	if err := ValidateKeyPair(key1, nil); err == nil {
		t.Errorf("ValidateKeyPair with nil public key expected error, got nil")
	}
}

func TestNewSignerMismatchedKeysFails(t *testing.T) {
	_, privPEM1, _ := generateTestRSAKey(t)
	_, _, pubPEM2 := generateTestRSAKey(t)

	_, err := NewSigner("example.com", "default", privPEM1, pubPEM2)
	if err == nil {
		t.Fatal("expected NewSigner with mismatched keys to fail, got nil")
	}
	if !strings.Contains(err.Error(), "key") {
		t.Errorf("expected error message to mention key mismatch, got: %v", err)
	}
}

func TestSignerLogging(t *testing.T) {
	_, privPEM, pubPEM := generateTestRSAKey(t)
	signer, err := NewSigner("example.com", "default", privPEM, pubPEM)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	signer.SetLogger(logger)

	msg := []byte("From: alice@example.com\r\nTo: bob@example.com\r\nSubject: Test\r\n\r\nHello")
	signed, err := signer.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(signed) == 0 {
		t.Fatal("expected signed message")
	}

	logOutput := buf.String()
	if !strings.Contains(logOutput, "DKIM signature created") {
		t.Errorf("expected log to contain 'DKIM signature created', got: %s", logOutput)
	}

	buf.Reset()
	badMsg := []byte("To: bob@example.com\r\nSubject: No From\r\n\r\nHello")
	_, err = signer.Sign(badMsg)
	if err == nil {
		t.Fatal("expected sign error for missing from header")
	}
	logOutput = buf.String()
	if !strings.Contains(logOutput, "DKIM signing failed") {
		t.Errorf("expected log to contain 'DKIM signing failed', got: %s", logOutput)
	}
}

func TestPEMEncodedKeyFormats(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}

	// 1. PKCS#1 PEM Private Key
	pkcs1PrivDER := x509.MarshalPKCS1PrivateKey(privKey)
	pkcs1PrivPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: pkcs1PrivDER,
	}))

	// 2. PKCS#8 PEM Private Key
	pkcs8PrivDER, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	pkcs8PrivPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8PrivDER,
	}))

	// 3. PKIX PEM Public Key
	pkixPubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal pkix: %v", err)
	}
	pkixPubPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pkixPubDER,
	}))

	// 4. PKCS#1 PEM Public Key
	pkcs1PubDER := x509.MarshalPKCS1PublicKey(&privKey.PublicKey)
	pkcs1PubPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pkcs1PubDER,
	}))

	// 5. X.509 Certificate PEM
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "mail.example.com",
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}))

	// 6. Multi-block PEM
	multiBlockPEM := "# Comment before block\n" + certPEM + "\n# Interstitial comment\n" + pkcs8PrivPEM

	// 7. PEM with literal escaped newlines
	escapedPrivPEM := strings.ReplaceAll(pkcs1PrivPEM, "\n", `\n`)
	escapedPubPEM := strings.ReplaceAll(pkixPubPEM, "\n", `\n`)

	// 8. PEM with Windows CRLF newlines
	crlfPrivPEM := strings.ReplaceAll(pkcs8PrivPEM, "\n", "\r\n")
	crlfPubPEM := strings.ReplaceAll(pkcs1PubPEM, "\n", "\r\n")

	// 9. OpenDKIM / BIND zone file multiline quoted DNS TXT record
	pubB64 := strings.ReplaceAll(pkixPubPEM, "-----BEGIN PUBLIC KEY-----", "")
	pubB64 = strings.ReplaceAll(pubB64, "-----END PUBLIC KEY-----", "")
	pubB64 = strings.TrimSpace(pubB64)
	splitIndex := len(pubB64) / 2
	bindDNS := `( "v=DKIM1; k=rsa; " ` + "\n" + `  "p=` + pubB64[:splitIndex] + `" ` + "\n" + `  "` + pubB64[splitIndex:] + `" ) ; comment`

	privateKeyVariants := []struct {
		name string
		data string
	}{
		{"PKCS1_PEM", pkcs1PrivPEM},
		{"PKCS8_PEM", pkcs8PrivPEM},
		{"MultiBlock_PEM", multiBlockPEM},
		{"EscapedNewlines_PEM", escapedPrivPEM},
		{"CRLF_PEM", crlfPrivPEM},
		{"SingleLine_PKCS1", strings.Join(strings.Fields(pkcs1PrivPEM), " ")},
		{"SingleLine_PKCS8", strings.Join(strings.Fields(pkcs8PrivPEM), " ")},
	}

	publicKeyVariants := []struct {
		name string
		data string
	}{
		{"PKIX_PEM", pkixPubPEM},
		{"PKCS1_PEM", pkcs1PubPEM},
		{"Certificate_PEM", certPEM},
		{"EscapedNewlines_PEM", escapedPubPEM},
		{"CRLF_PEM", crlfPubPEM},
		{"BindQuoted_DNS", bindDNS},
		{"SingleLine_PKIX", strings.Join(strings.Fields(pkixPubPEM), " ")},
		{"SingleLine_PKCS1", strings.Join(strings.Fields(pkcs1PubPEM), " ")},
	}

	msg := []byte("From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test PEM\r\n\r\nBody text\r\n")

	for _, priv := range privateKeyVariants {
		for _, pub := range publicKeyVariants {
			testName := priv.name + "_with_" + pub.name
			t.Run(testName, func(t *testing.T) {
				signer, err := NewSigner("example.com", "default", priv.data, pub.data)
				if err != nil {
					t.Fatalf("NewSigner failed: %v", err)
				}

				signed, err := signer.Sign(msg)
				if err != nil {
					t.Fatalf("Sign failed: %v", err)
				}

				if err := Verify(signed, signer.PublicKey()); err != nil {
					t.Fatalf("Verify failed: %v", err)
				}
			})
		}
	}
}

func TestLoadPEMKeysFromFiles(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}

	pkcs8PrivDER, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	pkcs8PrivPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8PrivDER,
	})

	pkcs1PubDER := x509.MarshalPKCS1PublicKey(&privKey.PublicKey)
	pkcs1PubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pkcs1PubDER,
	})

	tmpDir := t.TempDir()
	privFile := filepath.Join(tmpDir, "dkim.pkcs8.key")
	pubFile := filepath.Join(tmpDir, "dkim.pkcs1.pub")

	if err := os.WriteFile(privFile, pkcs8PrivPEM, 0o600); err != nil {
		t.Fatalf("write private key file: %v", err)
	}
	if err := os.WriteFile(pubFile, pkcs1PubPEM, 0o644); err != nil {
		t.Fatalf("write public key file: %v", err)
	}

	signer, err := NewSigner("example.com", "default", privFile, pubFile)
	if err != nil {
		t.Fatalf("NewSigner from files failed: %v", err)
	}

	msg := []byte("From: alice@example.com\r\nTo: bob@example.com\r\nSubject: File PEM Test\r\n\r\nBody")
	signed, err := signer.Sign(msg)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if err := Verify(signed, signer.PublicKey()); err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
}

func TestLoadKeysFromMissingFileReportsClearError(t *testing.T) {
	missingPath := filepath.Join(t.TempDir(), "nonexistent", "dkim.key")
	_, err := LoadPrivateKey(missingPath)
	if err == nil {
		t.Fatal("expected error loading missing private key file, got nil")
	}
	if !strings.Contains(err.Error(), "read private key file") {
		t.Errorf("error = %q, expected to contain 'read private key file'", err.Error())
	}

	_, err = LoadPublicKey(missingPath)
	if err == nil {
		t.Fatal("expected error loading missing public key file, got nil")
	}
	if !strings.Contains(err.Error(), "read public key file") {
		t.Errorf("error = %q, expected to contain 'read public key file'", err.Error())
	}
}

func TestLoadKeysWithQuotedPaths(t *testing.T) {
	_, privPEM, pubPEM := generateTestRSAKey(t)
	tmpDir := t.TempDir()
	privFile := filepath.Join(tmpDir, "dkim.key")
	pubFile := filepath.Join(tmpDir, "dkim.pub")

	if err := os.WriteFile(privFile, []byte(privPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pubFile, []byte(pubPEM), 0o644); err != nil {
		t.Fatal(err)
	}

	// Quoted paths
	priv, err := LoadPrivateKey(`"` + privFile + `"`)
	if err != nil {
		t.Fatalf("LoadPrivateKey with quoted path failed: %v", err)
	}
	pub, err := LoadPublicKey(`'` + pubFile + `'`)
	if err != nil {
		t.Fatalf("LoadPublicKey with quoted path failed: %v", err)
	}

	if err := ValidateKeyPair(priv, pub); err != nil {
		t.Fatalf("ValidateKeyPair failed: %v", err)
	}
}

func TestEncryptedPrivateKeyReportsClearError(t *testing.T) {
	encryptedPEM := `-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,F1E2D3C4B5A697887766554433221100

dGVzdGV4YW1wbGVlbmNyeXB0ZWRkYXRhMTIzNDU2Nzg5MDEyMzQ1Njc4OTA=
-----END RSA PRIVATE KEY-----`

	_, err := LoadPrivateKey(encryptedPEM)
	if err == nil {
		t.Fatal("expected error for encrypted private key, got nil")
	}
	if !strings.Contains(err.Error(), "encrypted") {
		t.Errorf("error = %q, expected to mention 'encrypted'", err.Error())
	}
}

func TestECDSAPrivateKeyReportsClearError(t *testing.T) {
	ecKeyPEM := `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIP+sQcE9n+Y2P2c3...
-----END EC PRIVATE KEY-----`

	_, err := LoadPrivateKey(ecKeyPEM)
	if err == nil {
		t.Fatal("expected error for ECDSA private key, got nil")
	}
	if !strings.Contains(err.Error(), "ECDSA") {
		t.Errorf("error = %q, expected to mention 'ECDSA'", err.Error())
	}
}

func TestOpenSSHKeysParsing(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}

	// Build unencrypted OpenSSH format key container
	var pubKeyBuf bytes.Buffer
	// string "ssh-rsa"
	_ = binary.Write(&pubKeyBuf, binary.BigEndian, uint32(7))
	pubKeyBuf.WriteString("ssh-rsa")
	// e
	eBytes := big.NewInt(int64(privKey.PublicKey.E)).Bytes()
	_ = binary.Write(&pubKeyBuf, binary.BigEndian, uint32(len(eBytes)))
	pubKeyBuf.Write(eBytes)
	// n
	nBytes := privKey.PublicKey.N.Bytes()
	_ = binary.Write(&pubKeyBuf, binary.BigEndian, uint32(len(nBytes)))
	pubKeyBuf.Write(nBytes)

	pubKeyBytes := pubKeyBuf.Bytes()

	// Build private key section
	var privSection bytes.Buffer
	_ = binary.Write(&privSection, binary.BigEndian, uint32(0x12345678))
	_ = binary.Write(&privSection, binary.BigEndian, uint32(0x12345678))
	_ = binary.Write(&privSection, binary.BigEndian, uint32(7))
	privSection.WriteString("ssh-rsa")
	_ = binary.Write(&privSection, binary.BigEndian, uint32(len(nBytes)))
	privSection.Write(nBytes)
	_ = binary.Write(&privSection, binary.BigEndian, uint32(len(eBytes)))
	privSection.Write(eBytes)
	dBytes := privKey.D.Bytes()
	_ = binary.Write(&privSection, binary.BigEndian, uint32(len(dBytes)))
	privSection.Write(dBytes)
	iqmpBytes := privKey.Precomputed.Qinv.Bytes()
	_ = binary.Write(&privSection, binary.BigEndian, uint32(len(iqmpBytes)))
	privSection.Write(iqmpBytes)
	pBytes := privKey.Primes[0].Bytes()
	_ = binary.Write(&privSection, binary.BigEndian, uint32(len(pBytes)))
	privSection.Write(pBytes)
	qBytes := privKey.Primes[1].Bytes()
	_ = binary.Write(&privSection, binary.BigEndian, uint32(len(qBytes)))
	privSection.Write(qBytes)
	// comment
	_ = binary.Write(&privSection, binary.BigEndian, uint32(0))
	// padding to block size 8
	padLen := 8 - (privSection.Len() % 8)
	if padLen < 8 {
		for i := 1; i <= padLen; i++ {
			privSection.WriteByte(byte(i))
		}
	}

	var openSSHBuf bytes.Buffer
	openSSHBuf.WriteString("openssh-key-v1\x00")
	// cipher "none"
	_ = binary.Write(&openSSHBuf, binary.BigEndian, uint32(4))
	openSSHBuf.WriteString("none")
	// kdf "none"
	_ = binary.Write(&openSSHBuf, binary.BigEndian, uint32(4))
	openSSHBuf.WriteString("none")
	// kdfOptions ""
	_ = binary.Write(&openSSHBuf, binary.BigEndian, uint32(0))
	// num_keys 1
	_ = binary.Write(&openSSHBuf, binary.BigEndian, uint32(1))
	// pubkey
	_ = binary.Write(&openSSHBuf, binary.BigEndian, uint32(len(pubKeyBytes)))
	openSSHBuf.Write(pubKeyBytes)
	// privkey
	privSecBytes := privSection.Bytes()
	_ = binary.Write(&openSSHBuf, binary.BigEndian, uint32(len(privSecBytes)))
	openSSHBuf.Write(privSecBytes)

	openSSHPrivatePEM := pem.EncodeToMemory(&pem.Block{
		Type:  "OPENSSH PRIVATE KEY",
		Bytes: openSSHBuf.Bytes(),
	})

	openSSHPublicString := "ssh-rsa " + base64.StdEncoding.EncodeToString(pubKeyBytes) + " user@host"

	signer, err := NewSigner("example.com", "default", string(openSSHPrivatePEM), openSSHPublicString)
	if err != nil {
		t.Fatalf("NewSigner with OpenSSH keys failed: %v", err)
	}

	msg := []byte("From: alice@example.com\r\nTo: bob@example.com\r\nSubject: OpenSSH Test\r\n\r\nBody")
	signed, err := signer.Sign(msg)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if err := Verify(signed, signer.PublicKey()); err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
}

func TestGenerateKeyPairAndDNSFormatting(t *testing.T) {
	privKey, err := GenerateKeyPair(1024)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	if privKey == nil {
		t.Fatal("expected non-nil private key")
	}

	// Test invalid bit sizes.
	if _, err := GenerateKeyPair(512); err == nil {
		t.Fatal("expected error for 512 bits, got nil")
	}

	// Test PEM encoding.
	privPEM := PEMEncodePrivateKey(privKey)
	if !strings.HasPrefix(privPEM, "-----BEGIN RSA PRIVATE KEY-----") {
		t.Fatalf("unexpected private PEM header: %s", privPEM)
	}

	pubPEM, err := PEMEncodePublicKey(&privKey.PublicKey)
	if err != nil {
		t.Fatalf("PEMEncodePublicKey failed: %v", err)
	}
	if !strings.HasPrefix(pubPEM, "-----BEGIN PUBLIC KEY-----") {
		t.Fatalf("unexpected public PEM header: %s", pubPEM)
	}

	// Test round-trip parsing of encoded PEMs.
	parsedPriv, err := ParsePrivateKey([]byte(privPEM))
	if err != nil {
		t.Fatalf("ParsePrivateKey failed: %v", err)
	}
	parsedPub, err := ParsePublicKey([]byte(pubPEM))
	if err != nil {
		t.Fatalf("ParsePublicKey failed: %v", err)
	}
	if err := ValidateKeyPair(parsedPriv, parsedPub); err != nil {
		t.Fatalf("ValidateKeyPair failed: %v", err)
	}

	// Test DNS TXT record formatting.
	recName, recVal, err := FormatDNSTXTRecord("mail", "thepratts.info", &privKey.PublicKey)
	if err != nil {
		t.Fatalf("FormatDNSTXTRecord failed: %v", err)
	}
	if recName != "mail._domainkey.thepratts.info." {
		t.Errorf("recName = %q, want 'mail._domainkey.thepratts.info.'", recName)
	}
	if !strings.HasPrefix(recVal, "v=DKIM1; k=rsa; p=") {
		t.Errorf("recVal = %q, expected prefix 'v=DKIM1; k=rsa; p='", recVal)
	}

	// Parse DNS TXT record value with ParsePublicKey.
	dnsPub, err := ParsePublicKey([]byte(recVal))
	if err != nil {
		t.Fatalf("ParsePublicKey on DNS record failed: %v", err)
	}
	if err := ValidateKeyPair(privKey, dnsPub); err != nil {
		t.Fatalf("ValidateKeyPair on DNS public key failed: %v", err)
	}

	// Test Zone Entry formatting.
	zoneEntry, err := FormatDNSZoneEntry("mail", "thepratts.info", &privKey.PublicKey)
	if err != nil {
		t.Fatalf("FormatDNSZoneEntry failed: %v", err)
	}
	if !strings.HasPrefix(zoneEntry, "mail._domainkey.thepratts.info. IN TXT \"v=DKIM1; k=rsa; p=") {
		t.Errorf("unexpected zoneEntry format: %s", zoneEntry)
	}
}
