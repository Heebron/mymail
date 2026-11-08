// Package dkim implements DomainKeys Identified Mail (DKIM) signing and
// verification according to RFC 6376.
package dkim

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// DefaultSelector is the fallback selector name when none is configured.
const DefaultSelector = "default"

// DefaultSignedHeaders lists the message header names that will be signed if present.
var DefaultSignedHeaders = []string{
	"from",
	"to",
	"cc",
	"subject",
	"date",
	"message-id",
	"mime-version",
	"content-type",
	"reply-to",
}

// HeaderField represents a parsed message header line.
type HeaderField struct {
	RawKey string
	Key    string // Lowercase
	Value  string // Unfolded value
}

// Signer signs outgoing emails with a DKIM-Signature header.
type Signer struct {
	domain     string
	selector   string
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	headers    []string
	now        func() time.Time
	logger     *slog.Logger
}

// SetLogger configures an optional structured logger for recording DKIM signing activity.
func (s *Signer) SetLogger(logger *slog.Logger) {
	s.logger = logger
}

// NewSigner creates a new DKIM Signer with the given domain, selector, private key,
// and public key. Private and public keys can be file paths or raw PEM/base64 data.
// If a public key is provided, NewSigner verifies that the private and public keys
// form a matched pair.
func NewSigner(domain, selector, privateKeyData, publicKeyData string) (*Signer, error) {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return nil, errors.New("dkim domain is required")
	}
	selector = strings.TrimSpace(selector)
	if selector == "" {
		selector = DefaultSelector
	}

	privKey, err := LoadPrivateKey(privateKeyData)
	if err != nil {
		return nil, fmt.Errorf("load dkim private key: %w", err)
	}

	var pubKey *rsa.PublicKey
	if strings.TrimSpace(publicKeyData) != "" {
		pubKey, err = LoadPublicKey(publicKeyData)
		if err != nil {
			return nil, fmt.Errorf("load dkim public key: %w", err)
		}
		if err := ValidateKeyPair(privKey, pubKey); err != nil {
			return nil, fmt.Errorf("validate dkim key pair: %w", err)
		}
	}

	return &Signer{
		domain:     domain,
		selector:   selector,
		privateKey: privKey,
		publicKey:  pubKey,
		headers:    DefaultSignedHeaders,
		now:        time.Now,
	}, nil
}

// Domain returns the signing domain.
func (s *Signer) Domain() string {
	return s.domain
}

// Selector returns the selector name.
func (s *Signer) Selector() string {
	return s.selector
}

// PublicKey returns the parsed RSA public key, if available.
func (s *Signer) PublicKey() *rsa.PublicKey {
	if s.publicKey != nil {
		return s.publicKey
	}
	if s.privateKey != nil {
		return &s.privateKey.PublicKey
	}
	return nil
}

// PrivateKey returns the parsed RSA private key.
func (s *Signer) PrivateKey() *rsa.PrivateKey {
	return s.privateKey
}

// Sign signs an RFC 5322 email message with a DKIM-Signature header.
func (s *Signer) Sign(msg []byte) ([]byte, error) {
	if s.privateKey == nil {
		if s.logger != nil {
			s.logger.Warn("DKIM signing failed: private key is not configured", "domain", s.domain, "selector", s.selector)
		}
		return nil, errors.New("signer private key is not configured")
	}

	headers, body := SplitMessage(msg)

	// Canonicalize body using relaxed canonicalization and compute SHA-256 hash.
	canonBody := CanonicalizeBodyRelaxed(body)
	bodyHash := sha256.Sum256(canonBody)
	bh := base64.StdEncoding.EncodeToString(bodyHash[:])

	// Filter headers to sign.
	headerFields := ParseHeaders(headers)
	var signedHeaders []HeaderField
	var signedHeaderNames []string

	signMap := make(map[string]bool, len(s.headers))
	for _, h := range s.headers {
		signMap[strings.ToLower(h)] = true
	}

	for _, hf := range headerFields {
		if signMap[hf.Key] {
			signedHeaders = append(signedHeaders, hf)
			signedHeaderNames = append(signedHeaderNames, hf.Key)
		}
	}

	// From header is mandatory per RFC 6376 Section 5.4.
	hasFrom := false
	for _, hf := range signedHeaders {
		if hf.Key == "from" {
			hasFrom = true
			break
		}
	}
	if !hasFrom {
		if s.logger != nil {
			s.logger.Warn("DKIM signing failed: message missing required From header", "domain", s.domain, "selector", s.selector)
		}
		return nil, errors.New("message missing required From header for DKIM signing")
	}

	hTag := strings.Join(signedHeaderNames, ":")
	tTag := s.now().UTC().Unix()

	// Build DKIM-Signature header without b= value for canonicalization.
	dkimHeaderParams := fmt.Sprintf("v=1; a=rsa-sha256; c=relaxed/relaxed; d=%s; s=%s; t=%d; bh=%s; h=%s; b=",
		s.domain, s.selector, tTag, bh, hTag)

	// Canonicalize signed headers.
	var canonHeaders bytes.Buffer
	for _, hf := range signedHeaders {
		canonHeaders.WriteString(CanonicalizeHeaderRelaxed(hf.RawKey, hf.Value))
	}

	// Canonicalize the DKIM-Signature header itself (without trailing CRLF).
	canonDKIMHeader := CanonicalizeHeaderRelaxed("DKIM-Signature", dkimHeaderParams)
	canonDKIMHeader = strings.TrimRight(canonDKIMHeader, "\r\n")
	canonHeaders.WriteString(canonDKIMHeader)

	// Hash canonicalized headers and sign with RSA-SHA256 (PKCS#1 v1.5).
	headerHash := sha256.Sum256(canonHeaders.Bytes())
	signature, err := rsa.SignPKCS1v15(rand.Reader, s.privateKey, crypto.SHA256, headerHash[:])
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("DKIM signature generation failed", "domain", s.domain, "selector", s.selector, "error", err)
		}
		return nil, fmt.Errorf("sign dkim hash: %w", err)
	}

	bTag := base64.StdEncoding.EncodeToString(signature)

	// Format final DKIM-Signature header with nice line wrapping.
	finalDKIMHeader := fmt.Sprintf("DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=%s; s=%s;\r\n\tt=%d; bh=%s;\r\n\th=%s;\r\n\tb=%s\r\n",
		s.domain, s.selector, tTag, bh, hTag, bTag)

	if s.logger != nil {
		s.logger.Info("DKIM signature created", "domain", s.domain, "selector", s.selector, "headers", hTag, "body_hash", bh)
	}

	// Prepend DKIM-Signature header to the original message.
	var result bytes.Buffer
	result.WriteString(finalDKIMHeader)
	result.Write(msg)
	return result.Bytes(), nil
}

// resolveFilePath checks whether path starts with ~ or quotes and expands it.
func resolveFilePath(path string) string {
	path = strings.TrimSpace(path)
	path = strings.Trim(path, `"'`+"`")
	if strings.HasPrefix(path, "~/") || path == "~" {
		if home, err := os.UserHomeDir(); err == nil {
			path = filepath.Join(home, strings.TrimPrefix(path, "~/"))
		}
	}
	return path
}

// isLikelyFilePath returns true if the input looks like a filesystem path rather than inline key data.
func isLikelyFilePath(data string) bool {
	data = strings.TrimSpace(data)
	if strings.Contains(data, "-----BEGIN") || strings.Contains(data, "-----END") {
		return false
	}
	if strings.Contains(data, "\n") || strings.Contains(data, "\r") {
		return false
	}
	if strings.Contains(data, "p=") || strings.Contains(data, "v=DKIM1") {
		return false
	}
	if strings.HasPrefix(data, "/") || strings.HasPrefix(data, "./") || strings.HasPrefix(data, "../") || strings.HasPrefix(data, "~") {
		return true
	}
	if strings.Contains(data, string(filepath.Separator)) {
		return true
	}
	ext := strings.ToLower(filepath.Ext(data))
	if ext == ".key" || ext == ".pem" || ext == ".priv" || ext == ".pub" || ext == ".rsa" || ext == ".txt" || ext == ".der" || ext == ".crt" || ext == ".cer" {
		return true
	}
	return false
}

func decodeBase64Flexible(s string) ([]byte, error) {
	clean := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\r' || r == '\n' || r == '"' || r == '\'' || r == '`' {
			return -1
		}
		return r
	}, s)
	if clean == "" {
		return nil, errors.New("empty base64 payload")
	}
	if b, err := base64.StdEncoding.DecodeString(clean); err == nil {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(clean); err == nil {
		return b, nil
	}
	if b, err := base64.URLEncoding.DecodeString(clean); err == nil {
		return b, nil
	}
	if b, err := base64.RawURLEncoding.DecodeString(clean); err == nil {
		return b, nil
	}
	return nil, errors.New("invalid base64 encoding")
}

func parseOpenSSHPrivateKey(raw []byte) (*rsa.PrivateKey, error) {
	magic := []byte("openssh-key-v1\x00")
	if len(raw) < len(magic) || !bytes.Equal(raw[:len(magic)], magic) {
		return nil, errors.New("invalid OpenSSH private key header")
	}
	r := bytes.NewReader(raw[len(magic):])

	readString := func() (string, error) {
		var l uint32
		if err := binary.Read(r, binary.BigEndian, &l); err != nil {
			return "", err
		}
		buf := make([]byte, l)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		return string(buf), nil
	}

	readBytes := func() ([]byte, error) {
		var l uint32
		if err := binary.Read(r, binary.BigEndian, &l); err != nil {
			return nil, err
		}
		buf := make([]byte, l)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		return buf, nil
	}

	cipherName, err := readString()
	if err != nil {
		return nil, err
	}
	if cipherName != "none" {
		return nil, fmt.Errorf("OpenSSH private key is encrypted with %s (passphrase-protected keys are not supported)", cipherName)
	}
	kdfName, err := readString()
	if err != nil {
		return nil, err
	}
	if kdfName != "none" {
		return nil, fmt.Errorf("OpenSSH private key uses KDF %s", kdfName)
	}
	if _, err := readBytes(); err != nil {
		return nil, err
	}
	var numKeys uint32
	if err := binary.Read(r, binary.BigEndian, &numKeys); err != nil {
		return nil, err
	}
	if numKeys < 1 {
		return nil, errors.New("no keys in OpenSSH key container")
	}
	if _, err := readBytes(); err != nil {
		return nil, err
	}
	privBytes, err := readBytes()
	if err != nil {
		return nil, err
	}

	pr := bytes.NewReader(privBytes)
	var checkint1, checkint2 uint32
	if err := binary.Read(pr, binary.BigEndian, &checkint1); err != nil {
		return nil, err
	}
	if err := binary.Read(pr, binary.BigEndian, &checkint2); err != nil {
		return nil, err
	}
	if checkint1 != checkint2 {
		return nil, errors.New("corrupted OpenSSH private key: checkint mismatch")
	}

	readPrivString := func() (string, error) {
		var l uint32
		if err := binary.Read(pr, binary.BigEndian, &l); err != nil {
			return "", err
		}
		buf := make([]byte, l)
		if _, err := io.ReadFull(pr, buf); err != nil {
			return "", err
		}
		return string(buf), nil
	}

	readPrivBigInt := func() (*big.Int, error) {
		var l uint32
		if err := binary.Read(pr, binary.BigEndian, &l); err != nil {
			return nil, err
		}
		buf := make([]byte, l)
		if _, err := io.ReadFull(pr, buf); err != nil {
			return nil, err
		}
		return new(big.Int).SetBytes(buf), nil
	}

	keyType, err := readPrivString()
	if err != nil {
		return nil, err
	}
	if keyType != "ssh-rsa" {
		return nil, fmt.Errorf("OpenSSH private key is %s (DKIM requires an RSA private key)", keyType)
	}

	n, err := readPrivBigInt()
	if err != nil {
		return nil, err
	}
	e, err := readPrivBigInt()
	if err != nil {
		return nil, err
	}
	d, err := readPrivBigInt()
	if err != nil {
		return nil, err
	}
	iqmp, err := readPrivBigInt()
	if err != nil {
		return nil, err
	}
	_ = iqmp
	p, err := readPrivBigInt()
	if err != nil {
		return nil, err
	}
	q, err := readPrivBigInt()
	if err != nil {
		return nil, err
	}

	privKey := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: n,
			E: int(e.Int64()),
		},
		D:      d,
		Primes: []*big.Int{p, q},
	}
	privKey.Precompute()
	if err := privKey.Validate(); err != nil {
		return nil, fmt.Errorf("invalid RSA private key in OpenSSH container: %w", err)
	}
	return privKey, nil
}

func parseOpenSSHPublicKey(raw []byte) (*rsa.PublicKey, error) {
	str := strings.TrimSpace(string(raw))
	parts := strings.Fields(str)
	var der []byte
	var err error
	if len(parts) >= 2 && parts[0] == "ssh-rsa" {
		der, err = base64.StdEncoding.DecodeString(parts[1])
		if err != nil {
			return nil, err
		}
	} else if len(parts) >= 1 && (parts[0] == "ecdsa-sha2-nistp256" || parts[0] == "ssh-ed25519") {
		return nil, fmt.Errorf("public key is %s (DKIM requires an RSA public key)", parts[0])
	} else {
		if decoded, err := decodeBase64Flexible(str); err == nil {
			der = decoded
		} else {
			der = raw
		}
	}

	r := bytes.NewReader(der)
	var keyTypeLen uint32
	if err := binary.Read(r, binary.BigEndian, &keyTypeLen); err != nil {
		return nil, err
	}
	if int(keyTypeLen) > r.Len() || keyTypeLen == 0 {
		return nil, errors.New("invalid OpenSSH public key")
	}
	keyTypeBuf := make([]byte, keyTypeLen)
	if _, err := io.ReadFull(r, keyTypeBuf); err != nil {
		return nil, err
	}
	keyType := string(keyTypeBuf)
	if keyType != "ssh-rsa" {
		return nil, fmt.Errorf("OpenSSH public key is %s (DKIM requires an RSA public key)", keyType)
	}

	readBigInt := func() (*big.Int, error) {
		var l uint32
		if err := binary.Read(r, binary.BigEndian, &l); err != nil {
			return nil, err
		}
		buf := make([]byte, l)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		return new(big.Int).SetBytes(buf), nil
	}

	e, err := readBigInt()
	if err != nil {
		return nil, err
	}
	n, err := readBigInt()
	if err != nil {
		return nil, err
	}
	return &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}, nil
}

// LoadPrivateKey loads an RSA private key from a file path or direct PEM/base64 string.
func LoadPrivateKey(data string) (*rsa.PrivateKey, error) {
	data = strings.TrimSpace(data)
	if data == "" {
		return nil, errors.New("private key data is empty")
	}

	resolvedPath := resolveFilePath(data)

	// Check if data is a path to an existing file or a likely file path.
	if !strings.Contains(data, "-----BEGIN") {
		if info, err := os.Stat(resolvedPath); err == nil && !info.IsDir() {
			fileBytes, err := os.ReadFile(resolvedPath)
			if err != nil {
				return nil, fmt.Errorf("read private key file %q: %w", resolvedPath, err)
			}
			key, err := ParsePrivateKey(fileBytes)
			if err != nil {
				return nil, fmt.Errorf("parse private key file %q: %w", resolvedPath, err)
			}
			return key, nil
		}

		if isLikelyFilePath(data) {
			fileBytes, err := os.ReadFile(resolvedPath)
			if err != nil {
				return nil, fmt.Errorf("read private key file %q: %w", resolvedPath, err)
			}
			key, err := ParsePrivateKey(fileBytes)
			if err != nil {
				return nil, fmt.Errorf("parse private key file %q: %w", resolvedPath, err)
			}
			return key, nil
		}
	}

	return ParsePrivateKey([]byte(data))
}

func parseRSAPrivateKeyDER(der []byte) (*rsa.PrivateKey, error) {
	// Try PKCS#1.
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}

	// Try PKCS#8.
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		if rsaKey, ok := key.(*rsa.PrivateKey); ok {
			return rsaKey, nil
		}
		if _, ok := key.(*ecdsa.PrivateKey); ok {
			return nil, errors.New("private key is ECDSA (DKIM requires an RSA private key)")
		}
		if _, ok := key.(ed25519.PrivateKey); ok {
			return nil, errors.New("private key is Ed25519 (DKIM requires an RSA private key)")
		}
		return nil, errors.New("private key is not RSA")
	}

	// Try EC private key SEC1.
	if _, err := x509.ParseECPrivateKey(der); err == nil {
		return nil, errors.New("private key is ECDSA (DKIM requires an RSA private key)")
	}

	// Try OpenSSH wire format if container.
	if key, err := parseOpenSSHPrivateKey(der); err == nil {
		return key, nil
	}

	return nil, errors.New("unable to parse RSA private key (expected PKCS#1 or PKCS#8)")
}

type rawPEMBlock struct {
	Type string
	Body string
}

var pemBlockRegex = regexp.MustCompile(`(?is)-----BEGIN\s+([A-Z0-9 _-]+?)\s*-----(.*?)-----END\s+([A-Z0-9 _-]+?)\s*-----`)

func extractPEMBlocksRegex(s string) []rawPEMBlock {
	matches := pemBlockRegex.FindAllStringSubmatch(s, -1)
	var blocks []rawPEMBlock
	for _, match := range matches {
		type1 := strings.ToUpper(strings.TrimSpace(match[1]))
		type2 := strings.ToUpper(strings.TrimSpace(match[3]))
		if type1 == type2 {
			blocks = append(blocks, rawPEMBlock{
				Type: type1,
				Body: match[2],
			})
		}
	}
	return blocks
}

// ParsePrivateKey parses an RSA private key from raw bytes (PEM PKCS#1, PKCS#8, OpenSSH, or base64 DER).
func ParsePrivateKey(raw []byte) (*rsa.PrivateKey, error) {
	if len(raw) == 0 {
		return nil, errors.New("private key data is empty")
	}

	// Strip UTF-8 BOM if present.
	raw = bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf"))

	// 1. Try decoding standard PEM blocks directly.
	rest := raw
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Headers["Proc-Type"] != "" || strings.Contains(block.Type, "ENCRYPTED") {
			return nil, errors.New("private key is encrypted (passphrase-protected keys are not supported; please provide an unencrypted RSA private key)")
		}
		if block.Type == "OPENSSH PRIVATE KEY" {
			if key, err := parseOpenSSHPrivateKey(block.Bytes); err == nil {
				return key, nil
			}
		}
		if block.Type == "EC PRIVATE KEY" {
			return nil, errors.New("private key is ECDSA (DKIM requires an RSA private key)")
		}
		if key, err := parseRSAPrivateKeyDER(block.Bytes); err == nil {
			return key, nil
		}
	}

	// 2. Unescape literal \n and \r sequences if present.
	rawStr := string(raw)
	if strings.Contains(rawStr, `\n`) || strings.Contains(rawStr, `\r`) {
		unescaped := strings.ReplaceAll(rawStr, `\r\n`, "\r\n")
		unescaped = strings.ReplaceAll(unescaped, `\n`, "\n")
		unescaped = strings.ReplaceAll(unescaped, `\r`, "\r")
		rest = []byte(unescaped)
		for len(rest) > 0 {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Headers["Proc-Type"] != "" || strings.Contains(block.Type, "ENCRYPTED") {
				return nil, errors.New("private key is encrypted (passphrase-protected keys are not supported; please provide an unencrypted RSA private key)")
			}
			if block.Type == "OPENSSH PRIVATE KEY" {
				if key, err := parseOpenSSHPrivateKey(block.Bytes); err == nil {
					return key, nil
				}
			}
			if block.Type == "EC PRIVATE KEY" {
				return nil, errors.New("private key is ECDSA (DKIM requires an RSA private key)")
			}
			if key, err := parseRSAPrivateKeyDER(block.Bytes); err == nil {
				return key, nil
			}
		}
		rawStr = unescaped
	}

	// 3. Regex fallback to extract PEM blocks (e.g. single-line PEM with spaces).
	blocks := extractPEMBlocksRegex(rawStr)
	for _, block := range blocks {
		if strings.Contains(block.Body, "Proc-Type:") && strings.Contains(block.Body, "ENCRYPTED") || strings.Contains(block.Type, "ENCRYPTED") {
			return nil, errors.New("private key is encrypted (passphrase-protected keys are not supported; please provide an unencrypted RSA private key)")
		}
		if block.Type == "EC PRIVATE KEY" {
			return nil, errors.New("private key is ECDSA (DKIM requires an RSA private key)")
		}
		if der, err := decodeBase64Flexible(block.Body); err == nil {
			if block.Type == "OPENSSH PRIVATE KEY" {
				if key, err := parseOpenSSHPrivateKey(der); err == nil {
					return key, nil
				}
			}
			if key, err := parseRSAPrivateKeyDER(der); err == nil {
				return key, nil
			}
		}
	}

	// 4. Try OpenSSH format directly on raw bytes.
	if key, err := parseOpenSSHPrivateKey(raw); err == nil {
		return key, nil
	}

	// 5. Try base64 DER decoding if string doesn't contain PEM markers.
	if !strings.Contains(rawStr, "-----BEGIN") {
		if der, err := decodeBase64Flexible(rawStr); err == nil {
			if key, err := parseRSAPrivateKeyDER(der); err == nil {
				return key, nil
			}
			if key, err := parseOpenSSHPrivateKey(der); err == nil {
				return key, nil
			}
		}
	}

	// 6. Try raw bytes directly as DER.
	if key, err := parseRSAPrivateKeyDER(raw); err == nil {
		return key, nil
	}

	return nil, errors.New("unable to parse RSA private key (expected PEM encoded PKCS#1 or PKCS#8)")
}

// LoadPublicKey loads an RSA public key from a file path or direct PEM/base64/DNS TXT string.
func LoadPublicKey(data string) (*rsa.PublicKey, error) {
	data = strings.TrimSpace(data)
	if data == "" {
		return nil, errors.New("public key data is empty")
	}

	resolvedPath := resolveFilePath(data)

	// Check if data is a path to an existing file or a likely file path.
	if !strings.Contains(data, "-----BEGIN") && !strings.Contains(data, "p=") && !strings.Contains(data, "ssh-rsa") {
		if info, err := os.Stat(resolvedPath); err == nil && !info.IsDir() {
			fileBytes, err := os.ReadFile(resolvedPath)
			if err != nil {
				return nil, fmt.Errorf("read public key file %q: %w", resolvedPath, err)
			}
			key, err := ParsePublicKey(fileBytes)
			if err != nil {
				return nil, fmt.Errorf("parse public key file %q: %w", resolvedPath, err)
			}
			return key, nil
		}

		if isLikelyFilePath(data) {
			fileBytes, err := os.ReadFile(resolvedPath)
			if err != nil {
				return nil, fmt.Errorf("read public key file %q: %w", resolvedPath, err)
			}
			key, err := ParsePublicKey(fileBytes)
			if err != nil {
				return nil, fmt.Errorf("parse public key file %q: %w", resolvedPath, err)
			}
			return key, nil
		}
	}

	return ParsePublicKey([]byte(data))
}

func parseRSAPublicKeyDER(der []byte) (*rsa.PublicKey, error) {
	// Try PKIX (SubjectPublicKeyInfo).
	if pub, err := x509.ParsePKIXPublicKey(der); err == nil {
		if rsaPub, ok := pub.(*rsa.PublicKey); ok {
			return rsaPub, nil
		}
		if _, ok := pub.(*ecdsa.PublicKey); ok {
			return nil, errors.New("public key is ECDSA (DKIM requires an RSA public key)")
		}
		if _, ok := pub.(ed25519.PublicKey); ok {
			return nil, errors.New("public key is Ed25519 (DKIM requires an RSA public key)")
		}
		return nil, errors.New("public key is not RSA")
	}

	// Try PKCS#1.
	if pub, err := x509.ParsePKCS1PublicKey(der); err == nil {
		return pub, nil
	}

	// Try X.509 Certificate.
	if cert, err := x509.ParseCertificate(der); err == nil {
		if rsaPub, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			return rsaPub, nil
		}
		return nil, errors.New("certificate public key is not RSA")
	}

	// Try OpenSSH wire format if container.
	if pub, err := parseOpenSSHPublicKey(der); err == nil {
		return pub, nil
	}

	return nil, errors.New("unable to parse RSA public key (expected PKIX, PKCS#1, or X.509 certificate)")
}

// ParsePublicKey parses an RSA public key from raw bytes (PEM PKIX, PKCS#1, Certificate, DNS TXT, or base64 DER).
func ParsePublicKey(raw []byte) (*rsa.PublicKey, error) {
	if len(raw) == 0 {
		return nil, errors.New("public key data is empty")
	}

	// Strip UTF-8 BOM if present.
	raw = bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf"))

	// 1. Try decoding standard PEM blocks directly.
	rest := raw
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "OPENSSH PUBLIC KEY" || block.Type == "SSH2 PUBLIC KEY" {
			if key, err := parseOpenSSHPublicKey(block.Bytes); err == nil {
				return key, nil
			}
		}
		if block.Type == "EC PUBLIC KEY" {
			return nil, errors.New("public key is ECDSA (DKIM requires an RSA public key)")
		}
		if key, err := parseRSAPublicKeyDER(block.Bytes); err == nil {
			return key, nil
		}
	}

	// 2. Unescape literal \n and \r sequences if present.
	rawStr := string(raw)
	if strings.Contains(rawStr, `\n`) || strings.Contains(rawStr, `\r`) {
		unescaped := strings.ReplaceAll(rawStr, `\r\n`, "\r\n")
		unescaped = strings.ReplaceAll(unescaped, `\n`, "\n")
		unescaped = strings.ReplaceAll(unescaped, `\r`, "\r")
		rest = []byte(unescaped)
		for len(rest) > 0 {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type == "OPENSSH PUBLIC KEY" || block.Type == "SSH2 PUBLIC KEY" {
				if key, err := parseOpenSSHPublicKey(block.Bytes); err == nil {
					return key, nil
				}
			}
			if block.Type == "EC PUBLIC KEY" {
				return nil, errors.New("public key is ECDSA (DKIM requires an RSA public key)")
			}
			if key, err := parseRSAPublicKeyDER(block.Bytes); err == nil {
				return key, nil
			}
		}
		rawStr = unescaped
	}

	// 3. Regex fallback to extract PEM blocks (e.g. single-line PEM with spaces).
	blocks := extractPEMBlocksRegex(rawStr)
	for _, block := range blocks {
		if block.Type == "EC PUBLIC KEY" {
			return nil, errors.New("public key is ECDSA (DKIM requires an RSA public key)")
		}
		if der, err := decodeBase64Flexible(block.Body); err == nil {
			if block.Type == "OPENSSH PUBLIC KEY" || block.Type == "SSH2 PUBLIC KEY" {
				if key, err := parseOpenSSHPublicKey(der); err == nil {
					return key, nil
				}
			}
			if key, err := parseRSAPublicKeyDER(der); err == nil {
				return key, nil
			}
		}
	}

	// 4. Try OpenSSH format (e.g. "ssh-rsa AAAAB3N... [comment]").
	if strings.Contains(rawStr, "ssh-rsa") {
		if key, err := parseOpenSSHPublicKey([]byte(rawStr)); err == nil {
			return key, nil
		}
	}

	// 5. Handle DNS TXT record formats (e.g. "v=DKIM1; k=rsa; p=MIIBIj...", Bind zone file format, etc.).
	target := rawStr
	if strings.Contains(target, "p=") {
		cleanDNS := strings.ReplaceAll(target, "\"", " ")
		cleanDNS = strings.ReplaceAll(cleanDNS, "(", " ")
		cleanDNS = strings.ReplaceAll(cleanDNS, ")", " ")
		cleanDNS = strings.ReplaceAll(cleanDNS, "\r", " ")
		cleanDNS = strings.ReplaceAll(cleanDNS, "\n", " ")

		parts := strings.Split(cleanDNS, ";")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(part, "p=") {
				target = strings.TrimSpace(strings.TrimPrefix(part, "p="))
				break
			}
		}
		if der, err := decodeBase64Flexible(target); err == nil {
			if key, err := parseRSAPublicKeyDER(der); err == nil {
				return key, nil
			}
		}
	}

	// 6. Try base64 DER decoding of target string when not containing PEM markers.
	if !strings.Contains(rawStr, "-----BEGIN") {
		if der, err := decodeBase64Flexible(target); err == nil {
			if key, err := parseRSAPublicKeyDER(der); err == nil {
				return key, nil
			}
			if key, err := parseOpenSSHPublicKey(der); err == nil {
				return key, nil
			}
		}
	}

	// 7. Try raw bytes directly as DER.
	if key, err := parseRSAPublicKeyDER(raw); err == nil {
		return key, nil
	}

	return nil, errors.New("unable to parse RSA public key (expected PEM encoded PKIX/PKCS#1, DNS TXT, or base64 DER)")
}

// ValidateKeyPair checks whether the provided RSA private and public keys form a matched pair.
func ValidateKeyPair(privKey *rsa.PrivateKey, pubKey *rsa.PublicKey) error {
	if privKey == nil {
		return errors.New("private key is nil")
	}
	if pubKey == nil {
		return errors.New("public key is nil")
	}
	if !privKey.PublicKey.Equal(pubKey) {
		return errors.New("public and private keys do not match")
	}
	return nil
}

// MatchKeys reports whether the provided RSA private and public keys form a matched pair.
func MatchKeys(privKey *rsa.PrivateKey, pubKey *rsa.PublicKey) bool {
	return ValidateKeyPair(privKey, pubKey) == nil
}

// SplitMessage separates an RFC 5322 message into raw headers and raw body.
func SplitMessage(msg []byte) (headers, body []byte) {
	if idx := bytes.Index(msg, []byte("\r\n\r\n")); idx >= 0 {
		return msg[:idx], msg[idx+4:]
	}
	if idx := bytes.Index(msg, []byte("\n\n")); idx >= 0 {
		return msg[:idx], msg[idx+2:]
	}
	return msg, nil
}

// ParseHeaders parses raw header bytes into a slice of HeaderField, unfolding continuation lines.
func ParseHeaders(headers []byte) []HeaderField {
	var fields []HeaderField
	s := string(headers)
	s = strings.ReplaceAll(s, "\r\n", "\n")
	lines := strings.Split(s, "\n")

	var currentKey, currentRawKey string
	var currentValue strings.Builder

	flush := func() {
		if currentRawKey != "" {
			fields = append(fields, HeaderField{
				RawKey: currentRawKey,
				Key:    currentKey,
				Value:  currentValue.String(),
			})
			currentRawKey = ""
			currentKey = ""
			currentValue.Reset()
		}
	}

	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			// Folded continuation line.
			if currentRawKey != "" {
				currentValue.WriteString(" ")
				currentValue.WriteString(strings.TrimSpace(line))
			}
		} else {
			flush()
			if colon := strings.IndexByte(line, ':'); colon >= 0 {
				currentRawKey = line[:colon]
				currentKey = strings.ToLower(strings.TrimSpace(currentRawKey))
				currentValue.WriteString(strings.TrimSpace(line[colon+1:]))
			}
		}
	}
	flush()
	return fields
}

// CanonicalizeHeaderRelaxed performs RFC 6376 Section 3.4.2 relaxed header canonicalization.
func CanonicalizeHeaderRelaxed(key, value string) string {
	key = strings.ToLower(strings.TrimSpace(key))

	var b strings.Builder
	inSpace := false
	for _, r := range value {
		if r == '\r' || r == '\n' || r == ' ' || r == '\t' {
			if !inSpace {
				b.WriteByte(' ')
				inSpace = true
			}
		} else {
			b.WriteRune(r)
			inSpace = false
		}
	}
	val := strings.TrimSpace(b.String())
	return key + ":" + val + "\r\n"
}

// CanonicalizeBodyRelaxed performs RFC 6376 Section 3.4.4 relaxed body canonicalization.
func CanonicalizeBodyRelaxed(body []byte) []byte {
	if len(body) == 0 {
		return nil
	}
	s := string(body)
	s = strings.ReplaceAll(s, "\r\n", "\n")
	lines := strings.Split(s, "\n")

	canonicalLines := make([]string, len(lines))
	for i, line := range lines {
		var b strings.Builder
		inSpace := false
		for _, r := range line {
			if r == ' ' || r == '\t' {
				if !inSpace {
					b.WriteByte(' ')
					inSpace = true
				}
			} else {
				b.WriteRune(r)
				inSpace = false
			}
		}
		canonicalLines[i] = strings.TrimRight(b.String(), " ")
	}

	// Delete all empty lines at the end of the body.
	lastNonEmpty := -1
	for i := len(canonicalLines) - 1; i >= 0; i-- {
		if canonicalLines[i] != "" {
			lastNonEmpty = i
			break
		}
	}
	if lastNonEmpty == -1 {
		return nil
	}

	var result strings.Builder
	for i := 0; i <= lastNonEmpty; i++ {
		result.WriteString(canonicalLines[i])
		result.WriteString("\r\n")
	}
	return []byte(result.String())
}

// Verify verifies a signed message against a given RSA public key.
func Verify(msg []byte, pubKey *rsa.PublicKey) error {
	if pubKey == nil {
		return errors.New("public key is required for verification")
	}

	headers, body := SplitMessage(msg)
	headerFields := ParseHeaders(headers)

	// Find the DKIM-Signature header.
	var dkimField *HeaderField
	var regularHeaders []HeaderField
	for i := range headerFields {
		if headerFields[i].Key == "dkim-signature" && dkimField == nil {
			dkimField = &headerFields[i]
		} else {
			regularHeaders = append(regularHeaders, headerFields[i])
		}
	}
	if dkimField == nil {
		return errors.New("no DKIM-Signature header found")
	}

	// Parse DKIM-Signature tags.
	tags := make(map[string]string)
	for _, part := range strings.Split(dkimField.Value, ";") {
		part = strings.TrimSpace(part)
		if k, v, ok := strings.Cut(part, "="); ok {
			tags[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}

	if tags["v"] != "1" {
		return fmt.Errorf("unsupported DKIM version: %s", tags["v"])
	}
	if tags["a"] != "rsa-sha256" {
		return fmt.Errorf("unsupported DKIM algorithm: %s", tags["a"])
	}
	canon := tags["c"]
	if canon == "" {
		canon = "simple/simple"
	}
	if canon != "relaxed/relaxed" {
		return fmt.Errorf("unsupported canonicalization: %s", canon)
	}

	// Verify body hash (bh).
	canonBody := CanonicalizeBodyRelaxed(body)
	bodyHash := sha256.Sum256(canonBody)
	expectedBH := base64.StdEncoding.EncodeToString(bodyHash[:])
	if tags["bh"] != expectedBH {
		return fmt.Errorf("body hash mismatch: got %s, calculated %s", tags["bh"], expectedBH)
	}

	// Canonicalize signed headers according to h= tag.
	hList := strings.Split(tags["h"], ":")
	hCount := make(map[string]int)
	for _, h := range hList {
		hCount[strings.ToLower(strings.TrimSpace(h))]++
	}

	// Match regular headers in order.
	var canonHeaders bytes.Buffer
	for _, reqName := range hList {
		reqName = strings.ToLower(strings.TrimSpace(reqName))
		found := false
		for _, hf := range regularHeaders {
			if hf.Key == reqName {
				canonHeaders.WriteString(CanonicalizeHeaderRelaxed(hf.RawKey, hf.Value))
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("signed header %q not found in message", reqName)
		}
	}

	// Rebuild DKIM-Signature header value with b= empty for signature verification.
	// We need to reconstruct the original header with b= replaced by b=.
	// Per RFC 6376, we take the original DKIM-Signature value, strip the b=... content, and canonicalize it.
	var rebuiltValue strings.Builder
	parts := strings.Split(dkimField.Value, ";")
	for i, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		if k, _, ok := strings.Cut(trimmed, "="); ok && strings.TrimSpace(k) == "b" {
			rebuiltValue.WriteString("b=")
			break
		} else {
			rebuiltValue.WriteString(trimmed)
			if i < len(parts)-1 {
				rebuiltValue.WriteString("; ")
			}
		}
	}

	canonDKIM := CanonicalizeHeaderRelaxed("DKIM-Signature", rebuiltValue.String())
	canonDKIM = strings.TrimRight(canonDKIM, "\r\n")
	canonHeaders.WriteString(canonDKIM)

	// Decode signature.
	cleanSig := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, tags["b"])
	sigBytes, err := base64.StdEncoding.DecodeString(cleanSig)
	if err != nil {
		return fmt.Errorf("decode signature base64: %w", err)
	}

	// Verify RSA signature.
	headerHash := sha256.Sum256(canonHeaders.Bytes())
	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, headerHash[:], sigBytes); err != nil {
		return fmt.Errorf("rsa signature verification failed: %w", err)
	}

	return nil
}

// GenerateKeyPair generates a new RSA private key of the given bit size (defaulting to 2048 if bits <= 0).
func GenerateKeyPair(bits int) (*rsa.PrivateKey, error) {
	if bits <= 0 {
		bits = 2048
	}
	if bits < 1024 {
		return nil, fmt.Errorf("RSA key size %d bits is too small (minimum 1024 bits required, 2048 bits recommended)", bits)
	}
	return rsa.GenerateKey(rand.Reader, bits)
}

// PEMEncodePrivateKey encodes an RSA private key in PKCS#1 PEM format.
func PEMEncodePrivateKey(privKey *rsa.PrivateKey) string {
	if privKey == nil {
		return ""
	}
	der := x509.MarshalPKCS1PrivateKey(privKey)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: der,
	}
	return string(pem.EncodeToMemory(block))
}

// PEMEncodePublicKey encodes an RSA public key in PKIX PEM format.
func PEMEncodePublicKey(pubKey *rsa.PublicKey) (string, error) {
	if pubKey == nil {
		return "", errors.New("public key is nil")
	}
	der, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", fmt.Errorf("marshal public key to PKIX: %w", err)
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}
	return string(pem.EncodeToMemory(block)), nil
}

// PublicKeyToDNSData returns the base64-encoded SubjectPublicKeyInfo string used in DKIM DNS TXT records.
func PublicKeyToDNSData(pubKey *rsa.PublicKey) (string, error) {
	if pubKey == nil {
		return "", errors.New("public key is nil")
	}
	der, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", fmt.Errorf("marshal public key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(der), nil
}

// FormatDNSTXTRecord formats the DNS TXT record name and value for a given selector, domain, and public key.
func FormatDNSTXTRecord(selector, domain string, pubKey *rsa.PublicKey) (recordName, recordValue string, err error) {
	selector = strings.TrimSpace(selector)
	if selector == "" {
		selector = "default"
	}
	domain = strings.TrimSpace(domain)
	domain = strings.TrimSuffix(domain, ".")

	dnsData, err := PublicKeyToDNSData(pubKey)
	if err != nil {
		return "", "", err
	}

	if domain != "" {
		recordName = fmt.Sprintf("%s._domainkey.%s.", selector, domain)
	} else {
		recordName = fmt.Sprintf("%s._domainkey.", selector)
	}
	recordValue = fmt.Sprintf("v=DKIM1; k=rsa; p=%s", dnsData)
	return recordName, recordValue, nil
}

// FormatDNSZoneEntry formats a complete DNS zone file TXT resource record entry.
func FormatDNSZoneEntry(selector, domain string, pubKey *rsa.PublicKey) (string, error) {
	name, val, err := FormatDNSTXTRecord(selector, domain, pubKey)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s IN TXT %q", name, val), nil
}
