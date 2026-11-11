package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"mymail/config"
)

// receivedCertificateLabel identifies certificates received over the split
// link in log messages that normally report a certificate file path.
const receivedCertificateLabel = "received from split local"

// peerCertificateStore holds the SMTP server certificate that a remote-only
// split instance serves. The certificate is held in memory only; it is either
// seeded from tls_cert_file or received from the local over the split link.
type peerCertificateStore struct {
	mu       sync.RWMutex
	cert     *tls.Certificate
	hostname string
	logger   *slog.Logger
	now      func() time.Time
}

func newPeerCertificateStore(hostname string, logger *slog.Logger) *peerCertificateStore {
	return &peerCertificateStore{hostname: hostname, logger: logger, now: time.Now}
}

// SetCertificate installs an already loaded certificate, such as one read
// from tls_cert_file at startup.
func (s *peerCertificateStore) SetCertificate(cert *tls.Certificate) {
	s.mu.Lock()
	s.cert = cert
	s.mu.Unlock()
}

// Set validates a PEM certificate chain and private key received from the
// local and replaces the current certificate. An invalid pair leaves the
// current certificate in place.
func (s *peerCertificateStore) Set(certPEM, keyPEM []byte) error {
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("invalid TLS certificate or private key: %w", err)
	}
	if certificate.Leaf == nil {
		leaf, err := x509.ParseCertificate(certificate.Certificate[0])
		if err != nil {
			return fmt.Errorf("parse TLS certificate: %w", err)
		}
		certificate.Leaf = leaf
	}
	leaf := certificate.Leaf
	now := s.now()
	if now.Before(leaf.NotBefore) {
		return fmt.Errorf("TLS certificate %q is not valid until %s", leaf.Subject.String(), leaf.NotBefore.UTC().Format(time.RFC3339))
	}
	if now.After(leaf.NotAfter) {
		return fmt.Errorf("TLS certificate %q expired at %s", leaf.Subject.String(), leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	if s.hostname != "" {
		if err := leaf.VerifyHostname(s.hostname); err != nil && s.logger != nil {
			s.logger.Warn("TLS certificate received from split local does not match hostname",
				"hostname", s.hostname,
				"subject_dn", leaf.Subject.String(),
				"subject_alt_names", certificateSANs(leaf),
			)
		}
	}
	if _, _, err := logTLSCertificate(s.logger, &certificate, receivedCertificateLabel); err != nil {
		return fmt.Errorf("inspect TLS certificate: %w", err)
	}
	s.SetCertificate(&certificate)
	return nil
}

// GetCertificate implements tls.Config.GetCertificate.
func (s *peerCertificateStore) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.cert == nil {
		return nil, errors.New("no TLS certificate has been received from the split local yet")
	}
	return s.cert, nil
}

// Available reports whether a certificate is ready to be served.
func (s *peerCertificateStore) Available() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cert != nil
}

// sendSplitTLSCertificate reads tls_cert_file and tls_key_file and sends them
// to the remote. The files are read on every call so a renewed certificate is
// picked up when the split link reconnects. Nothing is sent when the remote's
// certificate is not verified, because the private key must not be given to
// an unauthenticated peer.
func sendSplitTLSCertificate(cfg *config.Config, send func(certPEM, keyPEM []byte) error, logger *slog.Logger) error {
	if cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" {
		return nil
	}
	if cfg.SplitInsecureSkipVerify {
		logger.Warn("split TLS certificate not sent to remote because split_insecure_skip_verify is enabled; configure tls_cert_file and tls_key_file on the remote instead",
			"address", cfg.SplitConnect)
		return nil
	}
	certPEM, err := os.ReadFile(cfg.TLSCertFile)
	if err != nil {
		return fmt.Errorf("read tls_cert_file: %w", err)
	}
	keyPEM, err := os.ReadFile(cfg.TLSKeyFile)
	if err != nil {
		return fmt.Errorf("read tls_key_file: %w", err)
	}
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return fmt.Errorf("load tls_cert_file and tls_key_file: %w", err)
	}
	return send(certPEM, keyPEM)
}
