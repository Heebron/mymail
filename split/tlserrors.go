package split

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

func explainTLSError(err error, side string) string {
	var verificationErr *tls.CertificateVerificationError
	if errors.As(err, &verificationErr) {
		if side == "client" {
			return explainServerCertificateError(verificationErr.Err, verificationCertificate(err))
		}
		cert := verificationCertificate(err)
		return fmt.Sprintf("the connecting client's certificate failed verification: %v; check that it chains to the CA in split_ca_cert_file and is valid for client authentication%s",
			verificationErr.Err, certificateDescriptionSuffix(cert))
	}
	if side == "server" && strings.Contains(err.Error(), "client didn't provide a certificate") {
		return "the connecting client did not send a certificate; configure tls_cert_file and tls_key_file on the client and verify the server requires the intended split peer"
	}

	if alert := remoteTLSAlert(err); alert != "" {
		switch alert {
		case "bad certificate", "unknown certificate authority", "certificate expired", "unsupported certificate", "certificate unknown":
			if side == "server" {
				return fmt.Sprintf("the connecting peer rejected this server's certificate with TLS alert %q; the alert does not identify whether the problem is trust, hostname, or validity, so check the peer's split_ca_cert_file, split_connect hostname, and certificate validity", alert)
			}
			return fmt.Sprintf("the remote server rejected this client's certificate with TLS alert %q; check that tls_cert_file is signed by the remote split_ca_cert_file, has the clientAuth extended key usage, and is currently valid", alert)
		case "certificate required":
			return "the remote server requires a client certificate, but this client did not send one; configure tls_cert_file and tls_key_file"
		default:
			return fmt.Sprintf("the connecting peer sent TLS alert %q; check both peers' certificate and TLS configuration", alert)
		}
	}

	return "TLS negotiation failed; check the peer's TLS certificate, trust settings, hostname, and client-certificate requirements"
}

func explainServerCertificateError(err error, cert *x509.Certificate) string {
	var unknownAuthority x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthority) {
		return "the server certificate chain is not signed by a trusted CA; split_ca_cert_file replaces the system root pool when set, so ensure it contains the CA that signed the server certificate" + certificateDescriptionSuffix(cert)
	}

	var hostnameErr x509.HostnameError
	if errors.As(err, &hostnameErr) {
		cert = hostnameErr.Certificate
		return fmt.Sprintf("the server certificate is not valid for split_connect host %q; its DNS names are %v; set split_connect to a certificate hostname and split_connect_ip to its address to retain hostname verification, or set split_ignore_server_name: true to skip only the name check%s",
			hostnameErr.Host, cert.DNSNames, certificateDescriptionSuffix(cert))
	}

	var invalidErr x509.CertificateInvalidError
	if errors.As(err, &invalidErr) {
		cert = invalidErr.Cert
		if invalidErr.Reason == x509.Expired {
			return fmt.Sprintf("the server certificate is outside its validity window (%s through %s)%s",
				cert.NotBefore.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339), certificateDescriptionSuffix(cert))
		}
		return fmt.Sprintf("the server certificate is invalid: %v%s", err, certificateDescriptionSuffix(cert))
	}

	return fmt.Sprintf("the server certificate could not be verified: %v; check split_ca_cert_file, the split_connect hostname, and certificate validity%s", err, certificateDescriptionSuffix(cert))
}

func verifyChainIgnoringServerName(config *tls.Config) *tls.Config {
	if config == nil {
		config = &tls.Config{}
	}
	verifiedConfig := config.Clone()
	verifyConnection := verifiedConfig.VerifyConnection
	verifiedConfig.InsecureSkipVerify = true
	verifiedConfig.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 {
			return &tls.CertificateVerificationError{Err: errors.New("peer did not provide a certificate")}
		}

		intermediates := x509.NewCertPool()
		for _, certificate := range state.PeerCertificates[1:] {
			intermediates.AddCert(certificate)
		}
		options := x509.VerifyOptions{
			Roots:         verifiedConfig.RootCAs,
			Intermediates: intermediates,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		if verifiedConfig.Time != nil {
			options.CurrentTime = verifiedConfig.Time()
		}
		chains, err := state.PeerCertificates[0].Verify(options)
		if err != nil {
			return &tls.CertificateVerificationError{
				UnverifiedCertificates: state.PeerCertificates,
				Err:                    err,
			}
		}
		if verifyConnection != nil {
			state.VerifiedChains = chains
			return verifyConnection(state)
		}
		return nil
	}
	return verifiedConfig
}

func remoteTLSAlert(err error) string {
	var opErr *net.OpError
	if !errors.As(err, &opErr) || opErr.Op != "remote error" || opErr.Err == nil {
		return ""
	}
	return strings.TrimPrefix(opErr.Err.Error(), "tls: ")
}

func configuredCertificate(config *tls.Config) *x509.Certificate {
	if config == nil || len(config.Certificates) == 0 || len(config.Certificates[0].Certificate) == 0 {
		return nil
	}
	cert := config.Certificates[0].Leaf
	if cert == nil {
		cert, _ = x509.ParseCertificate(config.Certificates[0].Certificate[0])
	}
	return cert
}

func verificationCertificate(err error) *x509.Certificate {
	var verificationErr *tls.CertificateVerificationError
	if errors.As(err, &verificationErr) && len(verificationErr.UnverifiedCertificates) > 0 {
		return verificationErr.UnverifiedCertificates[0]
	}
	var hostnameErr x509.HostnameError
	if errors.As(err, &hostnameErr) {
		return hostnameErr.Certificate
	}
	var invalidErr x509.CertificateInvalidError
	if errors.As(err, &invalidErr) {
		return invalidErr.Cert
	}
	return nil
}

func certificateDescriptionSuffix(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	dnsNames := cert.DNSNames
	if len(dnsNames) == 0 {
		dnsNames = []string{"(none)"}
	}
	return fmt.Sprintf(" (certificate subject %q, issuer %q, DNS names %v, valid %s through %s)",
		cert.Subject.String(), cert.Issuer.String(), dnsNames,
		cert.NotBefore.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339))
}

func certificateLogAttrs(prefix string, cert *x509.Certificate) []any {
	if cert == nil {
		return nil
	}
	return []any{
		prefix + "_subject", cert.Subject.String(),
		prefix + "_issuer", cert.Issuer.String(),
		prefix + "_dns_names", cert.DNSNames,
		prefix + "_not_before", cert.NotBefore,
		prefix + "_not_after", cert.NotAfter,
	}
}
