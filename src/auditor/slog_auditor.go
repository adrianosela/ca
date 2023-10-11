package auditor

import (
	"io"

	"log/slog"
)

// SlogAuditor is a slog implementation of the Auditor interface.
type SlogAuditor struct {
	logger *slog.Logger
}

// ensure SlogAuditor implements Auditor.
var _ Auditor = (*SlogAuditor)(nil)

// NewSlog returns a slog implementation of the Auditor interface.
func NewSlog(w io.Writer, opts *slog.HandlerOptions) *SlogAuditor {
	if opts == nil {
		opts = &slog.HandlerOptions{}
	}
	return &SlogAuditor{
		logger: slog.New(slog.NewJSONHandler(w, opts)),
	}
}

// Audit handles an audit event.
func (a *SlogAuditor) Audit(e *Event) error {
	a.logger.Info(
		"issued certificate",
		"client.ip_address", e.Client.IPAddress,
		"client.user_agent", e.Client.UserAgent,
		"csr.public_key", e.CertificateSigningRequest.PublicKey,
		"csr.public_key_fingerprint", e.CertificateSigningRequest.PublicKeyFingerprint,
		"issued_certificate.serial_number", e.IssuedCertificate.SerialNumber,
		"issued_certificate.subject", e.IssuedCertificate.Subject,
		"issued_certificate.not_before", e.IssuedCertificate.NotBefore,
		"issued_certificate.not_after", e.IssuedCertificate.NotAfter,
		"issued_certificate.ip_addresses", e.IssuedCertificate.IPAddresses,
		"issued_certificate.dns_names", e.IssuedCertificate.DNSNames,
		"issued_certificate.email_addresses", e.IssuedCertificate.EmailAddresses,
		"issued_certificate.uris", e.IssuedCertificate.URIs,
		"issued_certificate.raw", e.IssuedCertificate.Raw,
	)
	return nil
}
