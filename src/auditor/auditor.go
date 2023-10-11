package auditor

import (
	"log/slog"
	"os"
)

// Auditor represents an entity capable of emitting
// rich audit logs for certificate issuance events.
type Auditor interface {
	Audit(*Event) error
}

// auditor is an internal-only implementation of the Auditor interface.
type auditor struct {
	logger *slog.Logger
}

// ensure auditor implements Auditor.
var _ Auditor = (*auditor)(nil)

// New returns the default Auditor.
func New() Auditor {
	return &auditor{
		logger: slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{})),
	}
}

// Audit handles an audit event.
func (a *auditor) Audit(e *Event) error {
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
