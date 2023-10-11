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

// Client represents the portion of an
// audit event describing the client.
type Client struct {
	IPAddress string `json:"ip_address"`
	UserAgent string `json:"user_agent"`
}

// CertificateSigningRequest represents the portion of an
// audit event describing the certificate signing request.
type CertificateSigningRequest struct {
	PublicKey            string `json:"public_key"`
	PublicKeyFingerprint string `json:"public_key_fingerprint"`
}

// IssuedCertificate represents the portion of an
// audit event describing the issued certificate.
type IssuedCertificate struct {
	SerialNumber   string   `json:"serial_number"`
	Issuer         string   `json:"issuer"`
	Subject        string   `json:"subject"`
	NotBefore      string   `json:"not_before"`
	NotAfter       string   `json:"not_after"`
	IPAddresses    []string `json:"ip_addresses"`
	DNSNames       []string `json:"dns_names"`
	EmailAddresses []string `json:"email_addresses"`
	URIs           []string `json:"uris"`
	Raw            string   `json:"raw"`
}

// Event represents an audit event.
type Event struct {
	Client                    Client                    `json:"client"`
	CertificateSigningRequest CertificateSigningRequest `json:"csr"`
	IssuedCertificate         IssuedCertificate         `json:"issued_certificate"`
}

type auditor struct {
	logger *slog.Logger
}

func New() Auditor {
	return &auditor{
		logger: slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{})),
	}
}

func (a *auditor) Audit(e *Event) error {
	a.logger.Info(
		"issued certificate",
		"client.ip_address", e.Client.IPAddress,
		"client.user_agent", e.Client.UserAgent,
		"csr.public_key", e.CertificateSigningRequest.PublicKey,
		"csr.public_key_fingerprint", e.CertificateSigningRequest.PublicKeyFingerprint,
		"issued_certificate.serial_number", e.IssuedCertificate.SerialNumber,
		"issued_certificate.issuer", e.IssuedCertificate.Issuer,
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
