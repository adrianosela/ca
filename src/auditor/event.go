package auditor

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
	Timestamp                 int64                     `json:"timestamp"`
	Client                    Client                    `json:"client"`
	CertificateSigningRequest CertificateSigningRequest `json:"csr"`
	IssuedCertificate         IssuedCertificate         `json:"issued_certificate"`
}
