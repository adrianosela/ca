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

// HTTPRequest represents the portion of an
// audit event describing the http request.
type HTTPRequest struct {
	ParseRequestBodyDuration int64 `json:"parse_request_body_duration_ms"`
	ParseCSRDuration         int64 `json:"parse_csr_duration_ms"`
	IssueCertificateDuration int64 `json:"issue_certificate_duration_ms"`
}

// Event represents an audit event.
type Event struct {
	Timestamp                 int64                     `json:"timestamp"`
	Client                    Client                    `json:"client"`
	CertificateSigningRequest CertificateSigningRequest `json:"csr"`
	IssuedCertificate         IssuedCertificate         `json:"issued_certificate"`
	HTTPRequest               HTTPRequest               `json:"http_request"`
}
