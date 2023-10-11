package auditor

// Client represents the portion of an
// audit event describing the client.
type Client struct {
	IPAddress string `json:"ip_address" ion:"ipAddress"`
	UserAgent string `json:"user_agent" ion:"userAgent"`
}

// CertificateSigningRequest represents the portion of an
// audit event describing the certificate signing request.
type CertificateSigningRequest struct {
	PublicKey            string `json:"public_key"             ion:"publicKey"`
	PublicKeyFingerprint string `json:"public_key_fingerprint" ion:"publicKeyFingerprint"`
}

// IssuedCertificate represents the portion of an
// audit event describing the issued certificate.
type IssuedCertificate struct {
	SerialNumber   string   `json:"serial_number"   ion:"serialNumber"`
	Issuer         string   `json:"issuer"          ion:"issuer"`
	Subject        string   `json:"subject"         ion:"subject"`
	NotBefore      string   `json:"not_before"      ion:"notBefore"`
	NotAfter       string   `json:"not_after"       ion:"notAfter"`
	IPAddresses    []string `json:"ip_addresses"    ion:"ipAddresses"`
	DNSNames       []string `json:"dns_names"       ion:"dnsNames"`
	EmailAddresses []string `json:"email_addresses" ion:"emailAddresses"`
	URIs           []string `json:"uris"            ion:"uris"`
	Raw            string   `json:"raw"             ion:"raw"`
}

// HTTPRequest represents the portion of an
// audit event describing the http request.
type HTTPRequest struct {
	ParseRequestBodyDuration int64 `json:"parse_request_body_duration_ms" ion:"parseRequestBodyDurationMs"`
	ParseCSRDuration         int64 `json:"parse_csr_duration_ms"          ion:"parseCsrDurationMs"`
	IssueCertificateDuration int64 `json:"issue_certificate_duration_ms"  ion:"issueCertificateDurationMs"`
}

// Event represents an audit event.
type Event struct {
	EventID                   string                    `json:"event_id"           ion:"eventId"`
	Timestamp                 int64                     `json:"timestamp"          ion:"timestamp"`
	Client                    Client                    `json:"client"             ion:"client"`
	CertificateSigningRequest CertificateSigningRequest `json:"csr"                ion:"csr"`
	IssuedCertificate         IssuedCertificate         `json:"issued_certificate" ion:"issuedCertificate"`
	HTTPRequest               HTTPRequest               `json:"http_request"       ion:"httpRequest"`
}
