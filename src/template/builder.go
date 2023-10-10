package template

import (
	"crypto/x509"
	"math/big"
	"math/rand"
	"time"
)

// CertificateTemplateBuilder represents an entity capable of building
// an x509 certificate template based off of an x509 certificate request
type CertificateTemplateBuilder interface {
	BuildTemplate(*x509.CertificateRequest) (*x509.Certificate, error)
}

// templateBuilder is an internal-only implementation
// of the CertificateTemplateBuilder interface.
type templateBuilder struct {
	clockSkew time.Duration
	lifespan  time.Duration
}

// BuildTemplate builds a certificate template based off of a given certificate signing request (CSR).
func (t *templateBuilder) BuildTemplate(csr *x509.CertificateRequest) (*x509.Certificate, error) {
	return &x509.Certificate{
		SerialNumber: big.NewInt(rand.Int63()),
		NotBefore:    time.Now().Add(-1 * t.clockSkew),
		NotAfter:     time.Now().Add(t.lifespan),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},

		// fields from CSR, tweak as needed
		Subject:     csr.Subject,
		IPAddresses: csr.IPAddresses,
		DNSNames:    csr.DNSNames,
	}, nil
}

// ensure templateBuilder implements CertificateTemplateBuilder.
var _ CertificateTemplateBuilder = (*templateBuilder)(nil)

// New returns the default CertificateTemplateBuilder.
func New(
	clockSkew time.Duration,
	lifespan time.Duration,
) CertificateTemplateBuilder {
	return &templateBuilder{
		clockSkew: clockSkew,
		lifespan:  lifespan,
	}
}
