package issuer

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"fmt"
)

// CertificateIssuer represents an entity capable of
// issuing (DER encoded) signed x509 certificates.
type CertificateIssuer interface {
	IssueCertificate(*x509.CertificateRequest) ([]byte, error)
}

// CertificateTemplateBuilder represents an entity capable of building
// an x509 certificate template based off of an x509 certificate request
type CertificateTemplateBuilder interface {
	BuildTemplate(*x509.CertificateRequest) (*x509.Certificate, error)
}

// issuer is an internal-only implementation of the CertificateIssuer interface.
type issuer struct {
	issuerCert      *x509.Certificate
	signer          crypto.Signer
	templateBuilder CertificateTemplateBuilder
}

// ensure issuer implements CertificateIssuer.
var _ CertificateIssuer = (*issuer)(nil)

// New returns the default CertificateIssuer.
func New(
	issuerCert *x509.Certificate,
	signer crypto.Signer,
	templateBuilder CertificateTemplateBuilder,
) CertificateIssuer {
	return &issuer{
		issuerCert:      issuerCert,
		signer:          signer,
		templateBuilder: templateBuilder,
	}
}

// IssueCertificate issues a (DER encoded) signed x509 certificate.
func (i *issuer) IssueCertificate(csr *x509.CertificateRequest) ([]byte, error) {
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("failed to verify signature on CSR: %v", err)
	}
	template, err := i.templateBuilder.BuildTemplate(csr)
	if err != nil {
		return nil, fmt.Errorf("failed to build x509 certificate template from CSR: %v", err)
	}
	derEncodedCert, err := x509.CreateCertificate(
		rand.Reader,
		template,
		i.issuerCert,
		csr.PublicKey,
		i.signer,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create x509 certificate: %v", err)
	}
	return derEncodedCert, nil
}
