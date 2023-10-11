package service

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/http"

	"github.com/adrianosela/ca/src/auditor"
	"github.com/gin-gonic/gin"
)

type certificateSigningRequestBody struct {
	ASN1Data []byte `json:"asn1data"`
}

func (s *Service) signHandler(c *gin.Context) {
	var payload *certificateSigningRequestBody
	if err := c.BindJSON(&payload); err != nil {
		c.AbortWithStatusJSON(
			http.StatusBadRequest,
			gin.H{"error": fmt.Sprintf("invalid request body: %v", err)},
		)
		return
	}

	csr, err := x509.ParseCertificateRequest(payload.ASN1Data)
	if err != nil {
		c.AbortWithStatusJSON(
			http.StatusBadRequest,
			gin.H{"error": fmt.Sprintf("invalid request body: %v", err)},
		)
		return
	}

	cert, certDER, err := s.iss.IssueCertificate(csr)
	if err != nil {
		// FIXME: log and do not return error
		c.AbortWithStatusJSON(
			http.StatusInternalServerError,
			gin.H{"error": fmt.Sprintf("failed to issue certificate: %v", err)},
		)
		return
	}

	event, err := buildAuditEvent(c, csr, cert, certDER)
	if err != nil {
		// FIXME: log and do not return error
		c.AbortWithStatusJSON(
			http.StatusInternalServerError,
			gin.H{"error": fmt.Sprintf("failed to build audit event: %v", err)},
		)
		return
	}

	if err = s.auditor.Audit(event); err != nil {
		// FIXME: log and do not return error
		c.AbortWithStatusJSON(
			http.StatusInternalServerError,
			gin.H{"error": fmt.Sprintf("failed to emit audit event: %v", err)},
		)
		return
	}

	if c.Query("format") == "pem" {
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
		c.AbortWithStatusJSON(http.StatusOK, gin.H{"certificate": string(certPEM)})
		return
	}

	c.AbortWithStatusJSON(http.StatusOK, gin.H{"certificate": certDER})
	return
}

func buildAuditEvent(
	c *gin.Context,
	csr *x509.CertificateRequest,
	cert *x509.Certificate,
	certDER []byte,
) (*auditor.Event, error) {
	publicKeyDER, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal PKIX public key: %v", err)
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyDER,
	})

	hash := sha256.Sum256(publicKeyDER)
	publicKeyFingerprint := hex.EncodeToString(hash[:])

	ipAddresses := []string{}
	for _, ip := range cert.IPAddresses {
		ipAddresses = append(ipAddresses, ip.String())
	}

	emails := []string{}
	for _, email := range cert.EmailAddresses {
		emails = append(emails, email)
	}

	dnsNames := []string{}
	for _, dnsName := range cert.DNSNames {
		dnsNames = append(dnsNames, dnsName)
	}

	uris := []string{}
	for _, uri := range cert.URIs {
		uris = append(uris, uri.String())
	}

	return &auditor.Event{
		Client: auditor.Client{
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
		},
		CertificateSigningRequest: auditor.CertificateSigningRequest{
			PublicKey:            string(publicKeyPEM),
			PublicKeyFingerprint: publicKeyFingerprint,
		},
		IssuedCertificate: auditor.IssuedCertificate{
			SerialNumber:   cert.SerialNumber.String(),
			Issuer:         cert.Issuer.String(),
			Subject:        cert.Subject.String(),
			NotBefore:      cert.NotBefore.String(),
			NotAfter:       cert.NotAfter.String(),
			IPAddresses:    ipAddresses,
			DNSNames:       dnsNames,
			EmailAddresses: emails,
			URIs:           uris,
			Raw:            string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})),
		},
	}, nil
}
