package service

import (
	"crypto/x509"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

type certificateSigningRequestBody struct {
	ASN1Data []byte `json:"asn1data"`
}

func (s *Service) certificateSigningRequestHandler(c *gin.Context) {
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

	cert, err := s.iss.IssueCertificate(csr)
	if err != nil {
		// FIXME: log and do not return error
		c.AbortWithStatusJSON(
			http.StatusInternalServerError,
			gin.H{"error": fmt.Sprintf("failed to issue certificate: %v", err)},
		)
		return
	}

	c.AbortWithStatusJSON(http.StatusOK, gin.H{"certificate": cert})
	return
}
