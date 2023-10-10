package service

import (
	"encoding/pem"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

func (s *Service) caHandler(c *gin.Context) {
	cert, err := s.iss.IssuerCertificate()
	if err != nil {
		// FIXME: log and do not return error
		c.AbortWithStatusJSON(
			http.StatusInternalServerError,
			gin.H{"error": fmt.Sprintf("failed to retrieve issuer certificate: %v", err)},
		)
		return
	}

	if c.Query("format") == "pem" {
		cert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})
		c.AbortWithStatusJSON(http.StatusOK, gin.H{"certificate": string(cert)})
		return
	}

	c.AbortWithStatusJSON(http.StatusOK, gin.H{"certificate": cert})
	return
}
