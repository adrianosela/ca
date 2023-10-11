package service

import (
	"net/http"

	"github.com/adrianosela/ca/src/auditor"
	"github.com/adrianosela/ca/src/issuer"
	"github.com/gin-gonic/gin"
)

type Service struct {
	iss     issuer.CertificateIssuer
	auditor auditor.Auditor
}

func NewService(
	iss issuer.CertificateIssuer,
	auditor auditor.Auditor,
) *Service {
	return &Service{
		iss:     iss,
		auditor: auditor,
	}
}

func (s *Service) HTTPHandler() http.Handler {
	r := gin.Default()

	r.GET("/certificates/ca", s.caHandler)
	r.POST("/certificates/sign", s.signHandler)

	return r
}
