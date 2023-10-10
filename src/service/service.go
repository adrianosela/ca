package service

import (
	"net/http"

	"github.com/adrianosela/ca/src/issuer"
	"github.com/gin-gonic/gin"
)

type Service struct {
	iss issuer.CertificateIssuer
}

func NewService(iss issuer.CertificateIssuer) *Service {
	return &Service{iss: iss}
}

func (s *Service) HTTPHandler() http.Handler {
	r := gin.Default()

	r.GET("/certificates/ca", s.caHandler)
	r.POST("/certificates/sign", s.signHandler)

	return r
}
