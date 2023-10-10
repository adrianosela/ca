package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"log"
	"math/big"
	"math/rand"
	"net/http"
	"time"

	"github.com/adrianosela/ca/src/issuer"
	"github.com/adrianosela/ca/src/service"
	"github.com/adrianosela/kmssigner"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

const (
	kmsKeyId             = "alias/my-ca-certificate-key"
	issuerCertificatePEM = `-----BEGIN CERTIFICATE-----
MIIDYTCCAkmgAwIBAgIIYUPs0/pgUuowDQYJKoZIhvcNAQELBQAwPzELMAkGA1UE
BhMCQ0ExGjAYBgNVBAoTEUFkcmlhbm8gU2VsYSBJbmMuMRQwEgYDVQQDEwthZHJp
YW5vc2VsYTAeFw0yMzEwMDgxOTAzNThaFw0zMzEwMDUxOTA4NThaMD8xCzAJBgNV
BAYTAkNBMRowGAYDVQQKExFBZHJpYW5vIFNlbGEgSW5jLjEUMBIGA1UEAxMLYWRy
aWFub3NlbGEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDC+BDzFcr3
LRM5ITUlqGLXvYWNczxI8lavxTgU5TQPPoS+h6Up99yJzNWzJcjwwDEJdNa0Iffq
ygLYj6Zvbye5hNIXnOKh/4+meFRBAzazgaOq5w6Inl5T0ct1yd9p+oecXZPK27lv
C3BhIx4xUnhrhoH8DkmoiJbyzl52SUWyetu4qMnYA/vVTmvudWuMCYErMAwGAJ7z
IENCi7+DIF/mRNowrDm75yMNNOpWdvbUSF+o9/V83QUPQspkFDP9A8xnAWxJGls5
WsQnDoK2K1k/lpy175sqbgv+rmF4MDYS9zbGyLNaPGJWRrYXQ5lWme03+3WzAEya
5azmjbAP0bEBAgMBAAGjYTBfMA4GA1UdDwEB/wQEAwIChDAdBgNVHSUEFjAUBggr
BgEFBQcDAgYIKwYBBQUHAwEwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU7TnZ
AzVQYDFfDFTRS4eyJAkrnYIwDQYJKoZIhvcNAQELBQADggEBAA1OD+j+PpWFDFER
tGWMGm6YUJ6w3ZVPOeEaN2YLWgG70l/H2JDO0DrG7R30eYWqCryedoivZF7tUFvJ
V65DQOhyzHcyHnjDayNHOMzk0QXGKh0VITZzA65oRDUERCl9jx14PiLVBAkB6GWK
liBN8mU/YhcSpu5T/MBnqdH4y1RDiMdVnCf+yadMFQ4U2uHfz0/TQZMOq/c0M6yM
6sGTT94NdzVJpAWEI8g3oJAbc2niEzfm89OPrNJ+WXGt6iQ/LthJWEwJdbLFdo7j
FkK4pPQDZzL7eEsFb9rc+puXja0cp+anDw/dNe4ZZ6+dumviW6BOoekmqTPzaCow
7oTKU0E=
-----END CERTIFICATE-----`
)

type templateBuilder struct {
	clockSkew time.Duration
	lifespan  time.Duration
}

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

func main() {
	ctx := context.Background()

	issuerCertificateDER, _ := pem.Decode([]byte(issuerCertificatePEM))
	issuerCertificate, err := x509.ParseCertificate(issuerCertificateDER.Bytes)
	if err != nil {
		log.Fatalf("failed to parse x509 issuer certificate from PEM: %v", err)
	}

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		log.Fatalf("failed to load AWS SDK config: %v", err)
	}

	signer, err := kmssigner.NewSigner(cfg, kmsKeyId, types.SigningAlgorithmSpecRsassaPkcs1V15Sha256)
	if err != nil {
		log.Fatalf("failed to initialize KMS signer: %v", err)
	}

	svc := service.NewService(issuer.New(
		issuerCertificate,
		signer,
		&templateBuilder{
			clockSkew: time.Minute * 5,
			lifespan:  time.Minute * 5,
		},
	))

	if err = http.ListenAndServe(":80", svc.HTTPHandler()); err != nil {
		log.Fatalf("failed to listen and serve http: %v", err)
	}
}
