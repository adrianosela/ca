package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"log"
	"net/http"
	"time"

	"github.com/adrianosela/ca/src/auditor"
	"github.com/adrianosela/ca/src/issuer"
	"github.com/adrianosela/ca/src/service"
	"github.com/adrianosela/ca/src/template"
	"github.com/adrianosela/kmssigner"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

const (
	kmsKeyId             = "alias/my-ca-certificate-key"
	issuerCertificatePEM = `-----BEGIN CERTIFICATE-----
MIIDYTCCAkmgAwIBAgIINgIDyGR/gtEwDQYJKoZIhvcNAQELBQAwPzELMAkGA1UE
BhMCQ0ExGjAYBgNVBAoTEUFkcmlhbm8gU2VsYSBJbmMuMRQwEgYDVQQDEwthZHJp
YW5vc2VsYTAeFw0yMzEwMTAxODQzMjVaFw0zMzEwMDcxODQ4MjVaMD8xCzAJBgNV
BAYTAkNBMRowGAYDVQQKExFBZHJpYW5vIFNlbGEgSW5jLjEUMBIGA1UEAxMLYWRy
aWFub3NlbGEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCqsDA4LGhE
fjsTiD+4OY7aPPy4FbBb/yAUo3g+X5iUmEpelpIIxPjBjSPk4on6yXyRE4kzrshK
OleAthHXZD/JtUdkL9cBM8EibGhi8yRLpTOEWeUUs1vFieTDk4e8JjYp8gNnlxkJ
F9wJJoIN+0spIopv91cEjLLIqpVxYx5eaM7ozhYVWfC3OSczzR1b9Kl7pHjDoiyP
A/BM3Buso7cI/+vcnsExPh5oKp0pMBpBDONJuluAOYso2Xn45mdTxy2xmlVIBVeI
JwlexRzVIQhvFmhPKEf5bDrLOEGMtestdWT7OdO3URgE784ASE1pVoB56OehEqtR
0iquH291K1G3AgMBAAGjYTBfMA4GA1UdDwEB/wQEAwIChDAdBgNVHSUEFjAUBggr
BgEFBQcDAgYIKwYBBQUHAwEwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUO43u
O6t0qWa6KOEiu2wo2bP6JkMwDQYJKoZIhvcNAQELBQADggEBAA6GxMHxX5O4b5qN
NzhD8tY845lTr/46a2BdpvkzJcD/5lmvAidXEUnViAwpBNMdxDqkl+X9YLO5qoex
feXbf2zlA2mLjYe6ZPUV+YKKidIV4cO7A8lA7nPzm7YyZUXk50ohjpLx5SsFdkha
UHDjsgXRc0e506JuQhEfwQBkK9dC4O/rUTttC3pgmkAxWXumxzqEpUumUy/VmyHu
aCif7n5lfVM1rU0bb4+4Y9uCfYVR2CTchDvap4i/E+iNbmb4/XzrWX9Oz3iDORr2
JUdeyYWZMtwX2tezyQS894oemgHR1Up6mTxnoF12uncUjs2GetGucC0O5wQZAxYx
dxaYKUk=
-----END CERTIFICATE-----`
)

func main() {
	ctx := context.Background()

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		log.Fatalf("failed to load AWS SDK config: %v", err)
	}

	signer, err := kmssigner.NewSigner(cfg, kmsKeyId, types.SigningAlgorithmSpecRsassaPkcs1V15Sha256)
	if err != nil {
		log.Fatalf("failed to initialize KMS signer: %v", err)
	}

	issuerCertificateDER, _ := pem.Decode([]byte(issuerCertificatePEM))
	issuerCertificate, err := x509.ParseCertificate(issuerCertificateDER.Bytes)
	if err != nil {
		log.Fatalf("failed to parse x509 issuer certificate from PEM: %v", err)
	}

	svc := service.NewService(
		issuer.New(
			issuerCertificate,
			signer,
			template.New(time.Minute*5, time.Minute*5),
		),
		auditor.New(),
	)

	if err = http.ListenAndServe(":80", svc.HTTPHandler()); err != nil {
		log.Fatalf("failed to listen and serve http: %v", err)
	}
}
