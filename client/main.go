package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"net"
	"net/http"
	"os"
)

type certificateSigningRequest struct {
	ASN1Data []byte `json:"asn1data"`
}

type certificateSigningResponse struct {
	Certificate []byte `json:"certificate"`
}

func main() {
	privateKeyFilename := os.Args[1]
	certificateFilename := os.Args[2]

	// create private key and save it
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("failed to generate RSA key pair: %v", err)
	}
	privateKeyFile, err := os.Create(privateKeyFilename)
	if err != nil {
		log.Fatalf("failed to open %s for writing key: %v", privateKeyFilename, err)
	}
	defer privateKeyFile.Close()
	privateKeyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	if _, err := privateKeyFile.Write(privateKeyPem); err != nil {
		log.Fatalf("failed to write privkey data to %s: %v", privateKeyFilename, err)
	}

	// create CSR, get a certificate, and save it
	csrTemplate := x509.CertificateRequest{
		Subject: pkix.Name{
			Organization: []string{"Example, Inc."},
			Country:      []string{"US"},
		},
		IPAddresses:        []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:           []string{"localhost"},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	csrBytesDER, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, privateKey)
	if err != nil {
		log.Fatalf("failed to create CSR: %v", err)
	}
	bodyBytes, err := json.Marshal(certificateSigningRequest{ASN1Data: csrBytesDER})
	if err != nil {
		log.Fatalf("failed to marshal certificate signing request to json: %v", err)
	}
	resp, err := http.Post("http://localhost:8080/certificates/sign", "application/json", bytes.NewBuffer(bodyBytes))
	if err != nil {
		log.Fatalf("failed to make certificate signing request: %v", err)
	}
	defer resp.Body.Close()
	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("failed to read response body: %v", err)
	}
	var response certificateSigningResponse
	if err = json.Unmarshal(respBytes, &response); err != nil {
		log.Fatalf("failed to unmarshal response body: %v", err)
	}
	pemCertData := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: response.Certificate,
	})
	certificateFile, err := os.Create(certificateFilename)
	if err != nil {
		log.Fatalf("Failed to open %s for writing csr: %v", certificateFilename, err)
	}
	defer certificateFile.Close()
	if _, err := certificateFile.Write(pemCertData); err != nil {
		log.Fatalf("Failed to write csr data to %s: %v", certificateFilename, err)
	}

}
