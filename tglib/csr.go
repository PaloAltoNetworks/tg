package tglib

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
)

// LoadCSRs loads the given bytes as an array of Certificate Signing Request.
func LoadCSRs(csrData []byte) ([]*x509.CertificateRequest, error) {

	csrs := []*x509.CertificateRequest{}

	var block *pem.Block
	block, csrData = pem.Decode(csrData)

	for ; block != nil; block, csrData = pem.Decode(csrData) {
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			return nil, err
		}
		if err := csr.CheckSignature(); err != nil {
			return nil, err
		}
		csrs = append(csrs, csr)
	}

	return csrs, nil
}

// GenerateSimpleCSR generate a CSR using the given parameters.
func GenerateSimpleCSR(orgs []string, units []string, commonName string, emails []string, privateKey crypto.PrivateKey) ([]byte, error) {

	csr := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:         commonName,
			Organization:       orgs,
			OrganizationalUnit: units,
		},
		EmailAddresses:     emails,
		SignatureAlgorithm: x509.ECDSAWithSHA384,
	}

	return GenerateCSR(csr, privateKey)
}

// GenerateCSR generate a CSR using the given parameters.
func GenerateCSR(csr *x509.CertificateRequest, privateKey crypto.PrivateKey) ([]byte, error) {

	csrDerBytes, err := x509.CreateCertificateRequest(rand.Reader, csr, privateKey)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDerBytes}), nil
}
