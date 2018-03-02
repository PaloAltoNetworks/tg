package tglib

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
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

// GenerateCSRwithSANs generates a SPIFFE certificate CSR.
func GenerateCSRwithSANs(orgs []string, units []string, commonName string, sans []string, privateKey crypto.PrivateKey) ([]byte, error) {
	csr := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:         commonName,
			Organization:       orgs,
			OrganizationalUnit: units,
		},
		SignatureAlgorithm: x509.ECDSAWithSHA384,
	}

	if len(sans) > 0 {
		s, err := BuildSubjectAltNameExtension(sans)
		if err != nil {
			return nil, err
		}
		csr.ExtraExtensions = []pkix.Extension{*s}
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

// CSRFromCertificate generates a new CSR from the given certificate
func CSRFromCertificate(cert *x509.Certificate) *x509.CertificateRequest {

	return &x509.CertificateRequest{
		DNSNames:           cert.DNSNames,
		EmailAddresses:     cert.EmailAddresses,
		Extensions:         cert.Extensions,
		ExtraExtensions:    cert.ExtraExtensions,
		IPAddresses:        cert.IPAddresses,
		PublicKey:          cert.PublicKey,
		Signature:          cert.Signature,
		SignatureAlgorithm: cert.SignatureAlgorithm,
		Subject:            cert.Subject,
		Version:            cert.Version,
	}
}

// SignCSR will sign the given CSR with the given signing cert
func SignCSR(
	csr *x509.CertificateRequest,
	signingCertificate *x509.Certificate,
	signingPrivateKey crypto.PrivateKey,

	beginning time.Time,
	expiration time.Time,
	keyUsage x509.KeyUsage,
	extKeyUsage []x509.ExtKeyUsage,
	signatureAlgorithm x509.SignatureAlgorithm,
	publicKeyAlgorithm x509.PublicKeyAlgorithm,

	isCA bool,
	policies []asn1.ObjectIdentifier,
) (*pem.Block, string, error) {

	sn, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, "", err
	}

	x509Cert := &x509.Certificate{
		SerialNumber: sn,
		Subject: pkix.Name{
			Country:            csr.Subject.Country,
			Locality:           csr.Subject.Locality,
			Province:           csr.Subject.Province,
			StreetAddress:      csr.Subject.StreetAddress,
			PostalCode:         csr.Subject.PostalCode,
			Organization:       csr.Subject.Organization,
			OrganizationalUnit: csr.Subject.OrganizationalUnit,
			CommonName:         csr.Subject.CommonName,
		},
		BasicConstraintsValid: true,
		DNSNames:              csr.DNSNames,
		ExtKeyUsage:           extKeyUsage,
		IPAddresses:           csr.IPAddresses,
		KeyUsage:              keyUsage,
		NotAfter:              expiration,
		NotBefore:             beginning,
		PolicyIdentifiers:     policies,
		IsCA:                  isCA,
	}

	if csr.ExtraExtensions != nil && len(csr.ExtraExtensions) > 0 {
		x509Cert.ExtraExtensions = append(x509Cert.ExtraExtensions, csr.ExtraExtensions...)
	}

	signerCert := x509Cert
	if signingCertificate != nil {
		if signingCertificate.KeyUsage&x509.KeyUsageCertSign == 0 {
			fmt.Println("Warn: The given parent certificate should be used to sign certificates as it doesn't have correct key usage")
		}
		signerCert = signingCertificate
	}

	x509Cert.AuthorityKeyId = signerCert.SubjectKeyId

	asn1Data, err := x509.CreateCertificate(rand.Reader, x509Cert, signerCert, csr.PublicKey, signingPrivateKey)
	if err != nil {
		return nil, "", err
	}

	certPEM := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: asn1Data,
	}

	return certPEM, sn.String(), nil
}
