package tglib

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/sirupsen/logrus"
)

// IssueCertiticate issues a new Certificate eventual signed using the signingCertificate
// and the given keyGen.
func IssueCertiticate(
	signingCertificate *x509.Certificate,
	signingPrivateKey crypto.PrivateKey,
	keyGen PrivateKeyGenerator,

	countries []string,
	provinces []string,
	localities []string,
	streetAddresses []string,
	postalCodes []string,
	organizations []string,
	organizationalUnits []string,
	commonName string,

	dnsNames []string,
	ipAddresses []net.IP,

	begining time.Time,
	expiration time.Time,
	keyUsage x509.KeyUsage,
	extKeyUsage []x509.ExtKeyUsage,
	signatureAlgorithm x509.SignatureAlgorithm,
	publicKeyAlgorithm x509.PublicKeyAlgorithm,
	isCA bool,

	policies []asn1.ObjectIdentifier,

) (*pem.Block, *pem.Block, error) {

	sn, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	sid, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}

	priv, err := keyGen()
	if err != nil {
		return nil, nil, err
	}

	var pub crypto.PublicKey
	switch k := priv.(type) {
	case *ecdsa.PrivateKey:
		pub = k.Public()
	case *rsa.PrivateKey:
		pub = k.Public()
	default:
		return nil, nil, fmt.Errorf("Unsupported private key")
	}

	x509Cert := &x509.Certificate{
		SerialNumber: sn,
		Subject: pkix.Name{
			Country:            countries,
			Locality:           localities,
			Province:           provinces,
			StreetAddress:      streetAddresses,
			PostalCode:         postalCodes,
			Organization:       organizations,
			OrganizationalUnit: organizationalUnits,
			CommonName:         commonName,
		},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		ExtKeyUsage:           extKeyUsage,
		IPAddresses:           ipAddresses,
		IsCA:                  isCA,
		KeyUsage:              keyUsage,
		NotAfter:              expiration,
		NotBefore:             begining,
		PublicKeyAlgorithm:    publicKeyAlgorithm,
		SubjectKeyId:          sid.Bytes(),
		PolicyIdentifiers:     policies,
	}

	if err != nil {
		return nil, nil, err
	}

	signerCert := x509Cert
	signerKey := priv
	if signingCertificate != nil {

		if signingCertificate.KeyUsage&x509.KeyUsageCertSign == 0 {
			logrus.Warn("The given parent certificate should be used to sign certificates as it doesn't have correct key usage")
		}

		signerCert = signingCertificate
		signerKey = signingPrivateKey
	}

	x509Cert.AuthorityKeyId = signerCert.SubjectKeyId

	asn1Data, err := x509.CreateCertificate(rand.Reader, x509Cert, signerCert, pub, signerKey)
	if err != nil {
		return nil, nil, err
	}

	privPEM, err := KeyToPEM(priv)
	if err != nil {
		return nil, nil, err
	}

	certPEM := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: asn1Data,
	}

	return certPEM, privPEM, nil
}

// Verify verifies the given certificate is signed by the given other certificate, and that
// the other certificate has the correct required key usage.
func Verify(signingCertPEMData []byte, certPEMData []byte, keyUsages []x509.ExtKeyUsage) error {

	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM([]byte(signingCertPEMData))
	if !ok {
		return fmt.Errorf("Unable to parse signing certificate")
	}

	block, rest := pem.Decode(certPEMData)
	if block == nil || len(rest) != 0 {
		return fmt.Errorf("Invalid child certificate")
	}

	x509Cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("Unable to parse child certificate: %s", err)
	}

	if keyUsages == nil {
		keyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	}

	if _, err := x509Cert.Verify(
		x509.VerifyOptions{
			Roots:     roots,
			KeyUsages: keyUsages,
		},
	); err != nil {
		return fmt.Errorf("Unable to verify child certificate: %s", err)
	}

	return nil
}

// SplitChain splits the given certificate data into the actual *x509.Certificate and a list of
// CA chain in a []*x509.Certificate
func SplitChain(certData []byte) (cert *x509.Certificate, caChain []*x509.Certificate, err error) {

	block, rest := pem.Decode(certData)

	for ; block != nil; block, rest = pem.Decode(rest) {

		if block.Type != "CERTIFICATE" {
			continue
		}

		crt, err := x509.ParseCertificate(block.Bytes)

		if err != nil {
			return nil, nil, err
		}

		if !crt.IsCA {
			cert = crt
			continue
		}

		if len(rest) != 0 {
			caChain = append(caChain, crt)
		}
	}

	return
}

// SplitChainPEM splits the given cert PEM []byte as the actual certificate
// and []byte as the rest of the chain.
func SplitChainPEM(certData []byte) ([]byte, []byte) {

	block, rest := pem.Decode(certData)

	return pem.EncodeToMemory(block), rest
}
