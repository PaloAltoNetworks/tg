package tglib

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"os/exec"
	"time"

	"github.com/sirupsen/logrus"
)

// PrivateKeyGenerator is the type of function that can generate a crypto.PrivateKey.
type PrivateKeyGenerator func() (crypto.PrivateKey, error)

// ECPrivateKeyGenerator generates a ECDSA private key.
func ECPrivateKeyGenerator() (crypto.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// RSAPrivateKeyGenerator generates a RSA private key.
func RSAPrivateKeyGenerator() (crypto.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

// KeyToPEM converts the given crypto.PrivateKey to *pem.Block .
func KeyToPEM(key interface{}) (*pem.Block, error) {

	var err error
	var b []byte
	var t string

	switch k := key.(type) {

	case *ecdsa.PrivateKey:
		if b, err = x509.MarshalECPrivateKey(k); err != nil {
			return nil, err
		}
		t = "EC PRIVATE KEY"

	case *rsa.PrivateKey:
		b = x509.MarshalPKCS1PrivateKey(k)
		t = "RSA PRIVATE KEY"

	default:
		return nil, fmt.Errorf("Given key is not compatible")
	}

	return &pem.Block{
		Type:  t,
		Bytes: b,
	}, nil
}

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

// ReadCertificate returns a new *x509.Certificate from the PEM bytes pf a cert and a key and decrypts it with the given password if needed.
func ReadCertificate(certPemBytes []byte, keyPemBytes []byte, password string) (*x509.Certificate, crypto.PrivateKey, error) {

	certBlock, rest := pem.Decode(certPemBytes)
	for {
		if len(rest) == 0 {
			break
		}
		certBlock, rest = pem.Decode(rest)
	}

	if certBlock == nil {
		return nil, nil, fmt.Errorf("Could not read cert data")
	}

	keyBlock, rest := pem.Decode(keyPemBytes)
	if len(rest) > 0 {
		return nil, nil, fmt.Errorf("Multiple private keys found. This is not supported")
	}
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("Could not read key data")
	}

	if x509.IsEncryptedPEMBlock(keyBlock) {
		var err error
		keyBlock, err = DecryptPrivateKey(keyBlock, password)
		if err != nil {
			return nil, nil, err
		}
	}

	cert, err := tls.X509KeyPair(pem.EncodeToMemory(certBlock), pem.EncodeToMemory(keyBlock))
	if err != nil {
		return nil, nil, err
	}

	x509cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, nil, err
	}

	var key crypto.PrivateKey
	switch keyBlock.Type {
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to unmarshal the private key: %s", err)
		}
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to unmarshal the private key: %s", err)
		}
	default:
		return nil, nil, fmt.Errorf("Unsuported private key type: %s", keyBlock.Type)
	}

	return x509cert, key, nil
}

// ReadCertificatePEM returns a new *x509.Certificate from the path of a cert, a key in PEM
// and decrypts it with the given password if needed.
func ReadCertificatePEM(certPath, keyPath, password string) (*x509.Certificate, crypto.PrivateKey, error) {

	certPemBytes, err := ioutil.ReadFile(certPath)
	if err != nil {
		return nil, nil, err
	}

	keyPemBytes, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, nil, err
	}

	return ReadCertificate(certPemBytes, keyPemBytes, password)
}

// DecryptPrivateKey decrypts the given private key
func DecryptPrivateKey(keyBlock *pem.Block, password string) (*pem.Block, error) {

	var data []byte
	data, err := x509.DecryptPEMBlock(keyBlock, []byte(password))
	if err != nil {
		return nil, err
	}

	return &pem.Block{
		Type:  keyBlock.Type,
		Bytes: data,
	}, nil
}

// DecryptPrivateKeyPEM decrypts the given private key PEM bytes
func DecryptPrivateKeyPEM(key []byte, password string) (*pem.Block, error) {

	keyBlock, _ := pem.Decode(key)

	return DecryptPrivateKey(keyBlock, password)
}

// GeneratePKCS12 generates a full PKCS certificate based on the input keys.
func GeneratePKCS12(out, certPath, keyPath, caPath, passphrase string) error {

	args := []string{
		"pkcs12",
		"-export",
		"-out", out,
		"-inkey", keyPath,
		"-in", certPath,
		"-certfile", caPath,
		"-passout", "pass:" + passphrase,
	}

	return exec.Command("openssl", args...).Run()
}

// ReadCertificatePEMFromData returns a certificate object out of a PEM encoded byte array
func ReadCertificatePEMFromData(certByte []byte) (*x509.Certificate, error) {
	certBlock, rest := pem.Decode(certByte)
	for {
		if len(rest) == 0 {
			break
		}
		certBlock, rest = pem.Decode(rest)
	}
	if certBlock == nil {
		return nil, fmt.Errorf("Could not read cert data")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %s", err.Error())
	}

	return cert, nil
}

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
