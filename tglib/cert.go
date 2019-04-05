package tglib

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

// Issue issues a new x509 certificate
func Issue(subject pkix.Name, options ...IssueOption) (*pem.Block, *pem.Block, error) {

	cfg := newIssueCfg()
	for _, option := range options {
		option(&cfg)
	}

	priv, err := cfg.keyGen()
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
		return nil, nil, fmt.Errorf("unsupported private key")
	}

	csr := &x509.CertificateRequest{
		Subject:            subject,
		DNSNames:           cfg.dnsNames,
		IPAddresses:        cfg.ipAddresses,
		PublicKeyAlgorithm: cfg.publicKeyAlgorithm,
		PublicKey:          pub,
	}

	signerKey := cfg.signingPrivateKey
	if signerKey == nil {
		signerKey = priv
	}

	certPEM, _, err := Sign(csr, cfg.signingCertificate, signerKey, options...)
	if err != nil {
		return nil, nil, err
	}

	privPEM, err := KeyToPEM(priv)
	if err != nil {
		return nil, nil, err
	}

	return certPEM, privPEM, nil
}

// Verify verifies the given certificate is signed by the given other certificate, and that
// the other certificate has the correct required key usage.
func Verify(signingCertPEMData []byte, certPEMData []byte, keyUsages []x509.ExtKeyUsage) error {

	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM(signingCertPEMData)
	if !ok {
		return fmt.Errorf("unable to parse signing certificate")
	}

	block, rest := pem.Decode(certPEMData)
	if block == nil || len(rest) != 0 {
		return fmt.Errorf("invalid child certificate")
	}

	x509Cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("unable to parse child certificate: %s", err)
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
		return fmt.Errorf("unable to verify child certificate: %s", err)
	}

	return nil
}

// ParseCertificate parse the given PEM bytes and returns the fist *x509.Certificate.
func ParseCertificate(certPemBytes []byte) (*x509.Certificate, error) {

	x509certs, err := ParseCertificates(certPemBytes)
	if err != nil {
		return nil, err
	}

	return x509certs[0], nil
}

// ParseCertificates parse the given PEM bytes and returns a []*x509.Certificate.
func ParseCertificates(certPemBytes []byte) ([]*x509.Certificate, error) {

	var x509Certs []*x509.Certificate
	var block *pem.Block
	rest := certPemBytes

	for {
		block, rest = pem.Decode(rest)
		if block == nil && len(rest) == 0 {
			break
		}

		if block == nil {
			return nil, fmt.Errorf("unable to parse certificate data: '%s'", string(rest))
		}

		x509Cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("unable to parse certificate: %s", err)
		}

		x509Certs = append(x509Certs, x509Cert)
	}

	if len(x509Certs) == 0 {
		return nil, fmt.Errorf("no certificate found in given data")
	}

	return x509Certs, nil
}

// ParseCertificatePEM reads the PEM certificate at the given path
// and returns the first *x509.Certificate found
func ParseCertificatePEM(path string) (*x509.Certificate, error) {

	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("unable to read pem file: %s", err)
	}

	return ParseCertificate(data)
}

// ParseCertificatePEMs reads the PEM certificate at the given path
// and returns the a []*x509.Certificate.
func ParseCertificatePEMs(path string) ([]*x509.Certificate, error) {

	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("unable to read pem file: %s", err)
	}

	return ParseCertificates(data)
}

// ReadCertificate returns a the first *x509.Certificate from the PEM bytes pf a cert and a key and decrypts it with the given password if needed.
func ReadCertificate(certPemBytes []byte, keyPemBytes []byte, password string) (*x509.Certificate, crypto.PrivateKey, error) {

	x509certs, key, err := ReadCertificates(certPemBytes, keyPemBytes, password)
	if err != nil {
		return nil, nil, err
	}

	return x509certs[0], key, nil
}

// ReadCertificates returns a []*x509.Certificate from the PEM bytes pf a cert and a key and decrypts it with the given password if needed.
func ReadCertificates(certPemBytes []byte, keyPemBytes []byte, password string) ([]*x509.Certificate, crypto.PrivateKey, error) {

	keyBlock, rest := pem.Decode(keyPemBytes)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("could not read key data from bytes: '%s'", string(keyPemBytes))
	}
	if len(rest) > 0 {
		return nil, nil, fmt.Errorf("multiple private keys found: this is not supported")
	}

	if x509.IsEncryptedPEMBlock(keyBlock) {
		var err error
		keyBlock, err = DecryptPrivateKey(keyBlock, password)
		if err != nil {
			return nil, nil, err
		}
	}

	cert, err := tls.X509KeyPair(certPemBytes, pem.EncodeToMemory(keyBlock))
	if err != nil {
		return nil, nil, err
	}

	x509certs := make([]*x509.Certificate, len(cert.Certificate))
	for i, cert := range cert.Certificate {
		x509cert, err := x509.ParseCertificate(cert)
		if err != nil {
			return nil, nil, err
		}
		x509certs[i] = x509cert
	}

	var key crypto.PrivateKey
	switch keyBlock.Type {
	case ecPrivateKeyHeader:
		key, err = x509.ParseECPrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to unmarshal EC private key: %s", err)
		}
	case rsaPrivateKeyHeader:
		key, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to unmarshal RSA private key: %s", err)
		}
	case privateKeyHeader:
		key, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to unmarshal private key: %s", err)
		}
	default:
		return nil, nil, fmt.Errorf("unsuported private key type: %s", keyBlock.Type)
	}

	return x509certs, key, nil
}

// ReadCertificatePEM returns a the first *x509.Certificate from the path of a cert, a key in PEM
// and decrypts it with the given password if needed.
func ReadCertificatePEM(certPath, keyPath, password string) (*x509.Certificate, crypto.PrivateKey, error) {

	x509certs, key, err := ReadCertificatePEMs(certPath, keyPath, password)
	if err != nil {
		return nil, nil, err
	}

	return x509certs[0], key, nil
}

// ReadCertificatePEMs returns a []*x509.Certificate from the path of a cert, a key in PEM
// and decrypts it with the given password if needed.
func ReadCertificatePEMs(certPath, keyPath, password string) ([]*x509.Certificate, crypto.PrivateKey, error) {

	certPemBytes, err := ioutil.ReadFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to read cert pem file: %s", err)
	}

	keyPemBytes, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to read key pem file: %s", err)
	}

	return ReadCertificates(certPemBytes, keyPemBytes, password)
}

// ToTLSCertificate converts the given cert and private key to a tls.Certificate. The private key must not be encrypted.
func ToTLSCertificate(cert *x509.Certificate, key crypto.PrivateKey) (tls.Certificate, error) {

	keyBlock, err := KeyToPEM(key)
	if err != nil {
		return tls.Certificate{}, err
	}

	certBlock := &pem.Block{
		Bytes: cert.Raw,
		Type:  "CERTIFICATE",
	}

	return tls.X509KeyPair(pem.EncodeToMemory(certBlock), pem.EncodeToMemory(keyBlock))
}

// ToTLSCertificates converts the given certs and private key to a tls.Certificate. The private key must not be encrypted.
func ToTLSCertificates(certs []*x509.Certificate, key crypto.PrivateKey) (tls.Certificate, error) {

	keyBlock, err := KeyToPEM(key)
	if err != nil {
		return tls.Certificate{}, err
	}

	var certBlocks []byte // nolint
	for _, cert := range certs {
		certBlocks = append(certBlocks, pem.EncodeToMemory(&pem.Block{Bytes: cert.Raw, Type: "CERTIFICATE"})...)
		certBlocks = append(certBlocks, '\n')
	}

	return tls.X509KeyPair(certBlocks, pem.EncodeToMemory(keyBlock))
}

// BuildCertificatesMaps returns to maps to get what certificate to use for which DNS or IPs.
// This can be used in a custom tls.Config.GetCertificate function.
func BuildCertificatesMaps(certs []tls.Certificate) (map[string]tls.Certificate, map[string]tls.Certificate, error) {

	certsNamesMap := map[string]tls.Certificate{}
	certsIPsMap := map[string]tls.Certificate{}

	for _, item := range certs {
		for _, subItem := range item.Certificate {
			x509Cert, err := x509.ParseCertificate(subItem)
			if err != nil {
				return nil, nil, err
			}
			certsNamesMap[x509Cert.Subject.CommonName] = item
			for _, dns := range x509Cert.DNSNames {
				certsNamesMap[dns] = item
			}
			for _, ip := range x509Cert.IPAddresses {
				certsIPsMap[ip.String()] = item
			}
		}
	}

	return certsNamesMap, certsIPsMap, nil
}

// CertToPEM converts the given *x509.Certificate to *pem.Block .
func CertToPEM(cert *x509.Certificate) (*pem.Block, error) {

	if cert == nil {
		return nil, fmt.Errorf("nil certificate provided")
	}

	if len(cert.Raw) == 0 {
		return nil, fmt.Errorf("certificate doesn't contain any data")
	}

	return &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}, nil
}
