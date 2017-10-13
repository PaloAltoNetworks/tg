package tglib

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net"
	"time"
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

	beginning time.Time,
	expiration time.Time,
	keyUsage x509.KeyUsage,
	extKeyUsage []x509.ExtKeyUsage,
	signatureAlgorithm x509.SignatureAlgorithm,
	publicKeyAlgorithm x509.PublicKeyAlgorithm,
	isCA bool,

	policies []asn1.ObjectIdentifier,

) (*pem.Block, *pem.Block, error) {

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

	csr := &x509.CertificateRequest{
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
		DNSNames:           dnsNames,
		IPAddresses:        ipAddresses,
		PublicKeyAlgorithm: publicKeyAlgorithm,
		PublicKey:          pub,
	}

	signerKey := signingPrivateKey
	if signingPrivateKey == nil {
		signerKey = priv
	}

	certPEM, _, err := SignCSR(csr, signingCertificate, signerKey, beginning, expiration, keyUsage, extKeyUsage, signatureAlgorithm, publicKeyAlgorithm, isCA, policies)
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

// BuildCertificatesMaps returns to maps to get what certificate to use for which DNS or IPs.
// This can be used in a custom tls.Config.GetCertificate function.
func BuildCertificatesMaps(certs []tls.Certificate) (map[string]*tls.Certificate, map[string]*tls.Certificate, error) {

	certsNamesMap := map[string]*tls.Certificate{}
	certsIPsMap := map[string]*tls.Certificate{}

	for _, item := range certs {
		for _, subItem := range item.Certificate {
			x509Cert, err := x509.ParseCertificate(subItem)
			if err != nil {
				return nil, nil, err
			}
			for _, dns := range x509Cert.DNSNames {
				certsNamesMap[dns] = &item
			}
			for _, ip := range x509Cert.IPAddresses {
				certsIPsMap[ip.String()] = &item
			}
		}
	}

	return certsNamesMap, certsIPsMap, nil
}
