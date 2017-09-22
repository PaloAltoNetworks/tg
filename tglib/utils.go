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
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"time"
)

// PrivateKeyGenerator is the type of function that can generate a crypto.PrivateKey.
type PrivateKeyGenerator func() (crypto.PrivateKey, error)

// ECPrivateKeyGenerator generates a ECDSA private key.
func ECPrivateKeyGenerator() (crypto.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// RSArivateKeyGenerator generates a RSA private key.
func RSArivateKeyGenerator() (crypto.PrivateKey, error) {
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
		return nil, fmt.Errorf("Given key is not ECDSA")
	}

	return &pem.Block{
		Type:  t,
		Bytes: b,
	}, nil
}

// IssueCertiticate issues a new Certificate eventual signed using the signingCerticate
// and the given keyGen.
func IssueCertiticate(
	signingCerticate *x509.Certificate,
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

) (*pem.Block, *pem.Block, error) {

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, err
	}

	x509CA := &x509.Certificate{
		SerialNumber: serialNumber,
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
		SignatureAlgorithm:    signatureAlgorithm,
		PublicKeyAlgorithm:    publicKeyAlgorithm,
		NotBefore:             begining,
		NotAfter:              expiration,
		BasicConstraintsValid: true,
		IsCA:        isCA,
		KeyUsage:    keyUsage,
		ExtKeyUsage: extKeyUsage,
		DNSNames:    dnsNames,
		IPAddresses: ipAddresses,
	}

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

	signer := x509CA
	if signingCerticate != nil {
		signer = signingCerticate
	}

	asn1Data, err := x509.CreateCertificate(rand.Reader, x509CA, signer, pub, priv)
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

	return privPEM, certPEM, nil
}

// ReadCertificatePEM returns a new *x509.Certificate from the path of a cert, a key in PEM
// and decrypts it with the given password if needed.
func ReadCertificatePEM(certPath, keyPath, password string) (*x509.Certificate, error) {

	certPemBytes, err := ioutil.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	certBlock, rest := pem.Decode(certPemBytes)
	for {
		if len(rest) == 0 {
			break
		}
		certBlock, rest = pem.Decode(rest)
	}

	if certBlock == nil {
		return nil, fmt.Errorf("Could not read cert data")
	}

	keyPemBytes, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	keyBlock, rest := pem.Decode(keyPemBytes)
	if len(rest) > 0 {
		return nil, fmt.Errorf("Multiple private keys found. This is not supported")
	}
	if keyBlock == nil {
		return nil, fmt.Errorf("Could not read key data")
	}

	if x509.IsEncryptedPEMBlock(keyBlock) {

		var data []byte
		data, err = x509.DecryptPEMBlock(keyBlock, []byte(password))
		if err != nil {
			return nil, err
		}

		keyBlock = &pem.Block{
			Type:  keyBlock.Type,
			Bytes: data,
		}
	}

	cert, err := tls.X509KeyPair(pem.EncodeToMemory(certBlock), pem.EncodeToMemory(keyBlock))
	if err != nil {
		return nil, err
	}

	x509cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}

	return x509cert, nil
}
