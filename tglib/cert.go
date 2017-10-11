package tglib

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

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
