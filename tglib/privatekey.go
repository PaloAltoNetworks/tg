package tglib

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
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
