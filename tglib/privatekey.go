// Copyright 2019 Aporeto Inc.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
		t = ecPrivateKeyHeader

	case *rsa.PrivateKey:
		b = x509.MarshalPKCS1PrivateKey(k)
		t = rsaPrivateKeyHeader

	default:
		return nil, fmt.Errorf("given key is not compatible: %T", k)
	}

	return &pem.Block{
		Type:  t,
		Bytes: b,
	}, nil
}

// PEMToKey loads a decrypted pem block and returns a crypto.PrivateKey
func PEMToKey(keyBlock *pem.Block) (crypto.PrivateKey, error) {

	switch keyBlock.Type {
	case ecPrivateKeyHeader:
		return x509.ParseECPrivateKey(keyBlock.Bytes)
	case rsaPrivateKeyHeader:
		return x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	case privateKeyHeader:
		return x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	default:
		return nil, fmt.Errorf("unsupported type: %s", keyBlock.Headers)
	}
}

// DecryptPrivateKey decrypts the given private key
func DecryptPrivateKey(keyBlock *pem.Block, password string) (*pem.Block, error) {

	if !x509.IsEncryptedPEMBlock(keyBlock) {
		return keyBlock, nil
	}

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

// EncryptPrivateKey encrypts the given private key
func EncryptPrivateKey(keyBlock *pem.Block, password string) (*pem.Block, error) {

	return x509.EncryptPEMBlock(rand.Reader, keyBlock.Type, keyBlock.Bytes, []byte(password), x509.PEMCipherAES256)
}

// EncryptPrivateKeyPEM encrypts the given private key PEM bytes
func EncryptPrivateKeyPEM(key []byte, password string) (*pem.Block, error) {

	keyBlock, _ := pem.Decode(key)

	return EncryptPrivateKey(keyBlock, password)
}
