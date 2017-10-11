package tglib

import (
	"crypto/x509"
	"encoding/pem"
)

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
