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
