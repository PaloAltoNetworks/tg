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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
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

	fmt.Println("DEPRECATED: tglib.IssueCertiticate is deprecated in favor or tglib.Issue")

	options := []IssueOption{
		OptIssueKeyGenerator(keyGen),
		OptIssueDNSSANs(dnsNames...),
		OptIssueIPSANs(ipAddresses...),
		OptIssueValidity(beginning, expiration),
		OptIssueKeyUsage(keyUsage),
		OptIssueExtendedKeyUsages(extKeyUsage...),
		OptIssueSignatureAlgorithm(signatureAlgorithm),
		OptIssuePublicKeyAlgorithm(publicKeyAlgorithm),
	}

	if signingCertificate != nil {
		options = append(options, OptIssueSigner(signingCertificate, signingPrivateKey))
	}

	if isCA {
		options = append(options, OptIssueTypeCA())
	}

	return Issue(
		pkix.Name{
			Country:            countries,
			Locality:           localities,
			Province:           provinces,
			StreetAddress:      streetAddresses,
			PostalCode:         postalCodes,
			Organization:       organizations,
			OrganizationalUnit: organizationalUnits,
			CommonName:         commonName,
		},
		options...,
	)
}

// SignCSR will sign the given CSR with the given signing cert
func SignCSR(
	csr *x509.CertificateRequest,
	signingCertificate *x509.Certificate,
	signingPrivateKey crypto.PrivateKey,

	beginning time.Time,
	expiration time.Time,
	keyUsage x509.KeyUsage,
	extKeyUsage []x509.ExtKeyUsage,
	signatureAlgorithm x509.SignatureAlgorithm,
	publicKeyAlgorithm x509.PublicKeyAlgorithm,

	isCA bool,
	policies []asn1.ObjectIdentifier,
) (*pem.Block, string, error) {

	fmt.Println("DEPRECATED: tglib.SignCSR is deprecated in favor or tglib.Sign")

	options := []IssueOption{
		OptIssueSigner(signingCertificate, signingPrivateKey),
		OptIssueValidity(beginning, expiration),
		OptIssueKeyUsage(keyUsage),
		OptIssueExtendedKeyUsages(extKeyUsage...),
		OptIssueSignatureAlgorithm(signatureAlgorithm),
		OptIssuePublicKeyAlgorithm(publicKeyAlgorithm),
	}

	if isCA {
		options = append(options, OptIssueTypeCA())
	}

	return Sign(csr, signingCertificate, signingPrivateKey, options...)
}
