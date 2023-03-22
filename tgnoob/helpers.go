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

package tgnoob

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"go.aporeto.io/tg/tglib"
)

// GenerateCertificate is a wrapper on top of tglib.IssueCertificate.
// Generates a new certificate and store it in the out directory.
func GenerateCertificate(
	name string,
	commonName string,
	password string,
	isCA bool,
	authServer bool,
	authClient bool,
	authEmail bool,
	p12 bool,
	p12Pass string,
	out string,
	force bool,
	algo string,
	signingCertPath string,
	signingCertKeyPath string,
	signingCertKeyPass string,
	country []string,
	state []string,
	city []string,
	address []string,
	zipCode []string,
	org []string,
	orgUnit []string,
	dns []string,
	ips []string,
	duration time.Duration,
	policies []string,
) error {

	var err error

	if name == "" {
		return fmt.Errorf("you must specify a name via --name")
	}

	if commonName == "" {
		commonName = name
	}

	if p12 && p12Pass == "" {
		return fmt.Errorf("you must set --p12-pass when setting --p12")
	}

	certOut := certificatePath(out, name)
	keyOut := certificateKeyPath(out, name)

	if _, err = os.Stat(certOut); !os.IsNotExist(err) && !force {
		return fmt.Errorf("destination file %s already exists. Use --force to overwrite", certOut)
	}
	if _, err = os.Stat(keyOut); !os.IsNotExist(err) && !force {
		return fmt.Errorf("destination file %s already exists. Use --force to overwrite", keyOut)
	}

	options := []tglib.IssueOption{
		tglib.OptIssueValidity(time.Now(), time.Now().Add(duration)),
		tglib.OptIssueDNSSANs(dns...),
	}

	switch algo {
	case algoECDSA:
		options = append(options, tglib.OptIssueAlgorithmECDSA())
	case algoRSA:
		options = append(options, tglib.OptIssueAlgorithmRSA())
	}

	if isCA {
		options = append(options, tglib.OptIssueTypeCA())
	}

	if authClient {
		options = append(options, tglib.OptIssueTypeClientAuth())
	}
	if authServer {
		options = append(options, tglib.OptIssueTypeServerAuth())
	}
	if authEmail {
		options = append(options, tglib.OptIssueTypeEmailProtection())
	}

	if signingCertPath != "" || signingCertKeyPath != "" {

		if signingCertPath == "" || signingCertKeyPath == "" {
			return fmt.Errorf("you must pass both --signing-cert and --signing-cert-key if you pass one or the other")
		}

		signingCert, signingKey, err := tglib.ReadCertificatePEM(signingCertPath, signingCertKeyPath, signingCertKeyPass)
		if err != nil {
			return fmt.Errorf("unable to read signing certiticate information: %s", err.Error())
		}

		options = append(options, tglib.OptIssueSigner(signingCert, signingKey))
	}

	netips := make([]net.IP, len(ips))
	for i, ip := range ips {
		netips[i] = net.ParseIP(ip)
	}
	options = append(options, tglib.OptIssueIPSANs(netips...))

	asnIdentifiers, err := makePolicies(policies)
	if err != nil {
		return err
	}
	options = append(options, tglib.OptIssuePolicies(asnIdentifiers...))

	pub, priv, err := tglib.Issue(
		pkix.Name{
			Country:            country,
			Province:           state,
			Locality:           city,
			StreetAddress:      address,
			PostalCode:         zipCode,
			Organization:       org,
			OrganizationalUnit: orgUnit,
			CommonName:         commonName,
		},
		options...,
	)

	if err != nil {
		return fmt.Errorf("unable to generate certificate: %s", err.Error())
	}

	if password != "" {
		priv, err = tglib.EncryptPrivateKey(priv, password)
		if err != nil {
			return fmt.Errorf("unable to encrypt private key: %s", err.Error())
		}
	}

	if err = ioutil.WriteFile(
		keyOut,
		pem.EncodeToMemory(priv),
		0600,
	); err != nil {
		return fmt.Errorf("unable to write private key on file: %s", err.Error())
	}

	if err = ioutil.WriteFile(
		certOut,
		pem.EncodeToMemory(pub),
		0600,
	); err != nil {
		return fmt.Errorf("unable to write public key on file: %s", err.Error())
	}

	if p12 {
		if err = tglib.GeneratePKCS12FromFiles(
			path.Join(out, name+".p12"),
			certOut,
			keyOut,
			signingCertPath,
			p12Pass,
		); err != nil {
			return fmt.Errorf("unable to write p12 on file: %s", err.Error())
		}
	}

	return nil
}

// GenerateCSR generates a new CSR with the given parameters.
func GenerateCSR(
	name string,
	commonName string,
	cert string,
	certKey string,
	certKeyPass string,
	out string,
	force bool,
	algo string,
	country []string,
	state []string,
	city []string,
	address []string,
	zipCode []string,
	org []string,
	orgUnit []string,
	dns []string,
	ips []string,
	policies []string,
) error {

	if name == "" {
		return fmt.Errorf("you must specify a name via --name")
	}

	if cert != "" && certKey == "" {
		return fmt.Errorf("if you specify --cert you must specify --cert-key")
	}

	if cert == "" && certKey != "" {
		return fmt.Errorf("if you specify --cert-key you must specify --cert")
	}

	if cert != "" && (org != nil ||
		orgUnit != nil ||
		commonName != "" ||
		country != nil ||
		state != nil ||
		city != nil ||
		zipCode != nil ||
		address != nil ||
		dns != nil ||
		ips != nil) {
		return fmt.Errorf("if you pass cert, you cannot pass any other information")
	}

	if cert == "" && commonName == "" {
		commonName = name
	}

	csrOut := certificateRequestPath(out, name)
	keyOut := certificateKeyPath(out, name)

	if _, err := os.Stat(csrOut); !os.IsNotExist(err) && !force {
		return fmt.Errorf("destination file %s already exists. Use --force to overwrite", csrOut)
	}
	if _, err := os.Stat(keyOut); !os.IsNotExist(err) && !force {
		return fmt.Errorf("destination file %s already exists. Use --force to overwrite", keyOut)
	}

	var csrBytes []byte

	if cert == "" {
		var keygen tglib.PrivateKeyGenerator
		var signalg x509.SignatureAlgorithm
		var pkalg x509.PublicKeyAlgorithm

		switch algo {
		case algoECDSA:
			keygen = tglib.ECPrivateKeyGenerator
			signalg = x509.ECDSAWithSHA384
			pkalg = x509.ECDSA
		case algoRSA:
			keygen = tglib.RSAPrivateKeyGenerator
			signalg = x509.SHA384WithRSA
			pkalg = x509.RSA
		}

		privateKey, err := keygen()
		if err != nil {
			return fmt.Errorf("unable to generate private key: %s", err.Error())
		}
		keyBlock, err := tglib.KeyToPEM(privateKey)
		if err != nil {
			return fmt.Errorf("unable to convert private key pem block: %s", err.Error())
		}

		var netips []net.IP
		for _, ip := range ips {
			netips = append(netips, net.ParseIP(ip))
		}

		csr := &x509.CertificateRequest{
			Subject: pkix.Name{
				CommonName:         commonName,
				Organization:       org,
				OrganizationalUnit: orgUnit,
				Country:            country,
				Locality:           city,
				StreetAddress:      address,
				Province:           state,
				PostalCode:         zipCode,
			},
			SignatureAlgorithm: signalg,
			PublicKeyAlgorithm: pkalg,
			DNSNames:           dns,
			IPAddresses:        netips,
		}

		csrBytes, err = tglib.GenerateCSR(csr, privateKey)
		if err != nil {
			return fmt.Errorf("unable to create csr: %s", err.Error())
		}

		if err = ioutil.WriteFile(
			keyOut,
			pem.EncodeToMemory(keyBlock),
			0600,
		); err != nil {
			return fmt.Errorf("unable to write private key on file: %s", err.Error())
		}

	} else {

		certData, err := ioutil.ReadFile(cert)
		if err != nil {
			return fmt.Errorf("unable to load cert %s: %s", certKey, err.Error())
		}
		certKeyData, err := ioutil.ReadFile(certKey)
		if err != nil {
			return fmt.Errorf("unable to load cert key %s: %s", certKey, err.Error())
		}

		cert, key, err := tglib.ReadCertificate(certData, certKeyData, certKeyPass)
		if err != nil {
			return fmt.Errorf("unable to read signing cert: %s", err.Error())
		}

		csr := tglib.CSRFromCertificate(cert)

		csrBytes, err = tglib.GenerateCSR(csr, key)
		if err != nil {
			return fmt.Errorf("unable to create csr: %s", err.Error())
		}
	}

	if err := ioutil.WriteFile(
		csrOut,
		csrBytes,
		0600,
	); err != nil {
		return fmt.Errorf("unable to write public key on file: %s", err.Error())
	}

	return nil
}

// SignCSR signs a CSR.
func SignCSR(
	name string,
	isCa bool,
	authServer bool,
	authClient bool,
	authEmail bool,
	out string,
	force bool,
	algo string,
	signingCertPath string,
	signingCertKeyPath string,
	signingCertKeyPass string,
	csr []string,
	duration time.Duration,
	policies []string,

) error {

	if name == "" {
		return fmt.Errorf("you must specify a name via --name")
	}

	if signingCertPath == "" {
		return fmt.Errorf("you must specify a signing cert via --signing-cert")
	}

	if signingCertKeyPath == "" {
		return fmt.Errorf("you must specify a signing cert key via --signing-cert-key")
	}

	if len(csr) == 0 {
		return fmt.Errorf("you must specify at least one csr via --csr")
	}

	if !isCa && !authServer && !authClient && !authEmail {
		return fmt.Errorf("you must set at least one of --auth-server or --auth-client or --auth-email")
	}

	certOut := certificatePath(out, name)
	if _, err := os.Stat(certOut); !os.IsNotExist(err) && !force {
		return fmt.Errorf("destination file %s already exists. Use --force to overwrite", certOut)
	}

	signingCertData, err := ioutil.ReadFile(signingCertPath)
	if err != nil {
		return fmt.Errorf("unable to load signing cert %s", signingCertPath)
	}
	signingCertKeyData, err := ioutil.ReadFile(signingCertKeyPath)
	if err != nil {
		return fmt.Errorf("unable to load signing cert key %s", signingCertKeyPath)
	}

	signingCert, signingKey, err := tglib.ReadCertificate(signingCertData, signingCertKeyData, signingCertKeyPass)
	if err != nil {
		return fmt.Errorf("unable to read signing cert: %s", err.Error())
	}

	var signalg x509.SignatureAlgorithm
	var pkalg x509.PublicKeyAlgorithm
	switch algo {
	case algoECDSA:
		signalg = x509.ECDSAWithSHA384
		pkalg = x509.ECDSA
	case algoRSA:
		signalg = x509.SHA384WithRSA
		pkalg = x509.RSA
	}

	var keyUsage x509.KeyUsage
	var extKeyUsage []x509.ExtKeyUsage
	if isCa {
		keyUsage = x509.KeyUsageCRLSign | x509.KeyUsageCertSign
	} else {
		keyUsage = x509.KeyUsageDigitalSignature
	}
	if authClient {
		keyUsage |= x509.KeyUsageDigitalSignature
		extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageClientAuth)
	}
	if authServer {
		keyUsage |= x509.KeyUsageKeyEncipherment
		extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageServerAuth)
	}
	if authEmail {
		keyUsage |= x509.KeyUsageKeyEncipherment
		extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageEmailProtection)
	}

	asnIdentifiers, err := makePolicies(policies)
	if err != nil {
		return err
	}

	for _, path := range csr {

		csrData, err := ioutil.ReadFile(path)
		if err != nil {
			return fmt.Errorf("unable to load csr %s", path)
		}
		csrs, err := tglib.LoadCSRs(csrData)
		if err != nil {
			return fmt.Errorf("unable to parse csr %s", path)
		}

		for _, csr := range csrs {
			certBlock, _, err := tglib.SignCSR(
				csr,
				signingCert,
				signingKey,
				time.Now(),
				time.Now().Add(duration),
				keyUsage,
				extKeyUsage,
				signalg,
				pkalg,
				isCa,
				asnIdentifiers,
			)
			if err != nil {
				return fmt.Errorf("unable to sign certificate: %s", err.Error())
			}

			if err = ioutil.WriteFile(
				certOut,
				pem.EncodeToMemory(certBlock),
				0600,
			); err != nil {
				return fmt.Errorf("unable to write certificate on file: %s", err.Error())
			}
		}
	}

	return nil
}

// VerifyCert verifies a certificate.
func VerifyCert(
	certPath string,
	signerPath string,
	authServer bool,
	authClient bool,
	authEmail bool,
) error {

	if certPath == "" {
		return fmt.Errorf("you must specify at a cert via --cert")
	}

	if signerPath == "" {
		return fmt.Errorf("you must specify at a signer cert via --signer")
	}

	certData, err := ioutil.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("certificate doesn't exist")
	}

	signerData, err := ioutil.ReadFile(signerPath)
	if err != nil {
		return fmt.Errorf("signing certificate doesn't existexist")
	}

	var extKeyUsage []x509.ExtKeyUsage
	if authClient {
		extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageClientAuth)
	}
	if authServer {
		extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageServerAuth)
	}
	if authEmail {
		extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageEmailProtection)
	}

	return tglib.Verify(signerData, certData, extKeyUsage)
}

// DecryptPrivateKey decrypts a private key.
func DecryptPrivateKey(
	certKeyPath string,
	password string,
) ([]byte, error) {

	if certKeyPath == "" {
		return nil, fmt.Errorf("you must specify the key to decrypt via --key")
	}

	if password == "" {
		return nil, fmt.Errorf("you must specify the key password --pass")
	}

	keyData, err := ioutil.ReadFile(certKeyPath)
	if err != nil {
		return nil, fmt.Errorf("private key doesn't exist")
	}

	keyBlock, err := tglib.DecryptPrivateKeyPEM(keyData, password)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(keyBlock), nil
}

// EncryptPrivateKey encrypts a private key.
func EncryptPrivateKey(
	certKeyPath string,
	password string,
) ([]byte, error) {

	if certKeyPath == "" {
		return nil, fmt.Errorf("you must specify the key to decrypt via --key")
	}

	if password == "" {
		return nil, fmt.Errorf("you must specify the key password --pass")
	}

	keyData, err := ioutil.ReadFile(certKeyPath)
	if err != nil {
		return nil, fmt.Errorf("private key doesn't exist")
	}

	keyBlock, err := tglib.EncryptPrivateKeyPEM(keyData, password)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(keyBlock), nil
}

// certificatePath computes the path for a certificate.
func certificatePath(out string, name string) string {
	return path.Join(out, name+"-cert.pem")
}

// certificateKeyPath computes the path for a certificate key.
func certificateKeyPath(out string, name string) string {
	return path.Join(out, name+"-key.pem")
}

// certificateRequestPath computes the path for a certificate request.
func certificateRequestPath(out string, name string) string {
	return path.Join(out, name+"-csr.pem")
}

// makePolicies converts a string slice to a slice of object identifier.
func makePolicies(originalPolicies []string) ([]asn1.ObjectIdentifier, error) {

	policies := make([]asn1.ObjectIdentifier, len(originalPolicies))

	for i, kv := range originalPolicies {
		parts := strings.Split(kv, ".")

		oid := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1}
		for _, part := range parts {
			n, e := strconv.Atoi(part)
			if e != nil {
				return nil, fmt.Errorf("given policy OID %s is invalid", kv)
			}
			oid = append(oid, n)
		}

		policies[i] = oid
	}

	return policies, nil
}
