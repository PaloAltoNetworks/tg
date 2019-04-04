package tglib

import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"net"
	"time"
)

type issueCfg struct {
	signingCertificate *x509.Certificate
	signingPrivateKey  crypto.PrivateKey
	keyGen             PrivateKeyGenerator
	signatureAlgorithm x509.SignatureAlgorithm
	publicKeyAlgorithm x509.PublicKeyAlgorithm
	policies           []asn1.ObjectIdentifier
	dnsNames           []string
	ipAddresses        []net.IP
	beginning          time.Time
	expiration         time.Time
	keyUsage           x509.KeyUsage
	extKeyUsage        []x509.ExtKeyUsage
	isCA               bool
}

func newIssueCfg() issueCfg {
	return issueCfg{
		keyGen:             ECPrivateKeyGenerator,
		signatureAlgorithm: x509.ECDSAWithSHA384,
		publicKeyAlgorithm: x509.ECDSA,
		beginning:          time.Now().Add(-1 * time.Hour),
		expiration:         time.Now().Add(12 * 31 * 24 * time.Hour),
	}
}

// IssueOption represents an issueing option.
type IssueOption func(*issueCfg)

// OptIssueSigner sets the signer for the certificate to be issued.
// By default, Issue will issue a self-signed certificate.
func OptIssueSigner(cert *x509.Certificate, key crypto.PrivateKey) IssueOption {
	return func(cfg *issueCfg) {
		cfg.signingCertificate = cert
		cfg.signingPrivateKey = key
	}
}

// OptIssueSignerPEMBytes sets the signer for the certificate to be issued in the PEM format.
// By default, Issue will issue a self-signed certificate.
func OptIssueSignerPEMBytes(cert []byte, key []byte, password string) IssueOption {
	return func(cfg *issueCfg) {
		cert, key, err := ReadCertificate(cert, key, password)
		if err != nil {
			panic(err)
		}
		OptIssueSigner(cert, key)(cfg)
	}
}

// OptIssueSignerPEMBlock sets the signer for the certificate to be issued in the PEM format.
// By default, Issue will issue a self-signed certificate.
func OptIssueSignerPEMBlock(cert *pem.Block, key *pem.Block, password string) IssueOption {
	return func(cfg *issueCfg) {
		OptIssueSignerPEMBytes(pem.EncodeToMemory(cert), pem.EncodeToMemory(key), password)(cfg)
	}
}

// OptIssueValidity sets the validity of the certificate to be issued.
// By default, the certificate is valid from the time it has been created
// for 1 year.
func OptIssueValidity(notBefore time.Time, notAfter time.Time) IssueOption {
	return func(cfg *issueCfg) {
		cfg.beginning = notBefore
		cfg.expiration = notAfter
	}
}

// OptIssueTypeCA sets the makes the certificate to be issued to be
// a Certificate Authority.
// It automatically applies the correct key usage, unless already
// set by another option.
func OptIssueTypeCA() IssueOption {
	return func(cfg *issueCfg) {
		cfg.isCA = true
		cfg.keyUsage |= x509.KeyUsageCRLSign | x509.KeyUsageCertSign
	}
}

// OptIssueTypeServerAuth configures the certificate to be issued to be a server certificate.
// This option can be combined with other OptIssueType*.
func OptIssueTypeServerAuth() IssueOption {
	return func(cfg *issueCfg) {
		OptIssueExtendedKeyUsages(x509.ExtKeyUsageServerAuth)(cfg)
		cfg.keyUsage |= x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	}
}

// OptIssueTypeClientAuth configures the certificate to be issued to be a client certificate.
// This option can be combined with other OptIssueType*.
func OptIssueTypeClientAuth() IssueOption {
	return func(cfg *issueCfg) {
		OptIssueExtendedKeyUsages(x509.ExtKeyUsageClientAuth)(cfg)
		cfg.keyUsage |= x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	}
}

// OptIssueTypeEmailProtection configures the certificate to be issued to be a email protection certificate.
// This option can be combined with other OptIssueType*.
func OptIssueTypeEmailProtection() IssueOption {
	return func(cfg *issueCfg) {
		OptIssueExtendedKeyUsages(x509.ExtKeyUsageEmailProtection)(cfg)
		cfg.keyUsage |= x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	}
}

// OptIssueTypeCodeSigning configures the certificate to be issued to be a code signing certificate.
// This option can be combined with other OptIssueType*.
func OptIssueTypeCodeSigning() IssueOption {
	return func(cfg *issueCfg) {
		OptIssueExtendedKeyUsages(x509.ExtKeyUsageCodeSigning)(cfg)
		cfg.keyUsage |= x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	}
}

// OptIssueIPSANs sets the IP SANs for the certificate to be issued.
func OptIssueIPSANs(ips ...net.IP) IssueOption {
	return func(cfg *issueCfg) {
		cfg.ipAddresses = ips
	}
}

// OptIssueDNSSANs the IP SANs for the certificate to be issued.
func OptIssueDNSSANs(dns ...string) IssueOption {
	return func(cfg *issueCfg) {
		cfg.dnsNames = dns
	}
}

// OptIssueAlgorithmECDSA configures the certificate to use ECDSA with SHA384 P256 curve.
func OptIssueAlgorithmECDSA() IssueOption {
	return func(cfg *issueCfg) {
		OptIssueKeyGenerator(ECPrivateKeyGenerator)(cfg)
		OptIssueSignatureAlgorithm(x509.ECDSAWithSHA384)(cfg)
		OptIssuePublicKeyAlgorithm(x509.ECDSA)(cfg)
	}
}

// OptIssueAlgorithmRSA configures the certificate to use 2048-bits RSA with SHA384 signature
func OptIssueAlgorithmRSA() IssueOption {
	return func(cfg *issueCfg) {
		OptIssueKeyGenerator(RSAPrivateKeyGenerator)(cfg)
		OptIssueSignatureAlgorithm(x509.SHA384WithRSA)(cfg)
		OptIssuePublicKeyAlgorithm(x509.RSA)(cfg)
	}
}

// OptIssueExtendedKeyUsages manually sets the extended key usage for the certificate.
// It will erase any previous extended usage set by options OptIssueType*.
//
// It is not recommended to use this option unless you know exactly what you are doing.
func OptIssueExtendedKeyUsages(usages ...x509.ExtKeyUsage) IssueOption {
	return func(cfg *issueCfg) {
		cfg.extKeyUsage = usages
	}
}

// OptIssueKeyUsage sets the key usage for the certificate.
// It will erase any previous usage set by options OptIssueType*.
//
// It is not recommended to use this option unless you know exactly what you are doing.
func OptIssueKeyUsage(usage x509.KeyUsage) IssueOption {
	return func(cfg *issueCfg) {
		cfg.keyUsage = usage
	}
}

// OptIssueKeyGenerator sets the private key generator to use.
// It will erase any previous extended usage set by options OptIssueAlgorithm*.
//
// It is not recommended to use this option unless you know exactly what you are doing.
func OptIssueKeyGenerator(keyGen PrivateKeyGenerator) IssueOption {
	return func(cfg *issueCfg) {
		cfg.keyGen = keyGen
	}
}

// OptIssuePublicKeyAlgorithm sets the signature algorithm for the public key.
// It will erase any previous extended usage set by options OptIssueAlgorithm*.
//
// It is not recommended to use this option unless you know exactly what you are doing.
func OptIssuePublicKeyAlgorithm(alg x509.PublicKeyAlgorithm) IssueOption {
	return func(cfg *issueCfg) {
		cfg.publicKeyAlgorithm = alg
	}
}

// OptIssueSignatureAlgorithm sets the signature algorithm for the certificate.
// By default, it uses x509.ECDSA.
//
// It is not recommended to use this option unless you know exactly what you are doing.
func OptIssueSignatureAlgorithm(alg x509.SignatureAlgorithm) IssueOption {
	return func(cfg *issueCfg) {
		cfg.signatureAlgorithm = alg
	}
}

// OptIssuePolicies sets additional policies OIDs.
func OptIssuePolicies(policies ...asn1.ObjectIdentifier) IssueOption {
	return func(cfg *issueCfg) {
		cfg.policies = policies
	}
}
