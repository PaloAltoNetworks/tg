package tglib

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	//revive:disable-next-line:dot-imports
	. "github.com/smartystreets/goconvey/convey"
)

const (
	signerCert = `-----BEGIN CERTIFICATE-----
MIIBPjCB5aADAgECAhBA+zJ4hsJYtl9bMZeLC/xpMAoGCCqGSM49BAMCMA8xDTAL
BgNVBAMTBHRlc3QwHhcNMjAwNTEzMTg0MTE4WhcNMzAwMzIyMTg0MTE4WjAPMQ0w
CwYDVQQDEwR0ZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEuw6rQz4eUVo9
X+MnoYC2LB2acHZY8P3DLMp8e9RYJ/dEmEmEkphijZ7+vfcb7DOUipFzcwD75nkb
LjANhxzg6aMjMCEwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wCgYI
KoZIzj0EAwIDSAAwRQIgJlNHz2SJ9Rwksz+Ody7pC00w9cLkI1bvrD+Yl6T3QyQC
IQDk7ayssVepBeko0+J9snQ3D6NvkAkZ0oBAYyUC7gsWCA==
-----END CERTIFICATE-----`

	signerKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEINH9EcK9PvZj5FNvKgrAWUMXKa+fQmCqVDvco88XHwTKoAoGCCqGSM49
AwEHoUQDQgAEuw6rQz4eUVo9X+MnoYC2LB2acHZY8P3DLMp8e9RYJ/dEmEmEkphi
jZ7+vfcb7DOUipFzcwD75nkbLjANhxzg6Q==
-----END EC PRIVATE KEY-----
`
)

func TestOptions(t *testing.T) {

	Convey("newIssueCfg should work", t, func() {
		cfg := newIssueCfg()
		So(cfg.keyGen, ShouldEqual, ECPrivateKeyGenerator)
		So(cfg.signatureAlgorithm, ShouldEqual, x509.ECDSAWithSHA384)
		So(cfg.publicKeyAlgorithm, ShouldEqual, x509.ECDSA)
		So(cfg.beginning.Unix(), ShouldBeLessThan, time.Now().Unix())
		So(cfg.expiration.Unix(), ShouldBeGreaterThan, time.Now().Unix())
	})

	Convey("OptIssueSigner should work", t, func() {
		cert, key, err := ReadCertificate([]byte(signerCert), []byte(signerKey), "")
		if err != nil {
			panic(err)
		}

		cfg := newIssueCfg()
		OptIssueSigner(cert, key)(&cfg)
		So(cfg.signingCertificate.Subject.CommonName, ShouldEqual, "test")
		So(cfg.signingPrivateKey, ShouldNotBeNil)
	})

	Convey("OptIssueSignerPEMBytes should work", t, func() {
		cfg := newIssueCfg()
		OptIssueSignerPEMBytes([]byte(signerCert), []byte(signerKey), "")(&cfg)
		So(cfg.signingCertificate.Subject.CommonName, ShouldEqual, "test")
		So(cfg.signingPrivateKey, ShouldNotBeNil)
	})

	Convey("OptIssueSignerPEMBytes with invalid data should panic", t, func() {
		cfg := newIssueCfg()
		So(func() { OptIssueSignerPEMBytes(nil, nil, "")(&cfg) }, ShouldPanic)
	})

	Convey("OptIssueSignerPEMBlock should work", t, func() {
		cfg := newIssueCfg()
		cert, _ := pem.Decode([]byte(signerCert))
		key, _ := pem.Decode([]byte(signerKey))
		OptIssueSignerPEMBlock(cert, key, "")(&cfg)
		So(cfg.signingCertificate.Subject.CommonName, ShouldEqual, "test")
		So(cfg.signingPrivateKey, ShouldNotBeNil)
	})

	Convey("OptIssueValidity should work", t, func() {
		cfg := newIssueCfg()
		t1 := time.Now().Add(-999 * time.Hour)
		t2 := time.Now().Add(999 * time.Hour)
		OptIssueValidity(t1, t2)(&cfg)
		So(cfg.beginning, ShouldResemble, t1)
		So(cfg.expiration, ShouldResemble, t2)
	})

	Convey("OptIssueTypeCA should work", t, func() {
		cfg := newIssueCfg()
		OptIssueTypeCA()(&cfg)
		So(cfg.isCA, ShouldBeTrue)
		So(cfg.keyUsage&x509.KeyUsageCRLSign, ShouldEqual, x509.KeyUsageCRLSign)
		So(cfg.keyUsage&x509.KeyUsageCertSign, ShouldEqual, x509.KeyUsageCertSign)
	})

	Convey("OptIssueTypeServerAuth should work", t, func() {
		cfg := newIssueCfg()
		OptIssueTypeServerAuth()(&cfg)
		So(cfg.extKeyUsage, ShouldContain, x509.ExtKeyUsageServerAuth)
		So(cfg.keyUsage&x509.KeyUsageDigitalSignature, ShouldEqual, x509.KeyUsageDigitalSignature)
		So(cfg.keyUsage&x509.KeyUsageKeyEncipherment, ShouldEqual, x509.KeyUsageKeyEncipherment)
	})

	Convey("OptIssueTypeClientAuth should work", t, func() {
		cfg := newIssueCfg()
		OptIssueTypeClientAuth()(&cfg)
		So(cfg.extKeyUsage, ShouldContain, x509.ExtKeyUsageClientAuth)
		So(cfg.keyUsage&x509.KeyUsageDigitalSignature, ShouldEqual, x509.KeyUsageDigitalSignature)
		So(cfg.keyUsage&x509.KeyUsageKeyEncipherment, ShouldEqual, x509.KeyUsageKeyEncipherment)
	})

	Convey("OptIssueTypeEmailProtection should work", t, func() {
		cfg := newIssueCfg()
		OptIssueTypeEmailProtection()(&cfg)
		So(cfg.extKeyUsage, ShouldContain, x509.ExtKeyUsageEmailProtection)
		So(cfg.keyUsage&x509.KeyUsageDigitalSignature, ShouldEqual, x509.KeyUsageDigitalSignature)
		So(cfg.keyUsage&x509.KeyUsageKeyEncipherment, ShouldEqual, x509.KeyUsageKeyEncipherment)
	})

	Convey("OptIssueTypeCodeSigning should work", t, func() {
		cfg := newIssueCfg()
		OptIssueTypeCodeSigning()(&cfg)
		So(cfg.extKeyUsage, ShouldContain, x509.ExtKeyUsageCodeSigning)
		So(cfg.keyUsage&x509.KeyUsageDigitalSignature, ShouldEqual, x509.KeyUsageDigitalSignature)
		So(cfg.keyUsage&x509.KeyUsageKeyEncipherment, ShouldEqual, x509.KeyUsageKeyEncipherment)
	})

	Convey("OptIssueIPSANs should work", t, func() {
		cfg := newIssueCfg()
		OptIssueIPSANs(net.IP{1, 1, 1, 1})(&cfg)
		So(cfg.ipAddresses, ShouldResemble, []net.IP{{1, 1, 1, 1}})
	})

	Convey("OptIssueDNSSANs should work", t, func() {
		cfg := newIssueCfg()
		OptIssueDNSSANs("toto.com")(&cfg)
		So(cfg.dnsNames, ShouldResemble, []string{"toto.com"})
	})

	Convey("OptIssueEmailAddresses should work", t, func() {
		cfg := newIssueCfg()
		OptIssueEmailAddresses([]string{"me@me.me"})(&cfg)
		So(cfg.emailAddresses, ShouldResemble, []string{"me@me.me"})
	})

	Convey("OptIssueAlgorithmECDSA should work", t, func() {
		cfg := newIssueCfg()
		OptIssueAlgorithmECDSA()(&cfg)
		So(cfg.keyGen, ShouldEqual, ECPrivateKeyGenerator)
		So(cfg.signatureAlgorithm, ShouldEqual, x509.ECDSAWithSHA384)
		So(cfg.publicKeyAlgorithm, ShouldEqual, x509.ECDSA)
	})

	Convey("OptIssueAlgorithmRSA should work", t, func() {
		cfg := newIssueCfg()
		OptIssueAlgorithmRSA()(&cfg)
		So(cfg.keyGen, ShouldEqual, RSAPrivateKeyGenerator)
		So(cfg.signatureAlgorithm, ShouldEqual, x509.SHA384WithRSA)
		So(cfg.publicKeyAlgorithm, ShouldEqual, x509.RSA)
	})

	Convey("OptIssueExtendedKeyUsages should work", t, func() {
		cfg := newIssueCfg()
		OptIssueExtendedKeyUsages(x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageServerAuth)(&cfg)
		So(cfg.extKeyUsage, ShouldResemble, []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageServerAuth})
	})

	Convey("OptIssueKeyUsage should work", t, func() {
		cfg := newIssueCfg()
		OptIssueKeyUsage(x509.KeyUsageDigitalSignature)(&cfg)
		So(cfg.keyUsage, ShouldResemble, x509.KeyUsageDigitalSignature)
	})

	Convey("OptIssueKeyGenerator should work", t, func() {
		cfg := newIssueCfg()
		OptIssueKeyGenerator(RSAPrivateKeyGenerator)(&cfg)
		So(cfg.keyGen, ShouldEqual, RSAPrivateKeyGenerator)
	})

	Convey("OptIssuePublicKeyAlgorithm should work", t, func() {
		cfg := newIssueCfg()
		OptIssuePublicKeyAlgorithm(x509.Ed25519)(&cfg)
		So(cfg.publicKeyAlgorithm, ShouldEqual, x509.Ed25519)
	})

	Convey("OptIssueSignatureAlgorithm should work", t, func() {
		cfg := newIssueCfg()
		OptIssueSignatureAlgorithm(x509.PureEd25519)(&cfg)
		So(cfg.signatureAlgorithm, ShouldEqual, x509.PureEd25519)
	})

	Convey("OptIssuePolicies should work", t, func() {
		cfg := newIssueCfg()
		OptIssuePolicies(asn1.ObjectIdentifier{1, 2, 3})(&cfg)
		So(cfg.policies, ShouldResemble, []asn1.ObjectIdentifier{{1, 2, 3}})
	})

	Convey("OptIssueExtraExtensions should work", t, func() {
		cfg := newIssueCfg()
		OptIssueExtraExtensions([]pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3}, Value: []byte("v")}})(&cfg)
		So(cfg.extraExtensions, ShouldResemble, []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3}, Value: []byte("v")}})
	})

	Convey("OptIssueSerialNumber should work", t, func() {
		cfg := newIssueCfg()
		sn := big.NewInt(42)
		OptIssueSerialNumber(sn)(&cfg)
		So(cfg.serialNumber, ShouldEqual, sn)
	})
}
