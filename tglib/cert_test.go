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
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
)

func TestIssue(t *testing.T) {

	Convey("Given I issue root ECDSA CA", t, func() {

		cacert, cakey, err := Issue(
			pkix.Name{CommonName: "my-ca"},
			OptIssueTypeCA(),
		)

		Convey("Then err should be nil", func() {
			So(err, ShouldBeNil)
		})

		Convey("Then cert should not be correct", func() {
			So(cacert, ShouldNotBeNil)
			x509cert, _ := ParseCertificate(pem.EncodeToMemory(cacert))
			So(x509cert.SignatureAlgorithm, ShouldEqual, x509.ECDSAWithSHA256)
			So(x509cert.PublicKeyAlgorithm, ShouldEqual, x509.ECDSA)
			So(x509cert.Subject.CommonName, ShouldEqual, "my-ca")
		})

		Convey("Then key should not be correct", func() {
			So(cakey, ShouldNotBeNil)
		})

		Convey("When I Issue a cert from that CA", func() {

			cert, _, err := Issue(
				pkix.Name{CommonName: "my-cert"},
				OptIssueSignerPEMBlock(cacert, cakey, ""),
				OptIssueTypeServerAuth(),
				OptIssueExtraExtensions([]pkix.Extension{
					{
						Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 50798, 1, 1},
						Value: []byte("hello"),
					},
				}),
			)

			Convey("Then err should be nil", func() {
				So(err, ShouldBeNil)
			})

			Convey("When I verify the signature for any usage", func() {

				err := Verify(pem.EncodeToMemory(cacert), pem.EncodeToMemory(cert), nil)

				Convey("Then err should be nil", func() {
					So(err, ShouldBeNil)
				})
			})

			Convey("When I verify the signature for valid usage", func() {

				err := Verify(pem.EncodeToMemory(cacert), pem.EncodeToMemory(cert), []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})

				Convey("Then err should be nil", func() {
					So(err, ShouldBeNil)
				})
			})

			Convey("When I verify the signature for specific missing usage", func() {

				err := Verify(pem.EncodeToMemory(cacert), pem.EncodeToMemory(cert), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})

				Convey("Then err should not be nil", func() {
					So(err, ShouldNotBeNil)
					So(err.Error(), ShouldEqual, "unable to verify child certificate: x509: certificate specifies an incompatible key usage")
				})
			})
		})

	})

	Convey("Given I issue root RSA CA", t, func() {

		cert, key, err := IssueCertiticate(
			nil,
			nil,
			RSAPrivateKeyGenerator,
			nil,
			nil,
			nil,
			nil,
			nil,
			nil,
			nil,
			"my-ca",
			nil,
			nil,
			time.Now(),
			time.Now().Add(2*time.Hour),
			x509.KeyUsageCRLSign|x509.KeyUsageCertSign,
			nil,
			x509.ECDSAWithSHA384,
			x509.ECDSA,
			true,
			nil,
		)

		Convey("Then err should be nil", func() {
			So(err, ShouldBeNil)
		})

		Convey("Then cert should not be correct", func() {
			So(cert, ShouldNotBeNil)
			x509cert, _ := ParseCertificate(pem.EncodeToMemory(cert))
			So(x509cert.SignatureAlgorithm, ShouldEqual, x509.SHA256WithRSA)
			So(x509cert.PublicKeyAlgorithm, ShouldEqual, x509.RSA)
			So(x509cert.Subject.CommonName, ShouldEqual, "my-ca")
		})

		Convey("Then key should not be correct", func() {
			So(key, ShouldNotBeNil)
		})
	})
}

func TestParseCertificates(t *testing.T) {

	Convey("Given I have a valid single certificate pem bytes", t, func() {

		pemdata := []byte(`-----BEGIN CERTIFICATE-----
MIIBSzCB8qADAgECAhB/m97PHhuMp31jkL82iaDTMAoGCCqGSM49BAMCMBcxFTAT
BgNVBAMTDHNpbmdsZS12YWxpZDAeFw0xOTA0MDMyMjA0MDlaFw0yOTAyMDkyMjA0
MDlaMBcxFTATBgNVBAMTDHNpbmdsZS12YWxpZDBZMBMGByqGSM49AgEGCCqGSM49
AwEHA0IABIuoCNWwV9sgOQlM3yCg5ZpO8tAg0qhp2CygD3lhRRR6SshuSzsHdpA/
RQogNbUzWhZzgeZ/3LdN97yUdh9ZWIGjIDAeMA4GA1UdDwEB/wQEAwIHgDAMBgNV
HRMBAf8EAjAAMAoGCCqGSM49BAMCA0gAMEUCIQCCgRiFFnSus15W8aFJl+f5W3Ey
dAj4VmjDEGz8NQisSQIgLTYqJrpjxT2/AQ7axw/GY2xl1CI43xpahnX+F0mq/tA=
-----END CERTIFICATE-----`)

		Convey("When I call ParseCertificates", func() {

			certs, err := ParseCertificates(pemdata)

			Convey("Then err should be nil", func() {
				So(err, ShouldBeNil)
			})

			Convey("Then certs should be correct", func() {
				So(len(certs), ShouldEqual, 1)
			})
		})
	})

	Convey("Given I have a invalid single certificate pem bytes", t, func() {

		pemdata := []byte(`-----BEGIN CERTIFICATE-----
HELLSzCB8qADAgECAhB/m97PHhuMp31jkL82iaDTMAoGCCqGSM49BAMCMBcxFTAT
BgNVBAMTDHNpbmdsZS12YWxpZDAeFw0xOTA0MDMyMjA0MDlaFw0yOTAyMDkyMjA0
MDlaMBcxFTATBgNVBAMTDHNpbmdsZS12YWxpZDBZMBMGByqGSM49AgEGCCqGSM49
AwEHA0IABIuoCNWwV9sgOQlM3yCg5ZpO8tAg0qhp2CygD3lhRRR6SshuSzsHdpA/
RQogNbUzWhZzgeZ/3LdN97yUdh9ZWIGjIDAeMA4GA1UdDwEB/wQEAwIHgDAMBgNV
HRMBAf8EAjAAMAoGCCqGSM49BAMCA0gAMEUCIQCCgRiFFnSus15W8aFJl+f5W3Ey
dAj4VmjDEGz8NQisSQIgLTYqJrpjxT2/AQ7axw/GY2xl1CI43xpahnX+F0mq/tA=
-----END CERTIFICATE-----`)

		Convey("When I call ParseCertificates", func() {

			certs, err := ParseCertificates(pemdata)

			Convey("Then err should not be nil", func() {
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldStartWith, "unable to parse certificate: asn1: structure error: tags don't match")
			})

			Convey("Then certs should be correct", func() {
				So(len(certs), ShouldEqual, 0)
			})
		})
	})

	Convey("Given I have a invalid encoded single certificate pem bytes", t, func() {

		pemdata := []byte(`-----BEGIN CERTIFICATE-----
NO
-----END CERTIFICATE-----`)

		Convey("When I call ParseCertificates", func() {

			certs, err := ParseCertificates(pemdata)

			Convey("Then err should not be nil", func() {
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldEqual, "unable to parse certificate data: '-----BEGIN CERTIFICATE-----\nNO\n-----END CERTIFICATE-----'")
			})

			Convey("Then certs should be correct", func() {
				So(len(certs), ShouldEqual, 0)
			})
		})
	})

	Convey("Given I haveempty pem bytes", t, func() {

		pemdata := []byte(``)

		Convey("When I call ParseCertificates", func() {

			certs, err := ParseCertificates(pemdata)

			Convey("Then err should not be nil", func() {
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldEqual, "no certificate found in given data")
			})

			Convey("Then certs should be correct", func() {
				So(len(certs), ShouldEqual, 0)
			})
		})
	})

	Convey("Given I have a valid 2 certificates pem bytes", t, func() {

		pemdata := []byte(`-----BEGIN CERTIFICATE-----
MIIBSzCB8qADAgECAhB/m97PHhuMp31jkL82iaDTMAoGCCqGSM49BAMCMBcxFTAT
BgNVBAMTDHNpbmdsZS12YWxpZDAeFw0xOTA0MDMyMjA0MDlaFw0yOTAyMDkyMjA0
MDlaMBcxFTATBgNVBAMTDHNpbmdsZS12YWxpZDBZMBMGByqGSM49AgEGCCqGSM49
AwEHA0IABIuoCNWwV9sgOQlM3yCg5ZpO8tAg0qhp2CygD3lhRRR6SshuSzsHdpA/
RQogNbUzWhZzgeZ/3LdN97yUdh9ZWIGjIDAeMA4GA1UdDwEB/wQEAwIHgDAMBgNV
HRMBAf8EAjAAMAoGCCqGSM49BAMCA0gAMEUCIQCCgRiFFnSus15W8aFJl+f5W3Ey
dAj4VmjDEGz8NQisSQIgLTYqJrpjxT2/AQ7axw/GY2xl1CI43xpahnX+F0mq/tA=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBSzCB8qADAgECAhB/m97PHhuMp31jkL82iaDTMAoGCCqGSM49BAMCMBcxFTAT
BgNVBAMTDHNpbmdsZS12YWxpZDAeFw0xOTA0MDMyMjA0MDlaFw0yOTAyMDkyMjA0
MDlaMBcxFTATBgNVBAMTDHNpbmdsZS12YWxpZDBZMBMGByqGSM49AgEGCCqGSM49
AwEHA0IABIuoCNWwV9sgOQlM3yCg5ZpO8tAg0qhp2CygD3lhRRR6SshuSzsHdpA/
RQogNbUzWhZzgeZ/3LdN97yUdh9ZWIGjIDAeMA4GA1UdDwEB/wQEAwIHgDAMBgNV
HRMBAf8EAjAAMAoGCCqGSM49BAMCA0gAMEUCIQCCgRiFFnSus15W8aFJl+f5W3Ey
dAj4VmjDEGz8NQisSQIgLTYqJrpjxT2/AQ7axw/GY2xl1CI43xpahnX+F0mq/tA=
-----END CERTIFICATE-----`)

		Convey("When I call ParseCertificates", func() {

			certs, err := ParseCertificates(pemdata)

			Convey("Then err should be nil", func() {
				So(err, ShouldBeNil)
			})

			Convey("Then certs should be correct", func() {
				So(len(certs), ShouldEqual, 2)
			})
		})
	})

	Convey("Given I have a invalid 2 certificates pem bytes", t, func() {

		pemdata := []byte(`-----BEGIN CERTIFICATE-----
MIIBSzCB8qADAgECAhB/m97PHhuMp31jkL82iaDTMAoGCCqGSM49BAMCMBcxFTAT
BgNVBAMTDHNpbmdsZS12YWxpZDAeFw0xOTA0MDMyMjA0MDlaFw0yOTAyMDkyMjA0
MDlaMBcxFTATBgNVBAMTDHNpbmdsZS12YWxpZDBZMBMGByqGSM49AgEGCCqGSM49
AwEHA0IABIuoCNWwV9sgOQlM3yCg5ZpO8tAg0qhp2CygD3lhRRR6SshuSzsHdpA/
RQogNbUzWhZzgeZ/3LdN97yUdh9ZWIGjIDAeMA4GA1UdDwEB/wQEAwIHgDAMBgNV
HRMBAf8EAjAAMAoGCCqGSM49BAMCA0gAMEUCIQCCgRiFFnSus15W8aFJl+f5W3Ey
dAj4VmjDEGz8NQisSQIgLTYqJrpjxT2/AQ7axw/GY2xl1CI43xpahnX+F0mq/tA=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
NOOOO
-----END CERTIFICATE-----`)

		Convey("When I call ParseCertificates", func() {

			certs, err := ParseCertificates(pemdata)

			Convey("Then err should not be nil", func() {
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldEqual, "unable to parse certificate data: '-----BEGIN CERTIFICATE-----\nNOOOO\n-----END CERTIFICATE-----'")
			})

			Convey("Then certs should be correct", func() {
				So(len(certs), ShouldEqual, 0)
			})
		})
	})

}

func TestParseCertificate(t *testing.T) {

	Convey("Given I have a valid single certificate pem bytes", t, func() {

		pemdata := []byte(`-----BEGIN CERTIFICATE-----
MIIBSzCB8qADAgECAhB/m97PHhuMp31jkL82iaDTMAoGCCqGSM49BAMCMBcxFTAT
BgNVBAMTDHNpbmdsZS12YWxpZDAeFw0xOTA0MDMyMjA0MDlaFw0yOTAyMDkyMjA0
MDlaMBcxFTATBgNVBAMTDHNpbmdsZS12YWxpZDBZMBMGByqGSM49AgEGCCqGSM49
AwEHA0IABIuoCNWwV9sgOQlM3yCg5ZpO8tAg0qhp2CygD3lhRRR6SshuSzsHdpA/
RQogNbUzWhZzgeZ/3LdN97yUdh9ZWIGjIDAeMA4GA1UdDwEB/wQEAwIHgDAMBgNV
HRMBAf8EAjAAMAoGCCqGSM49BAMCA0gAMEUCIQCCgRiFFnSus15W8aFJl+f5W3Ey
dAj4VmjDEGz8NQisSQIgLTYqJrpjxT2/AQ7axw/GY2xl1CI43xpahnX+F0mq/tA=
-----END CERTIFICATE-----`)

		Convey("When I call ParseCertificate", func() {

			cert, err := ParseCertificate(pemdata)

			Convey("Then err should be nil", func() {
				So(err, ShouldBeNil)
			})

			Convey("Then certs should be correct", func() {
				So(cert, ShouldNotBeNil)
			})
		})
	})

	Convey("Given I have an empty single certificate pem bytes", t, func() {

		pemdata := []byte(``)

		Convey("When I call ParseCertificate", func() {

			cert, err := ParseCertificate(pemdata)

			Convey("Then err should not be nil", func() {
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldEqual, "no certificate found in given data")
			})

			Convey("Then certs should be nil", func() {
				So(cert, ShouldBeNil)
			})
		})
	})
}

func TestCertificatePEM(t *testing.T) {

	Convey("Given I have a valid path with single cert", t, func() {

		Convey("When I call ParseCertificatePEM", func() {

			cert, err := ParseCertificatePEM("./fixtures/single-valid-cert.pem")

			Convey("Then err should be nil", func() {
				So(err, ShouldBeNil)
			})

			Convey("Then cert should not be nil", func() {
				So(cert, ShouldNotBeNil)
			})
		})
	})

	Convey("Given I have a valid path with multiple cert", t, func() {

		Convey("When I call ParseCertificatePEM", func() {

			cert, err := ParseCertificatePEM("./fixtures/multiple-valid-cert.pem")

			Convey("Then err should be nil", func() {
				So(err, ShouldBeNil)
			})

			Convey("Then cert should not be nil", func() {
				So(cert, ShouldNotBeNil)
			})
		})
	})

	Convey("Given I have an invalid path", t, func() {

		Convey("When I call ParseCertificatePEM", func() {

			cert, err := ParseCertificatePEM("./fixtures/not.pem")

			Convey("Then err should not be nil", func() {
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldEqual, "unable to read pem file: open ./fixtures/not.pem: no such file or directory")
			})

			Convey("Then cert should be nil", func() {
				So(cert, ShouldBeNil)
			})
		})
	})
}

func TestCertificatePEMs(t *testing.T) {

	Convey("Given I have a valid path with single cert", t, func() {

		Convey("When I call ParseCertificatePEMs", func() {

			cert, err := ParseCertificatePEMs("./fixtures/single-valid-cert.pem")

			Convey("Then err should be nil", func() {
				So(err, ShouldBeNil)
			})

			Convey("Then cert should be correct", func() {
				So(len(cert), ShouldEqual, 1)
			})
		})
	})

	Convey("Given I have a valid path with multiple cert", t, func() {

		Convey("When I call ParseCertificatePEMs", func() {

			cert, err := ParseCertificatePEMs("./fixtures/multiple-valid-cert.pem")

			Convey("Then err should be nil", func() {
				So(err, ShouldBeNil)
			})

			Convey("Then cert should be correct", func() {
				So(len(cert), ShouldEqual, 2)
			})
		})
	})

	Convey("Given I have an invalid path", t, func() {

		Convey("When I call ParseCertificatePEMs", func() {

			cert, err := ParseCertificatePEMs("./fixtures/not.pem")

			Convey("Then err should not be nil", func() {
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldEqual, "unable to read pem file: open ./fixtures/not.pem: no such file or directory")
			})

			Convey("Then cert should be nil", func() {
				So(cert, ShouldBeNil)
			})
		})
	})
}

func TestReadCertificates(t *testing.T) {

	Convey("Given I have a valid single cert pem and valid unencrypted key", t, func() {

		pemcertdata := []byte(`-----BEGIN CERTIFICATE-----
MIIBSzCB8qADAgECAhB/m97PHhuMp31jkL82iaDTMAoGCCqGSM49BAMCMBcxFTAT
BgNVBAMTDHNpbmdsZS12YWxpZDAeFw0xOTA0MDMyMjA0MDlaFw0yOTAyMDkyMjA0
MDlaMBcxFTATBgNVBAMTDHNpbmdsZS12YWxpZDBZMBMGByqGSM49AgEGCCqGSM49
AwEHA0IABIuoCNWwV9sgOQlM3yCg5ZpO8tAg0qhp2CygD3lhRRR6SshuSzsHdpA/
RQogNbUzWhZzgeZ/3LdN97yUdh9ZWIGjIDAeMA4GA1UdDwEB/wQEAwIHgDAMBgNV
HRMBAf8EAjAAMAoGCCqGSM49BAMCA0gAMEUCIQCCgRiFFnSus15W8aFJl+f5W3Ey
dAj4VmjDEGz8NQisSQIgLTYqJrpjxT2/AQ7axw/GY2xl1CI43xpahnX+F0mq/tA=
-----END CERTIFICATE-----`)

		pemkeydata := []byte(`-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIPXl916rXvtot4ZRN+uv3Y/CdD9VqWU1cTwLx5ybjDjwoAoGCCqGSM49
AwEHoUQDQgAEi6gI1bBX2yA5CUzfIKDlmk7y0CDSqGnYLKAPeWFFFHpKyG5LOwd2
kD9FCiA1tTNaFnOB5n/ct033vJR2H1lYgQ==
-----END EC PRIVATE KEY-----`)

		Convey("When I call ReadCertificates", func() {

			certs, key, err := ReadCertificates(pemcertdata, pemkeydata, "")

			Convey("Then err should be nil", func() {
				So(err, ShouldBeNil)
			})

			Convey("Then certs should be correct", func() {
				So(len(certs), ShouldEqual, 1)
			})

			Convey("Then key should be correct", func() {
				So(key, ShouldNotBeNil)
			})
		})
	})

	Convey("Given I have a valid single cert pem and valid encrypted key and valid password", t, func() {

		pemcertdata := []byte(`-----BEGIN CERTIFICATE-----
MIIBSzCB8qADAgECAhB/m97PHhuMp31jkL82iaDTMAoGCCqGSM49BAMCMBcxFTAT
BgNVBAMTDHNpbmdsZS12YWxpZDAeFw0xOTA0MDMyMjA0MDlaFw0yOTAyMDkyMjA0
MDlaMBcxFTATBgNVBAMTDHNpbmdsZS12YWxpZDBZMBMGByqGSM49AgEGCCqGSM49
AwEHA0IABIuoCNWwV9sgOQlM3yCg5ZpO8tAg0qhp2CygD3lhRRR6SshuSzsHdpA/
RQogNbUzWhZzgeZ/3LdN97yUdh9ZWIGjIDAeMA4GA1UdDwEB/wQEAwIHgDAMBgNV
HRMBAf8EAjAAMAoGCCqGSM49BAMCA0gAMEUCIQCCgRiFFnSus15W8aFJl+f5W3Ey
dAj4VmjDEGz8NQisSQIgLTYqJrpjxT2/AQ7axw/GY2xl1CI43xpahnX+F0mq/tA=
-----END CERTIFICATE-----`)

		pemkeydata := []byte(`-----BEGIN EC PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,1171146700781c20abde723841174005

MXY7uaLhfcLSUHytUu5ogGBRJnqRB1tdELobqKqWV30tJKk1dJKplMKMLbYvcxn/
yJNjFR1T1EBoNgfaFOTe9meFmp7KEJ0Ebx9421+NeAfSWjwlp03c1/oKiJSto8b3
0CSw1eQQmTa/wNnvpzOEM5qnlySrVBTLeNIbiB56NGc=
-----END EC PRIVATE KEY-----`)

		Convey("When I call ReadCertificates", func() {

			certs, key, err := ReadCertificates(pemcertdata, pemkeydata, "secret")

			Convey("Then err should be nil", func() {
				So(err, ShouldBeNil)
			})

			Convey("Then certs should be correct", func() {
				So(len(certs), ShouldEqual, 1)
			})

			Convey("Then key should be correct", func() {
				So(key, ShouldNotBeNil)
			})
		})
	})

	Convey("Given I have a valid single cert pem and valid encrypted key and wrong password", t, func() {

		pemcertdata := []byte(`-----BEGIN CERTIFICATE-----
MIIBSzCB8qADAgECAhB/m97PHhuMp31jkL82iaDTMAoGCCqGSM49BAMCMBcxFTAT
BgNVBAMTDHNpbmdsZS12YWxpZDAeFw0xOTA0MDMyMjA0MDlaFw0yOTAyMDkyMjA0
MDlaMBcxFTATBgNVBAMTDHNpbmdsZS12YWxpZDBZMBMGByqGSM49AgEGCCqGSM49
AwEHA0IABIuoCNWwV9sgOQlM3yCg5ZpO8tAg0qhp2CygD3lhRRR6SshuSzsHdpA/
RQogNbUzWhZzgeZ/3LdN97yUdh9ZWIGjIDAeMA4GA1UdDwEB/wQEAwIHgDAMBgNV
HRMBAf8EAjAAMAoGCCqGSM49BAMCA0gAMEUCIQCCgRiFFnSus15W8aFJl+f5W3Ey
dAj4VmjDEGz8NQisSQIgLTYqJrpjxT2/AQ7axw/GY2xl1CI43xpahnX+F0mq/tA=
-----END CERTIFICATE-----`)

		pemkeydata := []byte(`-----BEGIN EC PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,1171146700781c20abde723841174005

MXY7uaLhfcLSUHytUu5ogGBRJnqRB1tdELobqKqWV30tJKk1dJKplMKMLbYvcxn/
yJNjFR1T1EBoNgfaFOTe9meFmp7KEJ0Ebx9421+NeAfSWjwlp03c1/oKiJSto8b3
0CSw1eQQmTa/wNnvpzOEM5qnlySrVBTLeNIbiB56NGc=
-----END EC PRIVATE KEY-----`)

		Convey("When I call ReadCertificates", func() {

			certs, key, err := ReadCertificates(pemcertdata, pemkeydata, "not-secret")

			Convey("Then err should not be nil", func() {
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldEqual, "x509: decryption password incorrect")
			})

			Convey("Then certs should be correct", func() {
				So(len(certs), ShouldEqual, 0)
			})

			Convey("Then key should be correct", func() {
				So(key, ShouldBeNil)
			})
		})
	})

	Convey("Given I have a valid single cert pem and empty key", t, func() {

		pemcertdata := []byte(`-----BEGIN CERTIFICATE-----
MIIBSzCB8qADAgECAhB/m97PHhuMp31jkL82iaDTMAoGCCqGSM49BAMCMBcxFTAT
BgNVBAMTDHNpbmdsZS12YWxpZDAeFw0xOTA0MDMyMjA0MDlaFw0yOTAyMDkyMjA0
MDlaMBcxFTATBgNVBAMTDHNpbmdsZS12YWxpZDBZMBMGByqGSM49AgEGCCqGSM49
AwEHA0IABIuoCNWwV9sgOQlM3yCg5ZpO8tAg0qhp2CygD3lhRRR6SshuSzsHdpA/
RQogNbUzWhZzgeZ/3LdN97yUdh9ZWIGjIDAeMA4GA1UdDwEB/wQEAwIHgDAMBgNV
HRMBAf8EAjAAMAoGCCqGSM49BAMCA0gAMEUCIQCCgRiFFnSus15W8aFJl+f5W3Ey
dAj4VmjDEGz8NQisSQIgLTYqJrpjxT2/AQ7axw/GY2xl1CI43xpahnX+F0mq/tA=
-----END CERTIFICATE-----`)

		pemkeydata := []byte(``)

		Convey("When I call ReadCertificates", func() {

			certs, key, err := ReadCertificates(pemcertdata, pemkeydata, "not-secret")

			Convey("Then err should not be nil", func() {
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldEqual, "could not read key data from bytes: ''")
			})

			Convey("Then certs should be correct", func() {
				So(len(certs), ShouldEqual, 0)
			})

			Convey("Then key should be correct", func() {
				So(key, ShouldBeNil)
			})
		})
	})

	Convey("Given I have a empty cert pem and valid encrypted key", t, func() {

		pemcertdata := []byte(``)

		pemkeydata := []byte(`-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIPXl916rXvtot4ZRN+uv3Y/CdD9VqWU1cTwLx5ybjDjwoAoGCCqGSM49
AwEHoUQDQgAEi6gI1bBX2yA5CUzfIKDlmk7y0CDSqGnYLKAPeWFFFHpKyG5LOwd2
kD9FCiA1tTNaFnOB5n/ct033vJR2H1lYgQ==
-----END EC PRIVATE KEY-----`)

		Convey("When I call ReadCertificates", func() {

			certs, key, err := ReadCertificates(pemcertdata, pemkeydata, "")

			Convey("Then err should not be nil", func() {
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldEqual, "tls: failed to find any PEM data in certificate input")
			})

			Convey("Then certs should be correct", func() {
				So(len(certs), ShouldEqual, 0)
			})

			Convey("Then key should be correct", func() {
				So(key, ShouldBeNil)
			})
		})
	})

	Convey("Given I have a invalid single cert pem and valid unencrypted key", t, func() {

		pemcertdata := []byte(`NO`)

		pemkeydata := []byte(`-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIPXl916rXvtot4ZRN+uv3Y/CdD9VqWU1cTwLx5ybjDjwoAoGCCqGSM49
AwEHoUQDQgAEi6gI1bBX2yA5CUzfIKDlmk7y0CDSqGnYLKAPeWFFFHpKyG5LOwd2
kD9FCiA1tTNaFnOB5n/ct033vJR2H1lYgQ==
-----END EC PRIVATE KEY-----`)

		Convey("When I call ReadCertificates", func() {

			certs, key, err := ReadCertificates(pemcertdata, pemkeydata, "")

			Convey("Then err should not be nil", func() {
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldEqual, "tls: failed to find any PEM data in certificate input")
			})

			Convey("Then certs should be correct", func() {
				So(len(certs), ShouldEqual, 0)
			})

			Convey("Then key should be correct", func() {
				So(key, ShouldBeNil)
			})
		})
	})

	Convey("Given I have a invalid single cert pem content and valid unencrypted key", t, func() {

		pemcertdata := []byte(`-----BEGIN CERTIFICATE-----
NOOOSzCB8qADAgECAhB/m97PHhuMp31jkL82iaDTMAoGCCqGSM49BAMCMBcxFTAT
BgNVBAMTDHNpbmdsZS12YWxpZDAeFw0xOTA0MDMyMjA0MDlaFw0yOTAyMDkyMjA0
MDlaMBcxFTATBgNVBAMTDHNpbmdsZS12YWxpZDBZMBMGByqGSM49AgEGCCqGSM49
AwEHA0IABIuoCNWwV9sgOQlM3yCg5ZpO8tAg0qhp2CygD3lhRRR6SshuSzsHdpA/
RQogNbUzWhZzgeZ/3LdN97yUdh9ZWIGjIDAeMA4GA1UdDwEB/wQEAwIHgDAMBgNV
HRMBAf8EAjAAMAoGCCqGSM49BAMCA0gAMEUCIQCCgRiFFnSus15W8aFJl+f5W3Ey
dAj4VmjDEGz8NQisSQIgLTYqJrpjxT2/AQ7axw/GY2xl1CI43xpahnX+F0mq/tA=
-----END CERTIFICATE-----`)

		pemkeydata := []byte(`-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIPXl916rXvtot4ZRN+uv3Y/CdD9VqWU1cTwLx5ybjDjwoAoGCCqGSM49
AwEHoUQDQgAEi6gI1bBX2yA5CUzfIKDlmk7y0CDSqGnYLKAPeWFFFHpKyG5LOwd2
kD9FCiA1tTNaFnOB5n/ct033vJR2H1lYgQ==
-----END EC PRIVATE KEY-----`)

		Convey("When I call ReadCertificates", func() {

			certs, key, err := ReadCertificates(pemcertdata, pemkeydata, "")

			Convey("Then err should not be nil", func() {
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldEqual, "asn1: structure error: length too large")
			})

			Convey("Then certs should be correct", func() {
				So(len(certs), ShouldEqual, 0)
			})

			Convey("Then key should be correct", func() {
				So(key, ShouldBeNil)
			})
		})
	})

	Convey("Given I have a valid single cert pem and invalid unencrypted key", t, func() {

		pemcertdata := []byte(`-----BEGIN CERTIFICATE-----
MIIBSzCB8qADAgECAhB/m97PHhuMp31jkL82iaDTMAoGCCqGSM49BAMCMBcxFTAT
BgNVBAMTDHNpbmdsZS12YWxpZDAeFw0xOTA0MDMyMjA0MDlaFw0yOTAyMDkyMjA0
MDlaMBcxFTATBgNVBAMTDHNpbmdsZS12YWxpZDBZMBMGByqGSM49AgEGCCqGSM49
AwEHA0IABIuoCNWwV9sgOQlM3yCg5ZpO8tAg0qhp2CygD3lhRRR6SshuSzsHdpA/
RQogNbUzWhZzgeZ/3LdN97yUdh9ZWIGjIDAeMA4GA1UdDwEB/wQEAwIHgDAMBgNV
HRMBAf8EAjAAMAoGCCqGSM49BAMCA0gAMEUCIQCCgRiFFnSus15W8aFJl+f5W3Ey
dAj4VmjDEGz8NQisSQIgLTYqJrpjxT2/AQ7axw/GY2xl1CI43xpahnX+F0mq/tA=
-----END CERTIFICATE-----`)

		pemkeydata := []byte(`NO`)

		Convey("When I call ReadCertificates", func() {

			certs, key, err := ReadCertificates(pemcertdata, pemkeydata, "")

			Convey("Then err should not be nil", func() {
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldEqual, "could not read key data from bytes: 'NO'")
			})

			Convey("Then certs should be correct", func() {
				So(len(certs), ShouldEqual, 0)
			})

			Convey("Then key should be correct", func() {
				So(key, ShouldBeNil)
			})
		})
	})

	Convey("Given I have a valid single cert pem and multiple unencrypted key", t, func() {

		pemcertdata := []byte(`-----BEGIN CERTIFICATE-----
MIIBSzCB8qADAgECAhB/m97PHhuMp31jkL82iaDTMAoGCCqGSM49BAMCMBcxFTAT
BgNVBAMTDHNpbmdsZS12YWxpZDAeFw0xOTA0MDMyMjA0MDlaFw0yOTAyMDkyMjA0
MDlaMBcxFTATBgNVBAMTDHNpbmdsZS12YWxpZDBZMBMGByqGSM49AgEGCCqGSM49
AwEHA0IABIuoCNWwV9sgOQlM3yCg5ZpO8tAg0qhp2CygD3lhRRR6SshuSzsHdpA/
RQogNbUzWhZzgeZ/3LdN97yUdh9ZWIGjIDAeMA4GA1UdDwEB/wQEAwIHgDAMBgNV
HRMBAf8EAjAAMAoGCCqGSM49BAMCA0gAMEUCIQCCgRiFFnSus15W8aFJl+f5W3Ey
dAj4VmjDEGz8NQisSQIgLTYqJrpjxT2/AQ7axw/GY2xl1CI43xpahnX+F0mq/tA=
-----END CERTIFICATE-----`)

		pemkeydata := []byte(`-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIPXl916rXvtot4ZRN+uv3Y/CdD9VqWU1cTwLx5ybjDjwoAoGCCqGSM49
AwEHoUQDQgAEi6gI1bBX2yA5CUzfIKDlmk7y0CDSqGnYLKAPeWFFFHpKyG5LOwd2
kD9FCiA1tTNaFnOB5n/ct033vJR2H1lYgQ==
-----END EC PRIVATE KEY-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIPXl916rXvtot4ZRN+uv3Y/CdD9VqWU1cTwLx5ybjDjwoAoGCCqGSM49
AwEHoUQDQgAEi6gI1bBX2yA5CUzfIKDlmk7y0CDSqGnYLKAPeWFFFHpKyG5LOwd2
kD9FCiA1tTNaFnOB5n/ct033vJR2H1lYgQ==
-----END EC PRIVATE KEY-----`)

		Convey("When I call ReadCertificates", func() {

			certs, key, err := ReadCertificates(pemcertdata, pemkeydata, "")

			Convey("Then err should not be nil", func() {
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldEqual, "multiple private keys found: this is not supported")
			})

			Convey("Then certs should be correct", func() {
				So(len(certs), ShouldEqual, 0)
			})

			Convey("Then key should be correct", func() {
				So(key, ShouldBeNil)
			})
		})
	})

	Convey("Given I have a valid single cert pem and valid unencrypted key", t, func() {

		pemcertdata := []byte(`-----BEGIN CERTIFICATE-----
MIIBSzCB8qADAgECAhB/m97PHhuMp31jkL82iaDTMAoGCCqGSM49BAMCMBcxFTAT
BgNVBAMTDHNpbmdsZS12YWxpZDAeFw0xOTA0MDMyMjA0MDlaFw0yOTAyMDkyMjA0
MDlaMBcxFTATBgNVBAMTDHNpbmdsZS12YWxpZDBZMBMGByqGSM49AgEGCCqGSM49
AwEHA0IABIuoCNWwV9sgOQlM3yCg5ZpO8tAg0qhp2CygD3lhRRR6SshuSzsHdpA/
RQogNbUzWhZzgeZ/3LdN97yUdh9ZWIGjIDAeMA4GA1UdDwEB/wQEAwIHgDAMBgNV
HRMBAf8EAjAAMAoGCCqGSM49BAMCA0gAMEUCIQCCgRiFFnSus15W8aFJl+f5W3Ey
dAj4VmjDEGz8NQisSQIgLTYqJrpjxT2/AQ7axw/GY2xl1CI43xpahnX+F0mq/tA=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBSzCB8qADAgECAhB/m97PHhuMp31jkL82iaDTMAoGCCqGSM49BAMCMBcxFTAT
BgNVBAMTDHNpbmdsZS12YWxpZDAeFw0xOTA0MDMyMjA0MDlaFw0yOTAyMDkyMjA0
MDlaMBcxFTATBgNVBAMTDHNpbmdsZS12YWxpZDBZMBMGByqGSM49AgEGCCqGSM49
AwEHA0IABIuoCNWwV9sgOQlM3yCg5ZpO8tAg0qhp2CygD3lhRRR6SshuSzsHdpA/
RQogNbUzWhZzgeZ/3LdN97yUdh9ZWIGjIDAeMA4GA1UdDwEB/wQEAwIHgDAMBgNV
HRMBAf8EAjAAMAoGCCqGSM49BAMCA0gAMEUCIQCCgRiFFnSus15W8aFJl+f5W3Ey
dAj4VmjDEGz8NQisSQIgLTYqJrpjxT2/AQ7axw/GY2xl1CI43xpahnX+F0mq/tA=
-----END CERTIFICATE-----`)

		pemkeydata := []byte(`-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIPXl916rXvtot4ZRN+uv3Y/CdD9VqWU1cTwLx5ybjDjwoAoGCCqGSM49
AwEHoUQDQgAEi6gI1bBX2yA5CUzfIKDlmk7y0CDSqGnYLKAPeWFFFHpKyG5LOwd2
kD9FCiA1tTNaFnOB5n/ct033vJR2H1lYgQ==
-----END EC PRIVATE KEY-----`)

		Convey("When I call ReadCertificates", func() {

			certs, key, err := ReadCertificates(pemcertdata, pemkeydata, "")

			Convey("Then err should be nil", func() {
				So(err, ShouldBeNil)
			})

			Convey("Then certs should be correct", func() {
				So(len(certs), ShouldEqual, 2)
			})

			Convey("Then key should be correct", func() {
				So(key, ShouldNotBeNil)
			})
		})
	})
}

func TestReadCertificate(t *testing.T) {

	Convey("Given I have a multiple pem data", t, func() {

		pemcertdata := []byte(`-----BEGIN CERTIFICATE-----
MIIBSzCB8qADAgECAhB/m97PHhuMp31jkL82iaDTMAoGCCqGSM49BAMCMBcxFTAT
BgNVBAMTDHNpbmdsZS12YWxpZDAeFw0xOTA0MDMyMjA0MDlaFw0yOTAyMDkyMjA0
MDlaMBcxFTATBgNVBAMTDHNpbmdsZS12YWxpZDBZMBMGByqGSM49AgEGCCqGSM49
AwEHA0IABIuoCNWwV9sgOQlM3yCg5ZpO8tAg0qhp2CygD3lhRRR6SshuSzsHdpA/
RQogNbUzWhZzgeZ/3LdN97yUdh9ZWIGjIDAeMA4GA1UdDwEB/wQEAwIHgDAMBgNV
HRMBAf8EAjAAMAoGCCqGSM49BAMCA0gAMEUCIQCCgRiFFnSus15W8aFJl+f5W3Ey
dAj4VmjDEGz8NQisSQIgLTYqJrpjxT2/AQ7axw/GY2xl1CI43xpahnX+F0mq/tA=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBSzCB8qADAgECAhB/m97PHhuMp31jkL82iaDTMAoGCCqGSM49BAMCMBcxFTAT
BgNVBAMTDHNpbmdsZS12YWxpZDAeFw0xOTA0MDMyMjA0MDlaFw0yOTAyMDkyMjA0
MDlaMBcxFTATBgNVBAMTDHNpbmdsZS12YWxpZDBZMBMGByqGSM49AgEGCCqGSM49
AwEHA0IABIuoCNWwV9sgOQlM3yCg5ZpO8tAg0qhp2CygD3lhRRR6SshuSzsHdpA/
RQogNbUzWhZzgeZ/3LdN97yUdh9ZWIGjIDAeMA4GA1UdDwEB/wQEAwIHgDAMBgNV
HRMBAf8EAjAAMAoGCCqGSM49BAMCA0gAMEUCIQCCgRiFFnSus15W8aFJl+f5W3Ey
dAj4VmjDEGz8NQisSQIgLTYqJrpjxT2/AQ7axw/GY2xl1CI43xpahnX+F0mq/tA=
-----END CERTIFICATE-----`)

		pemkeydata := []byte(`-----BEGIN EC PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,1171146700781c20abde723841174005

MXY7uaLhfcLSUHytUu5ogGBRJnqRB1tdELobqKqWV30tJKk1dJKplMKMLbYvcxn/
yJNjFR1T1EBoNgfaFOTe9meFmp7KEJ0Ebx9421+NeAfSWjwlp03c1/oKiJSto8b3
0CSw1eQQmTa/wNnvpzOEM5qnlySrVBTLeNIbiB56NGc=
-----END EC PRIVATE KEY-----`)

		Convey("When I call ReadCertificate", func() {

			cert, key, err := ReadCertificate(pemcertdata, pemkeydata, "secret")

			Convey("Then err should be nil", func() {
				So(err, ShouldBeNil)
			})

			Convey("Then cert should be correct", func() {
				So(cert, ShouldNotBeNil)
			})

			Convey("Then key should be correct", func() {
				So(key, ShouldNotBeNil)
			})
		})
	})

	Convey("Given I have a multiple pem data but with an error", t, func() {

		pemcertdata := []byte(`-----BEGIN CERTIFICATE-----
MIIBSzCB8qADAgECAhB/m97PHhuMp31jkL82iaDTMAoGCCqGSM49BAMCMBcxFTAT
BgNVBAMTDHNpbmdsZS12YWxpZDAeFw0xOTA0MDMyMjA0MDlaFw0yOTAyMDkyMjA0
MDlaMBcxFTATBgNVBAMTDHNpbmdsZS12YWxpZDBZMBMGByqGSM49AgEGCCqGSM49
AwEHA0IABIuoCNWwV9sgOQlM3yCg5ZpO8tAg0qhp2CygD3lhRRR6SshuSzsHdpA/
RQogNbUzWhZzgeZ/3LdN97yUdh9ZWIGjIDAeMA4GA1UdDwEB/wQEAwIHgDAMBgNV
HRMBAf8EAjAAMAoGCCqGSM49BAMCA0gAMEUCIQCCgRiFFnSus15W8aFJl+f5W3Ey
dAj4VmjDEGz8NQisSQIgLTYqJrpjxT2/AQ7axw/GY2xl1CI43xpahnX+F0mq/tA=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBSzCB8qADAgECAhB/m97PHhuMp31jkL82iaDTMAoGCCqGSM49BAMCMBcxFTAT
BgNVBAMTDHNpbmdsZS12YWxpZDAeFw0xOTA0MDMyMjA0MDlaFw0yOTAyMDkyMjA0
MDlaMBcxFTATBgNVBAMTDHNpbmdsZS12YWxpZDBZMBMGByqGSM49AgEGCCqGSM49
AwEHA0IABIuoCNWwV9sgOQlM3yCg5ZpO8tAg0qhp2CygD3lhRRR6SshuSzsHdpA/
RQogNbUzWhZzgeZ/3LdN97yUdh9ZWIGjIDAeMA4GA1UdDwEB/wQEAwIHgDAMBgNV
HRMBAf8EAjAAMAoGCCqGSM49BAMCA0gAMEUCIQCCgRiFFnSus15W8aFJl+f5W3Ey
dAj4VmjDEGz8NQisSQIgLTYqJrpjxT2/AQ7axw/GY2xl1CI43xpahnX+F0mq/tA=
-----END CERTIFICATE-----`)

		pemkeydata := []byte(`-----BEGIN EC PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,1171146700781c20abde723841174005

MXY7uaLhfcLSUHytUu5ogGBRJnqRB1tdELobqKqWV30tJKk1dJKplMKMLbYvcxn/
yJNjFR1T1EBoNgfaFOTe9meFmp7KEJ0Ebx9421+NeAfSWjwlp03c1/oKiJSto8b3
0CSw1eQQmTa/wNnvpzOEM5qnlySrVBTLeNIbiB56NGc=
-----END EC PRIVATE KEY-----`)

		Convey("When I call ReadCertificate", func() {

			cert, key, err := ReadCertificate(pemcertdata, pemkeydata, "not-secret")

			Convey("Then err should not be nil", func() {
				So(err, ShouldNotBeNil)
			})

			Convey("Then cert should be correct", func() {
				So(cert, ShouldBeNil)
			})

			Convey("Then key should be correct", func() {
				So(key, ShouldBeNil)
			})
		})
	})
}

func TestReadCertificatePEM(t *testing.T) {

	Convey("Given I have a path with a correct single cert", t, func() {

		Convey("When I call ReadCertificatePEM", func() {

			cert, key, err := ReadCertificatePEM("./fixtures/single-valid-cert.pem", "./fixtures/single-valid-key.pem", "")

			Convey("Then err should be nil", func() {
				So(err, ShouldBeNil)
			})

			Convey("Then cert should be correct", func() {
				So(cert, ShouldNotBeNil)
			})

			Convey("Then key should be correct", func() {
				So(key, ShouldNotBeNil)
			})
		})
	})

	Convey("Given I have an invalid cert path", t, func() {

		Convey("When I call ReadCertificatePEM", func() {

			cert, key, err := ReadCertificatePEM("./fixtures/not.pem", "./fixtures/single-valid-key.pem", "")

			Convey("Then err should not be nil", func() {
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldEqual, "unable to read cert pem file: open ./fixtures/not.pem: no such file or directory")
			})

			Convey("Then cert should be correct", func() {
				So(cert, ShouldBeNil)
			})

			Convey("Then key should be correct", func() {
				So(key, ShouldBeNil)
			})
		})
	})

	Convey("Given I have an invalid key path", t, func() {

		Convey("When I call ReadCertificatePEM", func() {

			cert, key, err := ReadCertificatePEM("./fixtures/single-valid-cert.pem", "./fixtures/not.pem", "")

			Convey("Then err should not be nil", func() {
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldEqual, "unable to read key pem file: open ./fixtures/not.pem: no such file or directory")
			})

			Convey("Then cert should be correct", func() {
				So(cert, ShouldBeNil)
			})

			Convey("Then key should be correct", func() {
				So(key, ShouldBeNil)
			})
		})
	})
}
