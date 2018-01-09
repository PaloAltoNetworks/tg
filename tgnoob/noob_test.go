package tgnoob

import (
	"io/ioutil"
	"os"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func Test_CreateCA(t *testing.T) {
	Convey("Given an outputfolder", t, func() {

		outputFolder, _ := ioutil.TempDir("", "certificates")

		Convey("I should be able to generate a certificate authority", func() {
			certPath, keyPath, err := CreateCA("ca-acme", "acme", "", outputFolder)

			So(err, ShouldBeNil)
			So(certPath, ShouldEqual, outputFolder+"/ca-acme-cert.pem")
			So(keyPath, ShouldEqual, outputFolder+"/ca-acme-key.pem")
			_, err = os.Stat(certPath)
			So(err, ShouldBeNil)
			_, err = os.Stat(keyPath)
			So(err, ShouldBeNil)
		})

		Reset(func() {
			os.Remove(outputFolder) // nolint
		})
	})
}

func Test_CreateCertificates(t *testing.T) {
	Convey("Given a certificate authority certificate", t, func() {

		var err error

		outputFolder, _ := ioutil.TempDir("", "certificates")
		singingCertPath, signingCertKeyPath, err := CreateCA("ca-acme", "acme", "passwd", outputFolder)
		So(err, ShouldBeNil)

		Convey("I should be able to generate a client certificate", func() {
			certPath, keyPath, err := CreateClientCertificate(
				"client",
				"organization",
				"",
				singingCertPath,
				signingCertKeyPath,
				"passwd",
				[]string{},
				[]string{},
				outputFolder,
			)

			So(err, ShouldBeNil)
			So(certPath, ShouldEqual, outputFolder+"/client-cert.pem")
			So(keyPath, ShouldEqual, outputFolder+"/client-key.pem")
			_, err = os.Stat(certPath)
			So(err, ShouldBeNil)
			_, err = os.Stat(keyPath)
			So(err, ShouldBeNil)
		})

		Convey("I should be able to generate a server certificate", func() {
			certPath, keyPath, err := CreateServerCertificate(
				"server",
				"organization",
				"",
				singingCertPath,
				signingCertKeyPath,
				"passwd",
				[]string{},
				[]string{},
				outputFolder,
			)

			So(err, ShouldBeNil)
			So(certPath, ShouldEqual, outputFolder+"/server-cert.pem")
			So(keyPath, ShouldEqual, outputFolder+"/server-key.pem")
			_, err = os.Stat(certPath)
			So(err, ShouldBeNil)
			_, err = os.Stat(keyPath)
			So(err, ShouldBeNil)
		})

		Convey("I should not be able to generate a server certificate when passing a wrong password", func() {
			_, _, err := CreateServerCertificate(
				"server",
				"organization",
				"",
				singingCertPath,
				signingCertKeyPath,
				"wrongpasswd",
				[]string{},
				[]string{},
				outputFolder,
			)

			So(err, ShouldNotBeNil)
		})

		Reset(func() {
			os.Remove(outputFolder) // nolint
		})

	})
}
