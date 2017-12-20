package tgnoob

import (
	"io/ioutil"
	"os"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
)

func Test_GenerateCertificate(t *testing.T) {
	Convey("Given an outputfolder", t, func() {

		outputFolder, _ := ioutil.TempDir("", "certificates")

		Convey("If no name is provided, it should fail", func() {
			err := GenerateCertificate(
				"",           // name
				"commonName", // commonName
				"password",   // password
				true,         // isCA
				true,         // authServer
				true,         // authClient
				true,         // authEmail
				false,        // p12
				"",           // p12Pass
				outputFolder, // out
				false,        // force
				algoECDSA,    // algo
				"",           // signingCertPath
				"",           // signingCertKeyPath
				"",           // signingCertKeyPass
				[]string{},   // country
				[]string{},   // state
				[]string{},   // city
				[]string{},   // address
				[]string{},   // zipCode
				[]string{},   // org
				[]string{},   // orgUnit
				[]string{},   // dns
				[]string{},   // ips
				time.Second,  // duration
				[]string{},   // policies
			)
			So(err, ShouldNotBeNil)
		})

		Convey("If no common name is provided, it should not fail", func() {
			err := GenerateCertificate(
				"name",       // name
				"",           // commonName
				"password",   // password
				true,         // isCA
				true,         // authServer
				true,         // authClient
				true,         // authEmail
				false,        // p12
				"",           // p12Pass
				outputFolder, // out
				false,        // force
				algoECDSA,    // algo
				"",           // signingCertPath
				"",           // signingCertKeyPath
				"",           // signingCertKeyPass
				[]string{},   // country
				[]string{},   // state
				[]string{},   // city
				[]string{},   // address
				[]string{},   // zipCode
				[]string{},   // org
				[]string{},   // orgUnit
				[]string{},   // dns
				[]string{},   // ips
				time.Second,  // duration
				[]string{},   // policies
			)
			So(err, ShouldBeNil)
		})

		Convey("If no auth is provided, it should fail", func() {
			err := GenerateCertificate(
				"name",       // name
				"commonName", // commonName
				"password",   // password
				false,        // isCA
				false,        // authServer
				false,        // authClient
				false,        // authEmail
				false,        // p12
				"",           // p12Pass
				outputFolder, // out
				false,        // force
				algoECDSA,    // algo
				"",           // signingCertPath
				"",           // signingCertKeyPath
				"",           // signingCertKeyPass
				[]string{},   // country
				[]string{},   // state
				[]string{},   // city
				[]string{},   // address
				[]string{},   // zipCode
				[]string{},   // org
				[]string{},   // orgUnit
				[]string{},   // dns
				[]string{},   // ips
				time.Second,  // duration
				[]string{},   // policies
			)
			So(err, ShouldNotBeNil)
		})

		Reset(func() {
			os.Remove(outputFolder)
		})
	})
}
func Test_GenerateCSR(t *testing.T) {
	Convey("Given an outputfolder", t, func() {

		var err error

		outputFolder, _ := ioutil.TempDir("", "certificates")
		singingCertPath, signingCertKeyPath, err := CreateCA("ca-acme", "acme", "passwd", outputFolder)
		So(err, ShouldBeNil)

		Convey("If no name is provided, it should fail", func() {
			err := GenerateCSR(
				"demo",             // name
				"aporeto",          // commonName
				singingCertPath,    // cert
				signingCertKeyPath, // certKey
				"passwd",           // certKeyPass
				outputFolder,       // out
				true,               // force
				algoRSA,            // algo
				[]string{},         // country
				[]string{},         // state
				[]string{},         // city
				[]string{},         // address
				[]string{},         // zipCode
				[]string{},         // org
				[]string{},         // orgUnit
				[]string{},         // dns
				[]string{},         // ips
				[]string{},         // policies
			)
			So(err, ShouldNotBeNil)
		})

		Reset(func() {
			os.Remove(outputFolder)
		})
	})
}
