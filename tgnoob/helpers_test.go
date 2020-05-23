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
	"os"
	"testing"
	"time"

	//revive:disable-next-line:dot-imports
	. "github.com/smartystreets/goconvey/convey"
)

func Test_GenerateCertificate(t *testing.T) {
	Convey("Given an outputfolder", t, func() {

		outputFolder, _ := os.MkdirTemp("", "certificates")

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
				[]string{},   // tags
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
				[]string{},   // tags
				time.Second,  // duration
				[]string{},   // policies
			)
			So(err, ShouldBeNil)
		})

		Reset(func() {
			os.Remove(outputFolder) // nolint
		})
	})
}
func Test_GenerateCSR(t *testing.T) {
	Convey("Given an outputfolder", t, func() {

		outputFolder, _ := os.MkdirTemp("", "certificates")

		Convey("I should be able to generate a csr with a certificate", func() {

			var err error
			singingCertPath, signingCertKeyPath, err := CreateCA("ca-acme", "acme", "passwd", outputFolder)
			So(err, ShouldBeNil)

			err = GenerateCSR(
				"demo",             // name
				"",                 // commonName
				singingCertPath,    // cert
				signingCertKeyPath, // certKey
				"passwd",           // certKeyPass
				outputFolder,       // out
				true,               // force
				algoRSA,            // algo
				nil,                // country
				nil,                // state
				nil,                // city
				nil,                // address
				nil,                // zipCode
				nil,                // org
				nil,                // orgUnit
				nil,                // dns
				nil,                // ips
				[]string{},         // policies
			)
			So(err, ShouldBeNil)
		})

		Convey("I should be able to generate a csr without a certificate", func() {
			err := GenerateCSR(
				"demo",                  // name
				"demo",                  // commonName
				"",                      // cert
				"",                      // certKey
				"",                      // certKeyPass
				outputFolder,            // out
				true,                    // force
				algoRSA,                 // algo
				[]string{"us"},          // country
				[]string{"ca"},          // state
				[]string{"sanjose"},     // city
				[]string{"demo street"}, // address
				[]string{"95000"},       // zipCode
				[]string{"demo"},        // org
				[]string{"org-demo"},    // orgUnit
				[]string{"demo.com"},    // dns
				[]string{"192.169.0.1"}, // ips
				[]string{},              // policies
			)
			So(err, ShouldBeNil)
		})

		Reset(func() {
			os.Remove(outputFolder) // nolint
		})
	})
}
