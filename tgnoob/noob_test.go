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

	. "github.com/smartystreets/goconvey/convey"
)

func Test_CreateCA(t *testing.T) {
	Convey("Given an outputfolder", t, func() {

		outputFolder, _ := os.MkdirTemp("", "certificates")

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

		outputFolder, _ := os.MkdirTemp("", "certificates")
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
