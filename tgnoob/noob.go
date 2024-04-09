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
	"time"
)

// CreateCA creates a Certificates Authority Certificate.
func CreateCA(
	name string,
	organization string,
	password string,
	out string,
) (string, string, error) {

	var err error

	if out == "" {
		if out, err = os.MkdirTemp("", "certificates"); err != nil {
			return "", "", err
		}
	}

	if err = GenerateCertificate(
		name,                   // string
		organization,           // commonName
		password,               // password
		true,                   // isCA
		false,                  // authServer
		false,                  // authClient
		false,                  // authEmail
		false,                  // p12
		"",                     // p12Pass
		out,                    // out
		false,                  // force
		algoECDSA,              // algo
		"",                     // signingCertPath
		"",                     // signingCertKeyPath
		"",                     // signingCertKeyPass
		[]string{"us"},         // country
		[]string{"ca"},         // state
		[]string{"sanjose"},    // city
		[]string{},             // address
		[]string{},             // zipCode
		[]string{organization}, // org
		[]string{},             // orgUnit
		[]string{},             // dns
		[]string{},             // ips
		14*24*time.Hour,        // duration
		[]string{},             // policies
	); err != nil {
		return "", "", err
	}

	certOut := certificatePath(out, name)
	keyOut := certificateKeyPath(out, name)

	return certOut, keyOut, nil

}

// CreateSignedCA creates a Certificates Authority Certificate.
func CreateSignedCA(
	name string,
	organization string,
	password string,
	signingCertPath string,
	signingCertKeyPath string,
	signingCertKeyPass string,
	out string,
) (string, string, error) {

	var err error

	if out == "" {
		if out, err = os.MkdirTemp("", "certificates"); err != nil {
			return "", "", err
		}
	}

	if err = GenerateCertificate(
		name,                   // string
		organization,           // commonName
		password,               // password
		true,                   // isCA
		false,                  // authServer
		false,                  // authClient
		false,                  // authEmail
		false,                  // p12
		"",                     // p12Pass
		out,                    // out
		false,                  // force
		algoECDSA,              // algo
		signingCertPath,        // signingCertPath
		signingCertKeyPath,     // signingCertKeyPath
		signingCertKeyPass,     // signingCertKeyPass
		[]string{"us"},         // country
		[]string{"ca"},         // state
		[]string{"sanjose"},    // city
		[]string{},             // address
		[]string{},             // zipCode
		[]string{organization}, // org
		[]string{},             // orgUnit
		[]string{},             // dns
		[]string{},             // ips
		14*24*time.Hour,        // duration
		[]string{},             // policies
	); err != nil {
		return "", "", err
	}

	certOut := certificatePath(out, name)
	keyOut := certificateKeyPath(out, name)

	return certOut, keyOut, nil

}

// CreateClientCertificate creates a client certificate.
func CreateClientCertificate(
	name string,
	organization string,
	password string,
	signingCertPath string,
	signingCertKeyPath string,
	signingCertKeyPass string,
	dns []string,
	ips []string,
	out string,
) (string, string, error) {

	var err error

	if out == "" {
		if out, err = os.MkdirTemp("", "certificates"); err != nil {
			return "", "", err
		}
	}

	if err = GenerateCertificate(
		name,                   // string
		organization,           // commonName
		password,               // password
		false,                  // isCA
		false,                  // authServer
		true,                   // authClient
		false,                  // authEmail
		false,                  // p12
		"",                     // p12Pass
		out,                    // out
		false,                  // force
		algoECDSA,              // algo
		signingCertPath,        // signingCertPath
		signingCertKeyPath,     // signingCertKeyPath
		signingCertKeyPass,     // signingCertKeyPass
		[]string{"us"},         // country
		[]string{"ca"},         // state
		[]string{"sanjose"},    // city
		[]string{},             // address
		[]string{},             // zipCode
		[]string{organization}, // org
		[]string{},             // orgUnit
		dns,                    // dns
		ips,                    // ips
		14*24*time.Hour,        // duration
		[]string{},             // policies
	); err != nil {
		return "", "", err
	}

	certOut := certificatePath(out, name)
	keyOut := certificateKeyPath(out, name)

	return certOut, keyOut, nil
}

// CreateServerCertificate creates a client certificate.
func CreateServerCertificate(
	name string,
	organization string,
	password string,
	signingCertPath string,
	signingCertKeyPath string,
	signingCertKeyPass string,
	dns []string,
	ips []string,
	out string,
) (string, string, error) {

	var err error

	if out == "" {
		if out, err = os.MkdirTemp("", "certificates"); err != nil {
			return "", "", err
		}
	}

	if err = GenerateCertificate(
		name,                   // string
		organization,           // commonName
		password,               // password
		false,                  // isCA
		true,                   // authServer
		false,                  // authClient
		false,                  // authEmail
		false,                  // p12
		"",                     // p12Pass
		out,                    // out
		false,                  // force
		algoECDSA,              // algo
		signingCertPath,        // signingCertPath
		signingCertKeyPath,     // signingCertKeyPath
		signingCertKeyPass,     // signingCertKeyPass
		[]string{"us"},         // country
		[]string{"ca"},         // state
		[]string{"sanjose"},    // city
		[]string{},             // address
		[]string{},             // zipCode
		[]string{organization}, // org
		[]string{},             // orgUnit
		dns,                    // dns
		ips,                    // ips
		14*24*time.Hour,        // duration
		[]string{},             // policies
	); err != nil {
		return "", "", err
	}

	certOut := certificatePath(out, name)
	keyOut := certificateKeyPath(out, name)

	return certOut, keyOut, nil
}
