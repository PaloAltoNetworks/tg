package tgnoob

import (
	"io/ioutil"
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
		if out, err = ioutil.TempDir("", "aporeto_certificates"); err != nil {
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
		24*time.Hour,           // duration
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
		if out, err = ioutil.TempDir("", "aporeto_certificates"); err != nil {
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
		[]string{},             // dns
		[]string{},             // ips
		24*time.Hour,           // duration
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
		if out, err = ioutil.TempDir("", "aporeto_certificates"); err != nil {
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
		[]string{},             // dns
		[]string{},             // ips
		24*time.Hour,           // duration
		[]string{},             // policies
	); err != nil {
		return "", "", err
	}

	certOut := certificatePath(out, name)
	keyOut := certificateKeyPath(out, name)

	return certOut, keyOut, nil
}
