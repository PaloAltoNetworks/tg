package main

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"net"
	"os"
	"path"
	"strings"
	"time"

	"github.com/aporeto-inc/tg/tglib"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

func main() {

	var err error

	pflag.String("out", "./", "Path to the directtory where the certificate files will be written.")
	pflag.Bool("force", false, "Overwrite the certificate if it already exists.")
	pflag.String("name", "", "Base name of the certificate.")

	pflag.StringSlice("org", nil, "List of organizations that will be written in the certificate subject.")
	pflag.StringSlice("org-unit", nil, "List of organizational units that will be written in the certificate subject.")
	pflag.String("common-name", "", "Common name that will be written in the certificate subject.")
	pflag.StringSlice("country", nil, "Country that will be written the the subject.")
	pflag.StringSlice("state", nil, "State that will be written the the subject.")
	pflag.StringSlice("city", nil, "City that will be written the the subject.")
	pflag.StringSlice("zip-code", nil, "City that will be written the the subject.")
	pflag.StringSlice("address", nil, "Address that will be written the the subject.")
	pflag.Bool("p12", false, "If set, a p12 will also be generated. This needs openssl binary to be installed on your machine.")
	pflag.String("p12-pass", "", "Set the p12 passphrase. Only works when --p12 is set.")

	pflag.StringSlice("dns", nil, "List of alternate DNS names.")
	pflag.StringSlice("ip", nil, "List of alternate ips.")

	pflag.Duration("validity", 86400*time.Hour, "Duration of the validity of the certificate.")
	pflag.Bool("is-ca", false, "If set the issued certificate could be used as a certificate authority.")
	pflag.Bool("auth-server", false, "If set, the issued certificate can be used for server authentication.")
	pflag.Bool("auth-client", false, "If set, the issued certificate can be used for client authentication.")

	pflag.String("algo", "ecdsa", "Signature algorithm to use. Can be rsa or ecdsa.")
	pflag.String("pass", "", "Passphrase to use for the private key. If not given it will not be encryped.")
	pflag.String("signing-cert", "", "Path to the signing certificate.")
	pflag.String("signing-cert-key", "", "Path to the signing certificate key.")
	pflag.String("signing-cert-key-pass", "", "PathPassword to decrypt the signing certificate key.")

	pflag.Parse()

	if err = viper.BindPFlags(pflag.CommandLine); err != nil {
		logrus.WithError(err).Fatal("unable to bind flags")
	}

	viper.SetEnvPrefix("tlsgen")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))

	if viper.GetString("name") == "" {
		logrus.Fatal("you must specify a name via --name")
	}

	if viper.GetString("common-name") == "" {
		viper.Set("common-name", viper.GetString("name"))
	}

	if !viper.GetBool("is-ca") && !viper.GetBool("auth-server") && !viper.GetBool("auth-client") {
		logrus.Fatal("you must set at least one of --auth-server or --auth-client")
	}

	if viper.GetBool("p12") && viper.GetString("p12-pass") == "" {
		logrus.Fatal("you must set --p12-pass when setting --p12")
	}

	certOut := path.Join(viper.GetString("out"), viper.GetString("name")+"-cert.pem")
	keyOut := path.Join(viper.GetString("out"), viper.GetString("name")+"-key.pem")

	if _, err = os.Stat(certOut); !os.IsNotExist(err) && !viper.GetBool("force") {
		logrus.WithField("path", certOut).Fatal("destination file already exists. Use --force to overwrite")
	}
	if _, err = os.Stat(keyOut); !os.IsNotExist(err) && !viper.GetBool("force") {
		logrus.WithField("path", certOut).Fatal("destination file already exists. Use --force to overwrite")
	}

	var keygen tglib.PrivateKeyGenerator
	var signalg x509.SignatureAlgorithm
	var pkalg x509.PublicKeyAlgorithm

	switch viper.GetString("algo") {
	case "ecdsa":
		keygen = tglib.ECPrivateKeyGenerator
		signalg = x509.ECDSAWithSHA384
		pkalg = x509.ECDSA
	case "rsa":
		keygen = tglib.RSAPrivateKeyGenerator
		signalg = x509.SHA384WithRSA
		pkalg = x509.RSA
	}

	var keyUsage x509.KeyUsage
	var extKeyUsage []x509.ExtKeyUsage
	if viper.GetBool("is-ca") {
		keyUsage = x509.KeyUsageCRLSign | x509.KeyUsageCertSign
	} else {
		keyUsage = x509.KeyUsageDigitalSignature
	}

	if viper.GetBool("auth-client") {
		keyUsage |= x509.KeyUsageDigitalSignature
		extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageClientAuth)
	}
	if viper.GetBool("auth-server") {
		keyUsage |= x509.KeyUsageKeyEncipherment
		extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageServerAuth)
	}

	var signingCert *x509.Certificate
	var signingKey crypto.PrivateKey
	signingCertPath := viper.GetString("signing-cert")
	signingCertKeyPath := viper.GetString("signing-cert-key")

	if signingCertPath != "" || signingCertKeyPath != "" {

		if signingCertPath == "" || signingCertKeyPath == "" {
			logrus.Fatal("you must pass both --signing-cert and --signing-cert-key if you pass one or the other")
		}

		signingCert, signingKey, err = tglib.ReadCertificatePEM(signingCertPath, signingCertKeyPath, viper.GetString("signing-cert-key-pass"))
		if err != nil {
			logrus.WithError(err).Fatal("unable to read signing certiticate information")
		}
	}

	var ips []net.IP
	for _, ip := range viper.GetStringSlice("ip") {
		ips = append(ips, net.ParseIP(ip))
	}

	priv, pub, err := tglib.IssueCertiticate(
		signingCert,
		signingKey,
		keygen,
		viper.GetStringSlice("country"),
		viper.GetStringSlice("state"),
		viper.GetStringSlice("city"),
		viper.GetStringSlice("address"),
		viper.GetStringSlice("zip-code"),
		viper.GetStringSlice("org"),
		viper.GetStringSlice("org-unit"),
		viper.GetString("common-name"),
		viper.GetStringSlice("dns"),
		ips,
		time.Now(),
		time.Now().Add(viper.GetDuration("validity")),
		keyUsage,
		extKeyUsage,
		signalg,
		pkalg,
		viper.GetBool("is-ca"),
	)

	if err != nil {
		logrus.WithError(err).Fatal("unable to generate certificate")
	}

	if pass := viper.GetString("pass"); pass != "" {
		priv, err = x509.EncryptPEMBlock(rand.Reader, priv.Type, priv.Bytes, []byte(pass), x509.PEMCipherAES256)
		if err != nil {
			logrus.WithError(err).Fatal("unable to encrypt private key")
		}
	}

	if err = ioutil.WriteFile(
		keyOut,
		pem.EncodeToMemory(priv),
		0644,
	); err != nil {
		logrus.WithError(err).Fatal("unable to write private key on file")
	}

	if err = ioutil.WriteFile(
		certOut,
		pem.EncodeToMemory(pub),
		0644,
	); err != nil {
		logrus.WithError(err).Fatal("unable to write public key on file")
	}

	if viper.GetBool("p12") {
		if err = tglib.GeneratePKCS12(
			path.Join(viper.GetString("out"), viper.GetString("name")+".p12"),
			certOut,
			keyOut,
			signingCertPath,
			viper.GetString("p12-pass"),
		); err != nil {
			logrus.WithError(err).Fatal("unable to write p12 on file")
		}
	}

	logrus.WithFields(logrus.Fields{
		"cert": viper.GetString("name") + "-cert.pem",
		"key":  viper.GetString("name") + "-key.pem",
	}).Info("X509 certificate key pair created")
}
