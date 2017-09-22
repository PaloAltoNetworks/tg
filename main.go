package main

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"net"
	"path"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/aporeto-inc/addedeffect/logutils"
	"github.com/aporeto-inc/tg/tglib"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

func main() {

	var err error

	logutils.Configure("info", "console")

	pflag.String("out", "./", "Path to the directtory where the certificate files will be written.")
	pflag.String("name", "", "Base name of the certificate.")

	pflag.StringSlice("org", nil, "List of organizations that will be written in the certificate subject.")
	pflag.StringSlice("org-unit", nil, "List of organizational units that will be written in the certificate subject.")
	pflag.StringSlice("common-name", nil, "Common name that will be written in the certificate subject.")
	pflag.StringSlice("country", nil, "Country that will be written the the subject.")
	pflag.StringSlice("state", nil, "State that will be written the the subject.")
	pflag.StringSlice("city", nil, "City that will be written the the subject.")
	pflag.StringSlice("zip-code", nil, "City that will be written the the subject.")
	pflag.StringSlice("address", nil, "Address that will be written the the subject.")

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
		zap.L().Fatal("Unable to bind flags", zap.Error(err))
	}

	viper.SetEnvPrefix("tlsgen")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))

	if viper.GetString("name") == "" {
		zap.L().Fatal("You must specify a name via --name.")
	}

	if !viper.GetBool("is-ca") && !viper.GetBool("auth-server") && !viper.GetBool("auth-client") {
		zap.L().Fatal("You must set at least one of --auth-server or --auth-client.")
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
		keygen = tglib.RSArivateKeyGenerator
		signalg = x509.SHA512WithRSA
		pkalg = x509.RSA
	}

	var keyUsage x509.KeyUsage
	var extKeyUsage []x509.ExtKeyUsage
	if viper.GetBool("is-ca") {
		keyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
	}
	if viper.GetBool("auth-client") {
		extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageClientAuth)
	}
	if viper.GetBool("auth-server") {
		extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageServerAuth)
	}

	var signingCert *x509.Certificate
	signingCertPath := viper.GetString("signing-cert")
	signingCertKeyPath := viper.GetString("signing-cert-key")

	if signingCertPath != "" || signingCertKeyPath != "" {

		if signingCertPath == "" || signingCertKeyPath == "" {
			zap.L().Fatal("You must pass both --signing-cert and --signing-cert-key if you pass one or the other.")
		}

		signingCert, err = tglib.ReadCertificatePEM(signingCertPath, signingCertKeyPath, viper.GetString("signing-cert-key-pass"))
		if err != nil {
			zap.L().Fatal("Unable to read signing certiticate information", zap.Error(err))
		}
	}

	var ips []net.IP
	for _, ip := range viper.GetStringSlice("ip") {
		ips = append(ips, net.ParseIP(ip))
	}

	priv, pub, err := tglib.IssueCertiticate(
		signingCert,
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
		zap.L().Fatal("Unable to generate certificate", zap.Error(err))
	}

	if pass := viper.GetString("pass"); pass != "" {
		priv, err = x509.EncryptPEMBlock(rand.Reader, priv.Type, priv.Bytes, []byte(pass), x509.PEMCipherAES256)
		if err != nil {
			zap.L().Fatal("Unable to encrypt private key", zap.Error(err))
		}
	}

	if err := ioutil.WriteFile(
		path.Join(viper.GetString("out"), viper.GetString("name")+"-key.pem"),
		pem.EncodeToMemory(priv),
		0644,
	); err != nil {
		zap.L().Fatal("Unable to write private key on file", zap.Error(err))
	}

	if err := ioutil.WriteFile(
		path.Join(viper.GetString("out"), viper.GetString("name")+"-cert.pem"),
		pem.EncodeToMemory(pub),
		0644,
	); err != nil {
		zap.L().Fatal("Unable to write public key on file", zap.Error(err))
	}

}
