package main

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"io/ioutil"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/aporeto-inc/tg/tglib"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	algoECDSA = "ecdsa"
	algoRSA   = "rsa"
)

func addPKIXFlags(cmd *cobra.Command) {
	cmd.Flags().StringSlice("org", nil, "List of organizations that will be written in the certificate subject.")
	cmd.Flags().StringSlice("org-unit", nil, "List of organizational units that will be written in the certificate subject.")
	cmd.Flags().String("common-name", "", "Common name that will be written in the certificate subject.")
	cmd.Flags().StringSlice("country", nil, "Country that will be written the the subject.")
	cmd.Flags().StringSlice("state", nil, "State that will be written the the subject.")
	cmd.Flags().StringSlice("city", nil, "City that will be written the the subject.")
	cmd.Flags().StringSlice("zip-code", nil, "City that will be written the the subject.")
	cmd.Flags().StringSlice("address", nil, "Address that will be written the the subject.")
	cmd.Flags().StringSlice("dns", nil, "List of alternate DNS names.")
	cmd.Flags().StringSlice("ip", nil, "List of alternate ips.")
}

func addSigningFlags(cmd *cobra.Command) {
	cmd.Flags().String("signing-cert", "", "Path to the signing certificate.")
	cmd.Flags().String("signing-cert-key", "", "Path to the signing certificate key.")
	cmd.Flags().String("signing-cert-key-pass", "", "PathPassword to decrypt the signing certificate key.")
	cmd.Flags().StringSlice("policy", nil, "Additonal policy extensions in the form --policy <OID>. Note that 1.3.6.1.4.1 is automatically added. Just start with your PEN number.")
	cmd.Flags().Duration("validity", 86400*time.Hour, "Duration of the validity of the certificate.")
	cmd.Flags().Bool("auth-server", false, "If set, the issued certificate can be used for server authentication.")
	cmd.Flags().Bool("auth-client", false, "If set, the issued certificate can be used for client authentication.")
}

func main() {

	cobra.OnInitialize(func() {
		viper.SetEnvPrefix("tlsgen")
		viper.AutomaticEnv()
		viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	})

	var rootCmd = &cobra.Command{
		Use: "tg",
	}
	rootCmd.PersistentFlags().String("out", "./", "Path to the directtory where the certificate files will be written.")
	rootCmd.PersistentFlags().Bool("force", false, "Overwrite the certificate if it already exists.")
	rootCmd.PersistentFlags().String("name", "", "Base name of the certificate.")
	rootCmd.PersistentFlags().String("algo", "ecdsa", "Signature algorithm to use. Can be rsa or ecdsa.")

	var cmdGen = &cobra.Command{
		Use:   "cert",
		Short: "Generate certificates",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return viper.BindPFlags(cmd.Flags())
		},
		Run: func(cmd *cobra.Command, args []string) {
			generateCertificate()
		},
	}
	cmdGen.Flags().Bool("p12", false, "If set, a p12 will also be generated. This needs openssl binary to be installed on your machine.")
	cmdGen.Flags().String("p12-pass", "", "Set the p12 passphrase. Only works when --p12 is set.")
	cmdGen.Flags().Bool("is-ca", false, "If set the issued certificate could be used as a certificate authority.")
	cmdGen.Flags().String("pass", "", "Passphrase to use for the private key. If not given it will not be encryped.")
	addPKIXFlags(cmdGen)
	addSigningFlags(cmdGen)

	var csrGen = &cobra.Command{
		Use:   "csr",
		Short: "Generate certificate signing request",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return viper.BindPFlags(cmd.Flags())
		},
		Run: func(cmd *cobra.Command, args []string) {
			generateCSR()
		},
	}
	addPKIXFlags(csrGen)

	var csrSign = &cobra.Command{
		Use:   "sign",
		Short: "Sign the given certificate signing request",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return viper.BindPFlags(cmd.Flags())
		},
		Run: func(cmd *cobra.Command, args []string) {
			signCSR()
		},
	}
	csrSign.Flags().StringSlice("csr", nil, "Path to csrs to sign.")
	addSigningFlags(csrSign)

	rootCmd.AddCommand(cmdGen)
	rootCmd.AddCommand(csrGen)
	rootCmd.AddCommand(csrSign)
	rootCmd.Execute()
}

func generateCertificate() {

	var err error

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
		logrus.WithField("path", keyOut).Fatal("destination file already exists. Use --force to overwrite")
	}

	var keygen tglib.PrivateKeyGenerator
	var signalg x509.SignatureAlgorithm
	var pkalg x509.PublicKeyAlgorithm
	switch viper.GetString("algo") {
	case algoECDSA:
		keygen = tglib.ECPrivateKeyGenerator
		signalg = x509.ECDSAWithSHA384
		pkalg = x509.ECDSA
	case algoRSA:
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

	pub, priv, err := tglib.IssueCertiticate(
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
		makePolicies(),
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
		if err = tglib.GeneratePKCS12FromFiles(
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

func generateCSR() {

	if viper.GetString("name") == "" {
		logrus.Fatal("you must specify a name via --name")
	}

	if viper.GetString("common-name") == "" {
		viper.Set("common-name", viper.GetString("name"))
	}

	csrOut := path.Join(viper.GetString("out"), viper.GetString("name")+"-csr.pem")
	keyOut := path.Join(viper.GetString("out"), viper.GetString("name")+"-key.pem")

	if _, err := os.Stat(csrOut); !os.IsNotExist(err) && !viper.GetBool("force") {
		logrus.WithField("path", csrOut).Fatal("destination file already exists. Use --force to overwrite")
	}
	if _, err := os.Stat(keyOut); !os.IsNotExist(err) && !viper.GetBool("force") {
		logrus.WithField("path", keyOut).Fatal("destination file already exists. Use --force to overwrite")
	}

	var keygen tglib.PrivateKeyGenerator
	var signalg x509.SignatureAlgorithm
	var pkalg x509.PublicKeyAlgorithm

	switch viper.GetString("algo") {
	case algoECDSA:
		keygen = tglib.ECPrivateKeyGenerator
		signalg = x509.ECDSAWithSHA384
		pkalg = x509.ECDSA
	case algoRSA:
		keygen = tglib.RSAPrivateKeyGenerator
		signalg = x509.SHA384WithRSA
		pkalg = x509.RSA
	}

	privateKey, err := keygen()
	if err != nil {
		logrus.WithError(err).Fatal("Unable to generate private key")
	}
	keyBlock, err := tglib.KeyToPEM(privateKey)
	if err != nil {
		logrus.WithError(err).Fatal("Unable to convert private key pem block")
	}

	var ips []net.IP
	for _, ip := range viper.GetStringSlice("ip") {
		ips = append(ips, net.ParseIP(ip))
	}

	csr := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:         viper.GetString("common-name"),
			Organization:       viper.GetStringSlice("org"),
			OrganizationalUnit: viper.GetStringSlice("org-unit"),
			Country:            viper.GetStringSlice("country"),
			Locality:           viper.GetStringSlice("city"),
			StreetAddress:      viper.GetStringSlice("address"),
			Province:           viper.GetStringSlice("state"),
			PostalCode:         viper.GetStringSlice("zip-code"),
		},
		SignatureAlgorithm: signalg,
		PublicKeyAlgorithm: pkalg,
		DNSNames:           viper.GetStringSlice("dns"),
		IPAddresses:        ips,
	}

	csrBytes, err := tglib.GenerateCSR(csr, privateKey)
	if err != nil {
		logrus.WithError(err).Fatal("Unable to create csr")
	}

	if err = ioutil.WriteFile(
		keyOut,
		pem.EncodeToMemory(keyBlock),
		0644,
	); err != nil {
		logrus.WithError(err).Fatal("unable to write private key on file")
	}

	if err = ioutil.WriteFile(
		csrOut,
		csrBytes,
		0644,
	); err != nil {
		logrus.WithError(err).Fatal("unable to write public key on file")
	}
}

func signCSR() {

	if viper.GetString("name") == "" {
		logrus.Fatal("you must specify a name via --name")
	}

	if viper.GetString("signing-cert") == "" {
		logrus.Fatal("you must specify a signing cert via --signing-cert")
	}

	if viper.GetString("signing-cert-key") == "" {
		logrus.Fatal("you must specify a signing cert key via --signing-cert-key")
	}

	if len(viper.GetStringSlice("csr")) == 0 {
		logrus.Fatal("you must specify at least one csr via --csr")
	}

	if !viper.GetBool("auth-server") && !viper.GetBool("auth-client") {
		logrus.Fatal("you must set at least one of --auth-server or --auth-client")
	}

	certOut := path.Join(viper.GetString("out"), viper.GetString("name")+"-cert.pem")
	if _, err := os.Stat(certOut); !os.IsNotExist(err) && !viper.GetBool("force") {
		logrus.WithField("path", certOut).Fatal("destination file already exists. Use --force to overwrite")
	}

	signingCertData, err := ioutil.ReadFile(viper.GetString("signing-cert"))
	if err != nil {
		logrus.WithError(err).WithField("path", viper.GetString("signing-cert")).Fatal("Unable to load signing cert")
	}
	signingCertKeyData, err := ioutil.ReadFile(viper.GetString("signing-cert-key"))
	if err != nil {
		logrus.WithError(err).WithField("path", viper.GetString("signing-cert-key")).Fatal("Unable to load signing cert key")
	}

	signingCert, signingKey, err := tglib.ReadCertificate(signingCertData, signingCertKeyData, viper.GetString("signing-cert-key-pass"))
	if err != nil {
		logrus.WithError(err).Fatal("Unable to read signing cert")
	}

	var signalg x509.SignatureAlgorithm
	var pkalg x509.PublicKeyAlgorithm
	switch viper.GetString("algo") {
	case algoECDSA:
		signalg = x509.ECDSAWithSHA384
		pkalg = x509.ECDSA
	case algoRSA:
		signalg = x509.SHA384WithRSA
		pkalg = x509.RSA
	}

	keyUsage := x509.KeyUsageDigitalSignature
	var extKeyUsage []x509.ExtKeyUsage
	if viper.GetBool("auth-client") {
		keyUsage |= x509.KeyUsageDigitalSignature
		extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageClientAuth)
	}
	if viper.GetBool("auth-server") {
		keyUsage |= x509.KeyUsageKeyEncipherment
		extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageServerAuth)
	}

	for _, path := range viper.GetStringSlice("csr") {

		csrData, err := ioutil.ReadFile(path)
		if err != nil {
			logrus.WithError(err).WithField("path", path).Fatal("Unable to load csr")
		}
		csrs, err := tglib.LoadCSRs(csrData)
		if err != nil {
			logrus.WithError(err).WithField("path", path).Fatal("Unable to parse csr")
		}

		for _, csr := range csrs {
			certBlock, err := tglib.SignCSR(
				csr,
				signingCert,
				signingKey,
				time.Now(),
				time.Now().Add(viper.GetDuration("validity")),
				keyUsage,
				extKeyUsage,
				signalg,
				pkalg,
				makePolicies(),
			)
			if err != nil {
				logrus.WithError(err).Fatal("Unable to sign certificate")
			}

			if err = ioutil.WriteFile(
				certOut,
				pem.EncodeToMemory(certBlock),
				0644,
			); err != nil {
				logrus.WithError(err).Fatal("unable to write certificate on file")
			}

		}
	}

}

func makePolicies() []asn1.ObjectIdentifier {

	var policies []asn1.ObjectIdentifier

	for _, kv := range viper.GetStringSlice("policy") {
		parts := strings.Split(kv, ".")

		oid := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1}
		for _, part := range parts {
			i, e := strconv.Atoi(part)
			if e != nil {
				logrus.WithField("oid", kv).Fatal("Given policy OID is invalid")
			}
			oid = append(oid, i)
		}

		policies = append(policies, oid)
	}

	return policies
}
