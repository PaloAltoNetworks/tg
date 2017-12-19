package main

import (
	"encoding/asn1"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/aporeto-inc/tg/tgnoob"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	algoECDSA = "ecdsa"
	algoRSA   = "rsa"
)

func addOutputFlags(cmd *cobra.Command) {
	cmd.Flags().String("out", "./", "Path to the directtory where the certificate files will be written.")
	cmd.Flags().Bool("force", false, "Overwrite the certificate if it already exists.")
	cmd.Flags().String("name", "", "Base name of the certificate.")
	cmd.Flags().String("algo", "ecdsa", "Signature algorithm to use. Can be rsa or ecdsa.")
}

func addUsageFlags(cmd *cobra.Command) {
	cmd.Flags().Bool("auth-server", false, "If set, the issued certificate can be used for server authentication.")
	cmd.Flags().Bool("auth-client", false, "If set, the issued certificate can be used for client authentication.")
	cmd.Flags().Bool("auth-email", false, "If set, the issued certificate can be used for email signature/encryption.")
}

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
	cmd.Flags().StringSlice("policy", nil, "Additional policy extensions in the form --policy <OID>. Note that 1.3.6.1.4.1 is automatically added. Just start with your PEN number.")
	cmd.Flags().Duration("validity", 86400*time.Hour, "Duration of the validity of the certificate.")
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
	addUsageFlags(cmdGen)
	addOutputFlags(cmdGen)

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
	csrGen.Flags().String("cert", "", "Create a new CSR from the given existing certificate. All other options will be ignored.")
	csrGen.Flags().String("cert-key", "", "Path to the key associated to the cert.")
	csrGen.Flags().String("cert-key-pass", "", "Password to the key associated to the cert.")
	addPKIXFlags(csrGen)
	addOutputFlags(csrGen)

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
	csrSign.Flags().Bool("is-ca", false, "If set the issued certificate could be used as a certificate authority.")
	addSigningFlags(csrSign)
	addUsageFlags(csrSign)
	addOutputFlags(csrSign)

	var verifyCmd = &cobra.Command{
		Use:   "verify",
		Short: "Verify if the given cert has been signed by another one",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return viper.BindPFlags(cmd.Flags())
		},
		Run: func(cmd *cobra.Command, args []string) {
			verifyCert()
		},
	}
	verifyCmd.Flags().String("cert", "", "Path to certificate to verify.")
	verifyCmd.Flags().String("signer", "", "Path to signing certificate.")
	addUsageFlags(verifyCmd)

	var decryptCmd = &cobra.Command{
		Use:   "decrypt",
		Short: "Decrypt of the given private key",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return viper.BindPFlags(cmd.Flags())
		},
		Run: func(cmd *cobra.Command, args []string) {
			decryptPrivateKey()
		},
	}
	decryptCmd.Flags().String("key", "", "path to the key.")
	decryptCmd.Flags().String("pass", "", "password to decrypt the key.")

	var encryptCmd = &cobra.Command{
		Use:   "encrypt",
		Short: "Encrypt of the given private key",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return viper.BindPFlags(cmd.Flags())
		},
		Run: func(cmd *cobra.Command, args []string) {
			encryptPrivateKey()
		},
	}
	encryptCmd.Flags().String("key", "", "path to the key.")
	encryptCmd.Flags().String("pass", "", "password to encrypt the key.")

	rootCmd.AddCommand(
		cmdGen,
		csrGen,
		csrSign,
		verifyCmd,
		decryptCmd,
		encryptCmd,
	)

	rootCmd.Execute() // nolint: errcheck
}

func generateCertificate() {

	if err := tgnoob.GenerateCertificate(
		viper.GetString("name"),
		viper.GetString("common-name"),
		viper.GetString("pass"),
		viper.GetBool("is-ca"),
		viper.GetBool("auth-server"),
		viper.GetBool("auth-client"),
		viper.GetBool("auth-email"),
		viper.GetBool("p12"),
		viper.GetString("p12-pass"),
		viper.GetString("out"),
		viper.GetBool("force"),
		viper.GetString("algo"),
		viper.GetString("signing-cert"),
		viper.GetString("signing-cert-key"),
		viper.GetString("signing-cert-key-pass"),
		viper.GetStringSlice("country"),
		viper.GetStringSlice("state"),
		viper.GetStringSlice("city"),
		viper.GetStringSlice("address"),
		viper.GetStringSlice("zip-code"),
		viper.GetStringSlice("org"),
		viper.GetStringSlice("org-unit"),
		viper.GetStringSlice("dns"),
		viper.GetStringSlice("ip"),
		viper.GetDuration("validity"),
		viper.GetStringSlice("policy"),
	); err != nil {
		logrus.WithError(err).Fatal("could not generate certificate")
	}

	logrus.WithFields(logrus.Fields{
		"cert": viper.GetString("name") + "-cert.pem",
		"key":  viper.GetString("name") + "-key.pem",
	}).Info("certificate key pair created")
}

func generateCSR() {

	if err := tgnoob.GenerateCSR(
		viper.GetString("name"),
		viper.GetString("common-name"),
		viper.GetString("cert"),
		viper.GetString("cert-key"),
		viper.GetString("cert-key-pass"),
		viper.GetString("out"),
		viper.GetBool("force"),
		viper.GetString("algo"),
		viper.GetStringSlice("country"),
		viper.GetStringSlice("state"),
		viper.GetStringSlice("city"),
		viper.GetStringSlice("address"),
		viper.GetStringSlice("zip-code"),
		viper.GetStringSlice("org"),
		viper.GetStringSlice("org-unit"),
		viper.GetStringSlice("dns"),
		viper.GetStringSlice("ip"),
		viper.GetStringSlice("policy"),
	); err != nil {
		logrus.WithError(err).Fatal("could not generate csr")
	}

	logrus.WithFields(logrus.Fields{
		"csr": viper.GetString("name") + "-csr.pem",
		"key": viper.GetString("name") + "-key.pem",
	}).Info("Certificate request and private key created")
}

func signCSR() {

	if err := tgnoob.SignCSR(
		viper.GetString("name"),
		viper.GetBool("is-ca"),
		viper.GetBool("auth-server"),
		viper.GetBool("auth-client"),
		viper.GetBool("auth-email"),
		viper.GetString("out"),
		viper.GetBool("force"),
		viper.GetString("algo"),
		viper.GetString("signing-cert"),
		viper.GetString("signing-cert-key"),
		viper.GetString("signing-cert-key-pass"),
		viper.GetStringSlice("csr"),
		viper.GetDuration("validity"),
		viper.GetStringSlice("policy"),
	); err != nil {
		logrus.WithError(err).Fatal("could not sign csr")
	}

	logrus.WithFields(logrus.Fields{
		"cert": viper.GetString("name") + "-cert.pem",
	}).Info("Certificate issued")
}

func verifyCert() {

	if err := tgnoob.VerifyCert(
		viper.GetString("cert"),
		viper.GetString("signer"),
		viper.GetBool("auth-server"),
		viper.GetBool("auth-client"),
		viper.GetBool("auth-email"),
	); err != nil {
		logrus.WithError(err).Fatal("could not verify the certificate")
	}

	logrus.Info("certificate verified")
}

func decryptPrivateKey() {

	var (
		err        error
		encodedPem []byte
	)

	if encodedPem, err = tgnoob.DecryptPrivateKey(
		viper.GetString("key"),
		viper.GetString("pass"),
	); err != nil {
		logrus.WithError(err).Fatal("unable to decrypt private key")
	}

	fmt.Printf("%s", encodedPem)
}

func encryptPrivateKey() {

	var (
		err        error
		encodedPem []byte
	)

	if encodedPem, err = tgnoob.EncryptPrivateKey(
		viper.GetString("key"),
		viper.GetString("pass"),
	); err != nil {
		logrus.WithError(err).Fatal("unable to encrypt private key")
	}

	fmt.Printf("%s", encodedPem)
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
