//go:build !windows

package tglib

import (
	"crypto/x509"
)

// SystemCertPool gets the system cert pool via Go libraries
func SystemCertPool() (*x509.CertPool, error) {
	return x509.SystemCertPool()
}
