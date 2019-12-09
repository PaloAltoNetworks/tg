// +build !windows

package tglib

import (
	"crypto/x509"
)

// GetSystemCertPool gets the system cert pool via Go libraries
func GetSystemCertPool() (*x509.CertPool, error) {
	return x509.SystemCertPool()
}
