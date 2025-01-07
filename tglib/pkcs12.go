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

package tglib

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

// GeneratePKCS12FromFiles generates a full PKCS certificate based on the input keys.
func GeneratePKCS12FromFiles(out, certPath, keyPath, caPath, passphrase string) error {

	var errb bytes.Buffer

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// TODO for pkcs12 file without encryption use: -keypbe NONE -certpbe NONE -nomaciter
	const command = "openssl"
	args := append(make([]string, 0, 15),
		"pkcs12",
		"-export",
		"-out", out,
		"-inkey", keyPath,
		"-in", certPath,
		"-passout", "pass:"+passphrase,
	)
	if len(caPath) > 0 {
		args = append(args, "-certfile", caPath)
	}

	// #nosec G204 audited OK - no command injection can occur here
	cmd := exec.CommandContext(ctx, command, args...)
	cmd.Stderr = &errb
	cmd.WaitDelay = 5 * time.Second

	err := cmd.Run()
	if err != nil {
		// include the openssl stderr output to aid in debugging the reason for failure
		err = fmt.Errorf("exec openssl failed: stderr='%s': %w", strings.TrimSpace(errb.String()), err)
	}

	return err
}

// GeneratePKCS12 generates a pkcs12
func GeneratePKCS12(cert []byte, key []byte, ca []byte, passphrase string) ([]byte, error) {

	// Some install like Docker Scratch doesn't have /tmp folder
	if _, err := os.Stat("/tmp"); os.IsNotExist(err) {
		if err = os.Mkdir("/tmp", 0750); err != nil {
			panic(fmt.Sprintf("unable to create non-existing temp folder: %s", err))
		}
	}

	// cert
	tmpcert, err := os.MkdirTemp("", "tmpcert")
	if err != nil {
		return nil, err
	}

	// #nosec G307
	defer os.RemoveAll(tmpcert) // nolint: errcheck

	if err = os.WriteFile(tmpcert, cert, 0666); err != nil {
		return nil, err
	}

	// key
	tmpkey, err := os.MkdirTemp("", "tmpkey")
	if err != nil {
		return nil, err
	}

	// #nosec G307
	defer os.RemoveAll(tmpkey) // nolint: errcheck

	if err = os.WriteFile(tmpkey, key, 0666); err != nil {
		return nil, err
	}

	// ca
	tmpca, err := os.MkdirTemp("", "tmpca")
	if err != nil {
		return nil, err
	}

	// #nosec G307
	defer os.RemoveAll(tmpca) // nolint: errcheck

	if err = os.WriteFile(tmpca, ca, 0666); err != nil {
		return nil, err
	}

	// p12
	tmpp12, err := os.MkdirTemp("", "tmpp12")
	if err != nil {
		return nil, err
	}

	// #nosec G307
	defer os.RemoveAll(tmpp12) // nolint: errcheck

	if err = GeneratePKCS12FromFiles(tmpp12, tmpcert, tmpkey, tmpca, passphrase); err != nil {
		return nil, err
	}

	tmpp12Reader := strings.NewReader(tmpp12)

	p12data, err := io.ReadAll(tmpp12Reader)
	if err != nil {
		return nil, err
	}
	return p12data, nil
}

// GenerateBase64PKCS12 generates a full PKCS certificate based on the input keys.
func GenerateBase64PKCS12(cert []byte, key []byte, ca []byte, passphrase string) (string, error) {

	p12data, err := GeneratePKCS12(cert, key, ca, passphrase)

	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(p12data), nil
}
