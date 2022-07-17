// Copyright 2020 Tamás Gulácsi.
//
// SPDX-License-Identifier: Apache-2.0

package signify

import (
	"fmt"
	"io"
	"os"
)

const (
	DefaultPrivKeyEnv = "NACL_PRIVATE_KEY"
	DefaultPubKeyEnv  = "NACL_PUBLIC_KEY"
)

func GenerateKeyFiles(pubKeyFile, privKeyFile string) error {
	pub, priv, err := GenerateKey()
	if err != nil {
		return err
	}
	for _, s := range []struct {
		fn   string
		s    fmt.Stringer
		mode os.FileMode
	}{
		{pubKeyFile, pub, 0444},
		{privKeyFile, priv, 0400},
	} {
		if s.fn == "" || s.fn == "-" {
			if _, err = fmt.Println(s.s); err != nil {
				return err
			}
		} else {
			if err := os.WriteFile(s.fn, []byte(s.s.String()), s.mode); err != nil {
				return err
			}
		}
	}
	return nil
}

func SignFile(privKey, privKeyFile, privKeyEnv, sigFile, msgFile string) error {
	var priv PrivateKey
	if privKey == "" {
		if privKeyFile != "" {
			b, err := os.ReadFile(privKeyFile)
			if err != nil {
				return fmt.Errorf("read private key from %q: %w", privKeyFile, err)
			}
			privKey = string(b)
		} else if privKeyEnv != "" {
			privKey = os.Getenv(privKeyEnv)
		}
	}
	if err := priv.Parse(privKey); err != nil {
		return err
	}

	var msg []byte
	var err error
	if msgFile == "" || msgFile == "-" {
		msg, err = io.ReadAll(os.Stdin)
	} else {
		msg, err = os.ReadFile(msgFile)
	}
	if err != nil {
		return fmt.Errorf("read message from %q: %w", msgFile, err)
	}
	out := Sign(make([]byte, 0, len(msg)+64), msg, priv)
	if sigFile == "" || sigFile == "-" {
		_, err = os.Stdout.Write(out)
	} else {
		err = os.WriteFile(sigFile, out, 0640)
	}
	if err != nil {
		return fmt.Errorf("write signed message to %q: %w", sigFile, err)
	}
	return nil
}

func VerifyFile(pubKey, pubKeyFile, pubKeyEnv, sigFile, msgFile string) error {
	var pub PublicKey
	if pubKey == "" {
		if pubKeyFile != "" {
			b, err := os.ReadFile(pubKeyFile)
			if err != nil {
				return fmt.Errorf("read public key from %q: %w", pubKeyFile, err)
			}
			pubKey = string(b)
		} else if pubKeyEnv != "" {
			pubKey = os.Getenv(pubKeyEnv)
		}
	}
	if err := pub.Parse(pubKey); err != nil {
		return err
	}

	var sig []byte
	var err error
	if sigFile == "" || sigFile == "-" {
		sig, err = io.ReadAll(os.Stdin)
	} else {
		sig, err = os.ReadFile(sigFile)
	}
	if err != nil {
		return fmt.Errorf("read signed message from %q: %w", sigFile, err)
	}
	out, ok := Open(make([]byte, 0, len(sig)-64), sig, pub)
	if !ok {
		return fmt.Errorf("signature mismatch")
	}
	if msgFile == "" || msgFile == "-" {
		_, err = os.Stdout.Write(out)
	} else {
		err = os.WriteFile(msgFile, out, 0640)
	}
	if err != nil {
		return fmt.Errorf("write message to %q: %w", msgFile, err)
	}
	return nil
}
