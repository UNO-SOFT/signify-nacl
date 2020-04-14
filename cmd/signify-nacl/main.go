// Copyright 2020 Tamás Gulácsi.
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/UNO-SOFT/signify-nacl"
)

func main() {
	if err := Main(); err != nil {
		log.Fatal(err)
	}
}

func Main() error {
	flag.Usage = func() {
		nm := os.Args[0]
		fmt.Fprintf(flag.CommandLine.Output(), `Usage of %[1]s:

	%[1]s -G/generate/gen/g -p pubkey -s seckey
	%[1]s -S/sign/sig/s [-x sigfile] -s seckey -m message
	%[1]s -V/verify/ver/v -p pubkey [-x sigfile] -m message

`, nm)
		flag.PrintDefaults()
	}
	if len(os.Args) == 1 {
		flag.Usage()
		return flag.ErrHelp
	}
	var pubKeyFile, privKeyFile string
	genFlags := flag.NewFlagSet("generate", flag.ContinueOnError)
	genFlags.StringVar(&pubKeyFile, "p", "-", "public key file")
	genFlags.StringVar(&privKeyFile, "s", "-", "secret key file")

	var msgFile, sigFile string
	var privKey, privKeyEnv string
	signFlags := flag.NewFlagSet("sign", flag.ContinueOnError)
	signFlags.StringVar(&privKeyFile, "s", "", "secret key file")
	signFlags.StringVar(&privKey, "S", "", "secret key")
	signFlags.StringVar(&privKeyEnv, "env", "NACL_PRIVATE_KEY", "environment variable to read the private key from")
	signFlags.StringVar(&msgFile, "m", "-", "message file")
	signFlags.StringVar(&sigFile, "x", "-", "signed message file to write to")

	var pubKey, pubKeyEnv string
	verifyFlags := flag.NewFlagSet("verify", flag.ContinueOnError)
	verifyFlags.StringVar(&pubKeyFile, "p", "", "public key file")
	verifyFlags.StringVar(&pubKey, "P", "", "public key")
	verifyFlags.StringVar(&pubKeyEnv, "env", "NACL_PUBLIC_KEY", "environment variable to read the public key from")
	verifyFlags.StringVar(&sigFile, "x", "-", "signed message file to read from")

	var todo string
	var fs *flag.FlagSet
	switch os.Args[1] {
	case "-G", "generate", "g", "gen":
		todo, fs = "generate", genFlags
	case "-S", "sign", "s", "sig":
		todo, fs = "sign", signFlags
	case "-V", "verify", "v", "ver":
		todo, fs = "verify", verifyFlags
	default:
		flag.Usage()
		return flag.ErrHelp
	}
	if err := fs.Parse(os.Args[2:]); err != nil {
		return err
	}

	switch todo {
	case "generate":
		pub, priv, err := signify.GenerateKey()
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
				if err := ioutil.WriteFile(s.fn, []byte(s.s.String()), s.mode); err != nil {
					return err
				}
			}
		}

	case "sign":
		var priv signify.PrivateKey
		if privKey == "" {
			if privKeyFile != "" {
				b, err := ioutil.ReadFile(privKeyFile)
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
			msg, err = ioutil.ReadAll(os.Stdin)
		} else {
			msg, err = ioutil.ReadFile(msgFile)
		}
		if err != nil {
			return fmt.Errorf("read message from %q: %w", msgFile, err)
		}
		out := signify.Sign(make([]byte, 0, len(msg)+64), msg, priv)
		if sigFile == "" || sigFile == "-" {
			_, err = os.Stdout.Write(out)
		} else {
			err = ioutil.WriteFile(sigFile, out, 0640)
		}
		if err != nil {
			return fmt.Errorf("write signed message to %q: %w", sigFile, err)
		}
		return nil

	case "verify":
		var pub signify.PublicKey
		if pubKey == "" {
			if pubKeyFile != "" {
				b, err := ioutil.ReadFile(pubKeyFile)
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
			sig, err = ioutil.ReadAll(os.Stdin)
		} else {
			sig, err = ioutil.ReadFile(sigFile)
		}
		if err != nil {
			return fmt.Errorf("read signed message from %q: %w", sigFile, err)
		}
		out, ok := signify.Open(make([]byte, 0, len(sig)-64), sig, pub)
		if !ok {
			return fmt.Errorf("signature mismatch")
		}
		if msgFile == "" || msgFile == "-" {
			_, err = os.Stdout.Write(out)
		} else {
			err = ioutil.WriteFile(msgFile, out, 0640)
		}
		if err != nil {
			return fmt.Errorf("write message to %q: %w", msgFile, err)
		}
		return nil

	default:
		panic("unreachable")
	}

	return nil
}
