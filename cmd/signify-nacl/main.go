// Copyright 2020 Tamás Gulácsi.
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/UNO-SOFT/signify-nacl"
	"github.com/UNO-SOFT/zlog/v2"
)

var verbose zlog.VerboseVar
var logger = zlog.NewLogger(zlog.MaybeConsoleHandler(&verbose, os.Stderr)).SLog()

func main() {
	if err := Main(); err != nil {
		logger.Error("Main", "error", err)
		os.Exit(1)
	}
}

func Main() error {
	flag.Var(&verbose, "v", "verbose logging")
	flag.Usage = func() {
		nm := os.Args[0]
		fmt.Fprintf(flag.CommandLine.Output(), `Usage of %[1]s:

	%[1]s -G/generate/gen/g -p pubkey -s seckey
	%[1]s -S/sign/sig/s [-x sigfile] [-ascii] -s seckey -m message
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

	var ascii bool
	var msgFile, sigFile string
	var privKey, privKeyEnv string
	signFlags := flag.NewFlagSet("sign", flag.ContinueOnError)
	signFlags.StringVar(&privKeyFile, "s", "", "secret key file")
	signFlags.StringVar(&privKey, "S", "", "secret key")
	signFlags.StringVar(&privKeyEnv, "env", signify.DefaultPrivKeyEnv, "environment variable to read the private key from")
	signFlags.StringVar(&msgFile, "m", "-", "message file")
	signFlags.StringVar(&sigFile, "x", "-", "signed message file to write to")
	signFlags.BoolVar(&ascii, "ascii", false, "ascii-safe sign")

	var pubKey, pubKeyEnv string
	verifyFlags := flag.NewFlagSet("verify", flag.ContinueOnError)
	verifyFlags.StringVar(&pubKeyFile, "p", "", "public key file")
	verifyFlags.StringVar(&pubKey, "P", "", "public key")
	verifyFlags.StringVar(&pubKeyEnv, "env", signify.DefaultPubKeyEnv, "environment variable to read the public key from")
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
		return signify.GenerateKeyFiles(pubKeyFile, privKeyFile)

	case "sign":
		return signify.SignFile(privKey, privKeyFile, privKeyEnv, sigFile, msgFile)

	case "verify":
		return signify.VerifyFile(pubKey, pubKeyFile, pubKeyEnv, sigFile, msgFile)

	default:
		panic("unreachable")
	}
}
