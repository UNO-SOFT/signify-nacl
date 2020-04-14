// Copyright 2020 Tamás Gulácsi.
//
// SPDX-License-Identifier: Apache-2.0

package signify_test

import (
	"bytes"
	"testing"

	"github.com/UNO-SOFT/signify-nacl"
)

func TestVerifySignatureNaCL(t *testing.T) {
	pubKey, privKey, err := signify.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("pub: %s", pubKey)
	t.Logf("sec: %s", privKey)

	var recip signify.PublicKey
	if err = recip.Parse(pubKey.String()); err != nil {
		t.Fatal(err)
	}
	if recip != pubKey {
		t.Fatalf("got %s wanted %s", recip, pubKey)
	}
	var ident signify.PrivateKey
	if err = ident.Parse(privKey.String()); err != nil {
		t.Fatal(err)
	}
	if ident != privKey {
		t.Fatalf("got %s wanted %s", ident, privKey)
	}

	const message = `árvíztűrő tükörfúrógép`
	signedMessage := signify.Sign(make([]byte, 0, len(message)+64), []byte(message), ident)
	t.Logf("% x %q", signedMessage[:64], signedMessage[64:])
	msg, ok := signify.Open(make([]byte, 0, len(message)), signedMessage, recip)
	if !ok {
		t.Fatal("not ok")
	}
	if !bytes.Equal(msg, []byte(message)) {
		t.Errorf("signature mismatch: got %q wanted %q", string(msg), message)
	}
}
