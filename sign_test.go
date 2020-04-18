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

	t.Run("parseKey", func(t *testing.T) {
		t.Parallel()
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
	})

	t.Run("sign", func(t *testing.T) {
		t.Parallel()
		const message = `árvíztűrő tükörfúrógép`
		signedMessage := signify.Sign(make([]byte, 0, len(message)+64), []byte(message), privKey)
		t.Logf("% x %q", signedMessage[:64], signedMessage[64:])
		msg, ok := signify.Open(make([]byte, 0, len(message)), signedMessage, pubKey)
		if !ok {
			t.Fatal("not ok")
		}
		if !bytes.Equal(msg, []byte(message)) {
			t.Errorf("signature mismatch: got %q wanted %q", string(msg), message)
		}
	})

	t.Run("json", func(t *testing.T) {
		t.Parallel()
		const testJSON = `{"msg":"árvíztűrő tükörfúrógép", "num":1.32}`
		signed := privKey.SignJSON(
			make([]byte, 0, len(testJSON)+signify.JSONOverhead),
			[]byte(testJSON))
		t.Log("signed:", string(signed))

		got, err := pubKey.VerifyJSON(make([]byte, 0, len(testJSON)), signed)
		if err != nil {
			t.Error(err)
		}
		if !bytes.Equal(got, []byte(testJSON)) {
			t.Errorf("got\n%q, \nwanted\n%q", string(got), testJSON)
		}
	})
}
