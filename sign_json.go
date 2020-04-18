// Copyright 2020 Tamás Gulácsi.
//
// SPDX-License-Identifier: Apache-2.0

package signify

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"unicode"
)

const naclSig = `,"naclSig":"`

// JSONOverhead is the size of `"naclSig":"tzCU4IasEj9jYNAMEY1YxM1bHAZoSSH/PHQL2mLLsCDD8QCW17g8wDGVBmZQn8lwulhHU0aRYOnZ11D9dwcuAQ=="}`
const JSONOverhead = 102

// SignJSON signs the given SERIALIZED JSON following
// https://perkeep.org/doc/json-signing/#signing
//
// O == the object to be signed
// J == any valid JSON serialization of O
// T == J, with 0+ trailing whitespace removed, and then 1 '}' character removed
// S == ascii-armored detached signature of T
// C == CONCAT(T, ',"naclSig":"', S, '"}', '\n')
func (pk PrivateKey) SignJSON(out, J []byte) []byte {
	T := bytes.TrimSuffix(bytes.TrimRightFunc(J, unicode.IsSpace), []byte{'}'})
	out = append(append(out, T...), naclSig...)
	sig := pk.SignDetached(T)
	n := base64.StdEncoding.EncodedLen(len(sig))
	out = append(out, make([]byte, n)...)
	base64.StdEncoding.Encode(out[len(out)-n:], sig)
	return append(out, '"', '}', '\n')
}

var (
	// ErrMismatch is the error for signature mismatch in verification.
	ErrMismatch = errors.New("signature mismatch")
	// BadFormat is returned when the formatting is uncomprehensible.
	BadFormat = errors.New("bad format")
)

// VerifyJSON verifies the given signed JSON and returns the payload
// following https://perkeep.org/doc/json-signing/#verifying
//
// Start with a byte array representing the JSON to be verified. call this ‘BA’ (“bytes all”)
//
// given the byte array, find the last index in ‘BA’ of the 12 byte substring:
//
//      ,"naclSig":"
//
// Let’s call the bytes before that ‘BP’ (“bytes payload”) and the bytes starting at that substring ‘BS’ (“bytes signature”)
//
// define ‘BPJ’ (“bytes payload JSON”) as ‘BP’ + the single byte ‘}’.
//
// replace the first byte of ‘BS’ (the ‘,’) with an open brace (‘{’) and parse it as JSON. verify that it’s a valid JSON object with exactly one key: “naclSig”
//
// verify that the ASCII-armored NaCL signature in “naclSig” signs the bytes in ‘BP’
func (pk PublicKey) VerifyJSON(out, BA []byte) ([]byte, error) {
	i := bytes.LastIndex(BA, []byte(naclSig))
	if i < 0 {
		return BA, fmt.Errorf("no %q: %w", naclSig, BadFormat)
	}
	type Signature struct {
		Sig []byte `json:"naclSig"`
	}
	BP, BS := BA[:i], BA[i:]
	BS[0] = '{'
	var their Signature
	err := json.Unmarshal(BS, &their)
	if err != nil {
		return nil, fmt.Errorf("%v: %w", err, BadFormat)
	} else if len(their.Sig) == 0 {
		return nil, fmt.Errorf("empty sig from %q: %w", string(BS), BadFormat)
	}
	BS[0] = ','
	out = append(append(out, BP...), '}')
	if pk.VerifyDetached(BP, their.Sig) {
		return out, nil
	}
	return out, fmt.Errorf("signature of %q is not %q: %w", string(BP), their.Sig, ErrMismatch)
}
