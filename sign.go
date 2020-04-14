// Copyright 2020 Tamás Gulácsi.
//
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.

// Package signify contains some helper functions for using golang.org/x/crypto/nacl/sign,
// and to encode/decode the private and public keys.
package signify

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/nacl/sign"
)

const (
	//NaCLPublicPrefix is the prefix for public keys.
	NaCLPublicPrefix = "nacl"
	// NaCLPrivatePreifx is the prefix for private keys.
	NaCLPrivatePrefix = "NACL-SECRET-KEY-"
)

// PublicKey is the public key bytes.
type PublicKey [32]byte

func (pk PublicKey) Prefix() string        { return NaCLPublicPrefix }
func (pk PublicKey) String() string        { return encodeKey(pk.Prefix(), pk[:]) }
func (pk *PublicKey) Parse(s string) error { return decodeKey(pk[:], pk.Prefix(), s) }

// PrivateKey is the private key bytes.
type PrivateKey [64]byte

func (pk PrivateKey) Prefix() string        { return NaCLPrivatePrefix }
func (pk PrivateKey) String() string        { return encodeKey(pk.Prefix(), pk[:]) }
func (pk *PrivateKey) Parse(s string) error { return decodeKey(pk[:], pk.Prefix(), s) }

func encodeKey(prefix string, key []byte) string {
	n := base64.StdEncoding.EncodedLen(len(key))
	p := make([]byte, len(prefix)+n)
	copy(p, prefix)
	base64.StdEncoding.Encode(p[len(prefix):], key)
	return string(p)
}

var (
	ErrBadPrefix = errors.New("bad prefix")
	ErrBadLength = errors.New("length mismatch")
)

func decodeKey(dst []byte, prefix, s string) error {
	if !strings.HasPrefix(s, prefix) {
		return fmt.Errorf("got %q wanted %q: %w", s, prefix, ErrBadPrefix)
	}
	s = s[len(prefix):]
	if n, err := base64.StdEncoding.Decode(dst, []byte(s)); err != nil {
		return err
	} else if n != len(dst) {
		return fmt.Errorf("got %d wanted %d: %w", n, len(dst), ErrBadLength)
	}
	return nil
}

// GenerateKey generates a keypair.
func GenerateKey() (PublicKey, PrivateKey, error) {
	pubKey, privKey, err := sign.GenerateKey(rand.Reader)
	if err != nil {
		return PublicKey{}, PrivateKey{}, err
	}
	return PublicKey(*pubKey), PrivateKey(*privKey), nil
}

// Open the signedMessage, appending the message to out.
func Open(out, signedMessage []byte, publicKey PublicKey) (message []byte, ok bool) {
	return sign.Open(out, signedMessage, (*[32]byte)(&publicKey))

}

// Sign the message with the given private key, return the signed message appended to out.
func Sign(out, message []byte, privateKey PrivateKey) []byte {
	return sign.Sign(out, message, (*[64]byte)(&privateKey))
}
