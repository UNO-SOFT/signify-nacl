// Copyright 2020, 2022 Tamás Gulácsi.
//
// SPDX-License-Identifier: Apache-2.0

// Package signify contains some helper functions for using golang.org/x/crypto/nacl/sign,
// and to encode/decode the private and public keys.
package signify

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/nacl/sign"
)

const (
	//NaCLPublicPrefix is the prefix for public keys.
	NaCLPublicPrefix = "nacl"
	// NaCLPrivatePreifx is the prefix for private keys.
	NaCLPrivatePrefix = "NACL-SECRET-KEY-"
	// Overhead bytes is the size of the signature
	Overhead = sign.Overhead
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

func (pk PrivateKey) Sign(out, message []byte) []byte {
	return Sign(out, message, pk)
}

// SignDetached returns only the signature of the message.
func (pk PrivateKey) SignDetached(message []byte) (sig []byte) {
	return ed25519.Sign(ed25519.PrivateKey(pk[:]), message)
}

func (pk PublicKey) Open(out, message []byte) ([]byte, bool) {
	return Open(out, message, pk)
}

// VerifyDetached verifies the message and the signature.
func (pk PublicKey) VerifyDetached(message, sig []byte) bool {
	return ed25519.Verify(ed25519.PublicKey(pk[:]), message, sig)
}
