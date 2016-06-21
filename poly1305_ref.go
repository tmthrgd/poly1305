// Copyright 2016 Tom Thorogood. All rights reserved.
// Use of this source code is governed by a
// Modified BSD License license that can be found in
// the LICENSE file.

// +build !amd64 gccgo appengine

package poly1305

import ref "golang.org/x/crypto/poly1305"

const useAVX, useAVX2 = false, false

// Sum generates an authenticator for m using a one-time key and puts the
// 16-byte result into out. Authenticating two different messages with the same
// key allows an attacker to forge messages at will.
func Sum(out *[TagSize]byte, m []byte, key *[KeySize]byte) {
	ref.Sum(out, m, key)
}

// Verify returns true if mac is a valid authenticator for m with the given
// key.
func Verify(mac *[TagSize]byte, m []byte, key *[KeySize]byte) bool {
	return ref.Verify(mac, m, key)
}

// New returns a new Poly1305 hash using the given key. Authenticating two
// different messages with the same key allows an attacker to forge messages
// at will.
func New(key []byte) (hash.Hash, error) {
	return newRef(key)
}
