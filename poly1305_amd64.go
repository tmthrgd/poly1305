// Copyright 2016 Tom Thorogood. All rights reserved.
// Use of this source code is governed by a
// Modified BSD License license that can be found in
// the LICENSE file.

// +build amd64,!gccgo,!appengine

package poly1305

import (
	"crypto/subtle"

	ref "golang.org/x/crypto/poly1305"
)

var useAVX, useAVX2 = hasAVX()

type poly1305_state [512]byte

// Sum generates an authenticator for m using a one-time key and puts the
// 16-byte result into out. Authenticating two different messages with the same
// key allows an attacker to forge messages at will.
func Sum(out *[TagSize]byte, m []byte, key *[KeySize]byte) {
	var mPtr *byte
	if len(m) != 0 {
		mPtr = &m[0]
	}

	switch {
	case useAVX2:
		var state poly1305_state
		poly1305_init_avx2(&state, key)
		poly1305_update_avx2(&state, mPtr, uint64(len(m)))
		poly1305_finish_avx2(&state, out)
	case useAVX:
		var state poly1305_state
		poly1305_init_avx(&state, key)
		poly1305_update_avx(&state, mPtr, uint64(len(m)))
		poly1305_finish_avx(&state, out)
	default:
		ref.Sum(out, m, key)
	}
}

// Verify returns true if mac is a valid authenticator for m with the given
// key.
func Verify(mac *[TagSize]byte, m []byte, key *[KeySize]byte) bool {
	var tmp [TagSize]byte
	Sum(&tmp, m, key)
	return subtle.ConstantTimeCompare(tmp[:], mac[:]) == 1
}

//go:generate perl poly1305_avx.pl golang-no-avx poly1305_avx_amd64.s
//go:generate perl poly1305_avx2.pl golang-no-avx poly1305_avx2_amd64.s

// This function is implemented in avx_amd64.s
//go:noescape
func hasAVX() (avx, avx2 bool)

// This function is implemented in poly1305_avx_amd64.s
//go:noescape
func poly1305_init_avx(state *poly1305_state, key *[32]byte)

// This function is implemented in poly1305_avx_amd64.s
//go:noescape
func poly1305_update_avx(state *poly1305_state, in *byte, in_len uint64)

// This function is implemented in poly1305_avx_amd64.s
//go:noescape
func poly1305_finish_avx(state *poly1305_state, mac *[16]byte)

// This function is implemented in poly1305_avx2_amd64.s
//go:noescape
func poly1305_init_avx2(state *poly1305_state, key *[32]byte)

// This function is implemented in poly1305_avx2_amd64.s
//go:noescape
func poly1305_update_avx2(state *poly1305_state, in *byte, in_len uint64)

// This function is implemented in poly1305_avx2_amd64.s
//go:noescape
func poly1305_finish_avx2(state *poly1305_state, mac *[16]byte)
