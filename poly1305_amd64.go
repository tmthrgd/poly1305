// Copyright 2016 Tom Thorogood. All rights reserved.
// Use of this source code is governed by a
// Modified BSD License license that can be found in
// the LICENSE file.

// +build amd64,!gccgo,!appengine

package poly1305

import (
	"crypto/subtle"
	"hash"

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

// New returns a new Poly1305 hash using the given key.
func New(key []byte) (hash.Hash, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKey
	}

	if !useAVX && !useAVX2 {
		return newRef(key)
	}

	h := new(avxHash)
	copy(h.key[:], key)
	h.Reset()
	return h, nil
}

type avxHash struct {
	key [KeySize]byte
	state poly1305_state

	buffer  [128]byte
	bufUsed int
}

func (h *avxHash) Write(p []byte) (n int, err error) {
	n = len(p)

	if n < 128 || h.bufUsed != 0 {
		i := copy(h.buffer[h.bufUsed:], p)
		h.bufUsed += i
		p = p[i:]

		if h.bufUsed == 128 {
			h.write(h.buffer[:])
			h.bufUsed = 0
		}
	}

	if len(p) >= 128 {
		h.write(p[:len(p) & -128])
		p = p[len(p) & -128:]
	}

	if len(p) != 0 {
		h.bufUsed = copy(h.buffer[:], p)
	}

	return
}

func (h *avxHash) write(p []byte) {
	var pPtr *byte
	if len(p) != 0 {
		pPtr = &p[0]
	}

	if useAVX2 {
		poly1305_update_avx2(&h.state, pPtr, uint64(len(p)))
	} else {
		poly1305_update_avx(&h.state, pPtr, uint64(len(p)))
	}
}

func (h *avxHash) Sum(b []byte) []byte {
	h2 := *h
	return h2.sum(b)
}

func (h *avxHash) sum(b []byte) []byte {
	if h.bufUsed != 0 {
		h.write(h.buffer[:h.bufUsed])
	}

	var tag [TagSize]byte

	if useAVX2 {
		poly1305_finish_avx2(&h.state, &tag)
	} else {
		poly1305_finish_avx(&h.state, &tag)
	}

	ret, out := sliceForAppend(b, TagSize)
	copy(out, tag[:])
	return ret
}

func (h *avxHash) Reset() {
	for i := 0; i < h.bufUsed; i++ {
		h.buffer[i] = 0
	}

	h.bufUsed = 0

	if useAVX2 {
		poly1305_init_avx2(&h.state, &h.key)
	} else {
		poly1305_init_avx(&h.state, &h.key)
	}
}

func (h *avxHash) Size() int {
	return TagSize
}

func (h *avxHash) BlockSize() int {
	return 128
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
