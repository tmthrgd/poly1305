// Copyright 2016 Tom Thorogood. All rights reserved.
// Use of this source code is governed by a
// Modified BSD License license that can be found in
// the LICENSE file.

// +build !amd64 gccgo appengine

package poly1305

import (
	"bytes"
	"hash"

	ref "golang.org/x/crypto/poly1305"
)

const useRef = true

var useAVX, useAVX2 = false, false

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
	if len(key) != KeySize {
		return nil, ErrInvalidKey
	}

	h := new(refHash)
	copy(h.key[:], key)
	return h, nil
}

type refHash struct {
	key [KeySize]byte

	buffer bytes.Buffer
}

func (h *refHash) Grow(n int) {
	h.buffer.Grow(n)
}

func (h *refHash) GetBuffer() interface{} {
	buf := h.buffer
	return &buf
}

func (h *refHash) SetBuffer(buf interface{}) {
	if buf == nil || h.buffer.Len() != 0 {
		return
	}

	h.buffer = *buf.(*bytes.Buffer)
	h.buffer.Reset()
}

func (h *refHash) Write(p []byte) (n int, err error) {
	return h.buffer.Write(p)
}

func (h *refHash) Sum(b []byte) []byte {
	var tag [TagSize]byte
	Sum(&tag, h.buffer.Bytes(), &h.key)

	ret, out := sliceForAppend(b, TagSize)
	copy(out, tag[:])
	return ret
}

func (h *refHash) Reset() {
	h.buffer.Reset()
}

func (h *refHash) Size() int {
	return TagSize
}

func (h *refHash) BlockSize() int {
	return 16
}
