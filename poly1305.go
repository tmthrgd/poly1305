// Copyright 2016 Tom Thorogood. All rights reserved.
// Use of this source code is governed by a
// Modified BSD License license that can be found in
// the LICENSE file.
//
// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package poly1305 implements Poly1305 one-time message authentication code as specified in http://cr.yp.to/mac/poly1305-20050329.pdf.
//
// Poly1305 is a fast, one-time authentication function. It is infeasible for an
// attacker to generate an authenticator for a message without the key. However, a
// key must only be used for a single message. Authenticating two different
// messages with the same key allows an attacker to forge authenticators for other
// messages with the same key.
//
// Poly1305 was originally coupled with AES in order to make Poly1305-AES. AES was
// used with a fixed key in order to generate one-time keys from an nonce.
// However, in this package AES isn't used and the one-time key is specified
// directly.
package poly1305

import (
	"bytes"
	"errors"
	"hash"
)

const (
	// KeySize is the length of Poly1305 keys, in bytes.
	KeySize = 32

	// TagSize is the length of Poly1305 tags, in bytes.
	TagSize = 16
)

var (
	// ErrInvalidKey is returned when the provided key is not KeySize bytes long.
	ErrInvalidKey = errors.New("invalid key length")
)

func newRef(key []byte) (hash.Hash, error) {
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

// sliceForAppend takes a slice and a requested number of bytes. It returns a
// slice with the contents of the given slice followed by that many bytes and a
// second slice that aliases into it and contains only the extra bytes. If the
// original slice has sufficient capacity then no allocation is performed.
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}

	tail = head[len(in):]
	return
}
