// Copyright 2014 Coda Hale. All rights reserved.
// Use of this source code is governed by an MIT
// License that can be found in the LICENSE file.

package poly1305

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"hash"
	"testing"

	ref "golang.org/x/crypto/poly1305"
)

const benchSize = 1024 * 1024

func benchmarkSum(b *testing.B, sum func(mac *[TagSize]byte, m []byte, key *[KeySize]byte)) {
	b.SetBytes(benchSize)

	var mac [TagSize]byte
	m := make([]byte, benchSize)
	var key [KeySize]byte

	for i := 0; i < b.N; i++ {
		sum(&mac, m, &key)
	}
}

func benchmarkHash(b *testing.B, h hash.Hash) {
	b.SetBytes(benchSize)

	m := make([]byte, benchSize)
	tag := make([]byte, 0, h.Size())

	for i := 0; i < b.N; i++ {
		h.Reset()

		h.Write(m)
		h.Sum(tag)
	}
}

func BenchmarkXCryptoSum(b *testing.B) {
	benchmarkSum(b, ref.Sum)
}

func BenchmarkSum(b *testing.B) {
	benchmarkSum(b, Sum)
}

func BenchmarkNew(b *testing.B) {
	var key [KeySize]byte
	h, err := New(key[:])
	if err != nil {
		b.Fatal(err)
	}

	benchmarkHash(b, h)
}

func BenchmarkHMACMD5(b *testing.B) {
	var key [KeySize]byte
	h := hmac.New(md5.New, key[:])

	benchmarkHash(b, h)
}

func BenchmarkHMACSHA1(b *testing.B) {
	var key [KeySize]byte
	h := hmac.New(sha1.New, key[:])

	benchmarkHash(b, h)
}

func BenchmarkHMACSHA256(b *testing.B) {
	var key [KeySize]byte
	h := hmac.New(sha256.New, key[:])

	benchmarkHash(b, h)
}
