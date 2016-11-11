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

type size struct {
	name string
	l    int
}

var sizes = []size{
	{"32", 32},
	{"128", 128},
	{"1K", 1 * 1024},
	{"16K", 16 * 1024},
	{"128K", 128 * 1024},
	{"1M", 1024 * 1024},
}

func benchmarkSum(b *testing.B, sum func(mac *[TagSize]byte, m []byte, key *[KeySize]byte), l int) {
	var mac [TagSize]byte
	m := make([]byte, l)
	var key [KeySize]byte

	b.SetBytes(int64(l))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		sum(&mac, m, &key)
	}
}

func benchmarkHash(b *testing.B, h hash.Hash, l int) {
	m := make([]byte, l)
	tag := make([]byte, 0, h.Size())

	b.SetBytes(int64(l))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		h.Reset()

		h.Write(m[:l/4])
		h.Write(m[l/4 : l/2])
		h.Write(m[l/2 : 3*l/4])
		h.Write(m[3*l/4:])
		h.Sum(tag)
	}
}

func BenchmarkXCryptoSum(b *testing.B) {
	for _, size := range sizes {
		b.Run(size.name, func(b *testing.B) {
			benchmarkSum(b, ref.Sum, size.l)
		})
	}
}

func BenchmarkSumx64(b *testing.B) {
	if useRef {
		b.Skip("skipping: do not have x64 implementation")
	}

	oldAVX, oldAVX2 := useAVX, useAVX2
	useAVX, useAVX2 = false, false
	defer func() {
		useAVX, useAVX2 = oldAVX, oldAVX2
	}()

	for _, size := range sizes {
		b.Run(size.name, func(b *testing.B) {
			benchmarkSum(b, Sum, size.l)
		})
	}
}

func BenchmarkSumAVX(b *testing.B) {
	if !useAVX {
		b.Skip("skipping: do not have AVX implementation")
	}

	oldAVX, oldAVX2 := useAVX, useAVX2
	useAVX, useAVX2 = true, false
	defer func() {
		useAVX, useAVX2 = oldAVX, oldAVX2
	}()

	for _, size := range sizes {
		b.Run(size.name, func(b *testing.B) {
			benchmarkSum(b, Sum, size.l)
		})
	}
}

func BenchmarkSumAVX2(b *testing.B) {
	if !useAVX2 {
		b.Skip("skipping: do not have AVX2 implementation")
	}

	oldAVX, oldAVX2 := useAVX, useAVX2
	useAVX, useAVX2 = false, true
	defer func() {
		useAVX, useAVX2 = oldAVX, oldAVX2
	}()

	for _, size := range sizes {
		b.Run(size.name, func(b *testing.B) {
			benchmarkSum(b, Sum, size.l)
		})
	}
}

func benchmarkNew(b *testing.B, l int) {
	var key [KeySize]byte
	h, err := New(key[:])
	if err != nil {
		b.Fatal(err)
	}

	benchmarkHash(b, h, l)
}

func BenchmarkNewx64(b *testing.B) {
	if useRef {
		b.Skip("skipping: do not have x64 implementation")
	}

	oldAVX, oldAVX2 := useAVX, useAVX2
	useAVX, useAVX2 = false, false
	defer func() {
		useAVX, useAVX2 = oldAVX, oldAVX2
	}()

	for _, size := range sizes {
		b.Run(size.name, func(b *testing.B) {
			benchmarkNew(b, size.l)
		})
	}
}

func BenchmarkNewAVX(b *testing.B) {
	if !useAVX {
		b.Skip("skipping: do not have AVX implementation")
	}

	oldAVX, oldAVX2 := useAVX, useAVX2
	useAVX, useAVX2 = true, false
	defer func() {
		useAVX, useAVX2 = oldAVX, oldAVX2
	}()

	for _, size := range sizes {
		b.Run(size.name, func(b *testing.B) {
			benchmarkNew(b, size.l)
		})
	}
}

func BenchmarkNewAVX2(b *testing.B) {
	if !useAVX2 {
		b.Skip("skipping: do not have AVX2 implementation")
	}

	oldAVX, oldAVX2 := useAVX, useAVX2
	useAVX, useAVX2 = false, true
	defer func() {
		useAVX, useAVX2 = oldAVX, oldAVX2
	}()

	for _, size := range sizes {
		b.Run(size.name, func(b *testing.B) {
			benchmarkNew(b, size.l)
		})
	}
}

func benchmarkHMAC(b *testing.B, fn func() hash.Hash) {
	for _, size := range sizes {
		b.Run(size.name, func(b *testing.B) {
			var key [KeySize]byte
			h := hmac.New(fn, key[:])

			benchmarkHash(b, h, size.l)
		})
	}
}

func BenchmarkHMAC_MD5(b *testing.B) {
	benchmarkHMAC(b, md5.New)
}

func BenchmarkHMAC_SHA1(b *testing.B) {
	benchmarkHMAC(b, sha1.New)
}

func BenchmarkHMAC_SHA256(b *testing.B) {
	benchmarkHMAC(b, sha256.New)
}
