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

func BenchmarkXCryptoSum(b *testing.B) {
	benchmarkSum(b, ref.Sum)
}

func BenchmarkSum(b *testing.B) {
	benchmarkSum(b, Sum)
}

func benchmarkHMAC(b *testing.B, h func() hash.Hash) {
	b.SetBytes(benchSize)

	var key [KeySize]byte
	mac := hmac.New(h, key[:])
	m := make([]byte, benchSize)
	tag := make([]byte, mac.Size())

	for i := 0; i < b.N; i++ {
		mac.Reset()

		mac.Write(m)
		mac.Sum(tag)
	}
}

func BenchmarkHMACMD5(b *testing.B) {
	benchmarkHMAC(b, md5.New)
}

func BenchmarkHMACSHA1(b *testing.B) {
	benchmarkHMAC(b, sha1.New)
}

func BenchmarkHMACSHA256(b *testing.B) {
	benchmarkHMAC(b, sha256.New)
}
