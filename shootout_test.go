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
		h.Write(m[l/4:l/2])
		h.Write(m[l/2:3*l/4])
		h.Write(m[3*l/4:])
		h.Sum(tag)
	}
}

func BenchmarkXCryptoSum_32(b *testing.B) {
	benchmarkSum(b, ref.Sum, 32)
}

func BenchmarkXCryptoSum_128(b *testing.B) {
	benchmarkSum(b, ref.Sum, 128)
}

func BenchmarkXCryptoSum_1k(b *testing.B) {
	benchmarkSum(b, ref.Sum, 1*1024)
}

func BenchmarkXCryptoSum_16k(b *testing.B) {
	benchmarkSum(b, ref.Sum, 16*1024)
}

func BenchmarkXCryptoSum_128k(b *testing.B) {
	benchmarkSum(b, ref.Sum, 128*1024)
}

func BenchmarkXCryptoSum_1M(b *testing.B) {
	benchmarkSum(b, ref.Sum, 1024*1024)
}

func benchmarkSumx64(b *testing.B, l int) {
	if useRef {
		b.Skip("skipping: do not have x64 implementation")
	}

	oldAVX, oldAVX2 := useAVX, useAVX2
	useAVX, useAVX2 = false, false
	defer func() {
		useAVX, useAVX2 = oldAVX, oldAVX2
	}()

	benchmarkSum(b, Sum, l)
}

func BenchmarkSumx64_32(b *testing.B) {
	benchmarkSumx64(b, 32)
}

func BenchmarkSumx64_128(b *testing.B) {
	benchmarkSumx64(b, 128)
}

func BenchmarkSumx64_1k(b *testing.B) {
	benchmarkSumx64(b, 1*1024)
}

func BenchmarkSumx64_16k(b *testing.B) {
	benchmarkSumx64(b, 16*1024)
}

func BenchmarkSumx64_128k(b *testing.B) {
	benchmarkSumx64(b, 128*1024)
}

func BenchmarkSumx64_1M(b *testing.B) {
	benchmarkSumx64(b, 1024*1024)
}

func benchmarkSumAVX(b *testing.B, l int) {
	if !useAVX {
		b.Skip("skipping: do not have AVX implementation")
	}

	oldAVX, oldAVX2 := useAVX, useAVX2
	useAVX, useAVX2 = true, false
	defer func() {
		useAVX, useAVX2 = oldAVX, oldAVX2
	}()

	benchmarkSum(b, Sum, l)
}

func BenchmarkSumAVX_32(b *testing.B) {
	benchmarkSumAVX(b, 32)
}

func BenchmarkSumAVX_128(b *testing.B) {
	benchmarkSumAVX(b, 128)
}

func BenchmarkSumAVX_1k(b *testing.B) {
	benchmarkSumAVX(b, 1*1024)
}

func BenchmarkSumAVX_16k(b *testing.B) {
	benchmarkSumAVX(b, 16*1024)
}

func BenchmarkSumAVX_128k(b *testing.B) {
	benchmarkSumAVX(b, 128*1024)
}

func BenchmarkSumAVX_1M(b *testing.B) {
	benchmarkSumAVX(b, 1024*1024)
}

func benchmarkSumAVX2(b *testing.B, l int) {
	if !useAVX2 {
		b.Skip("skipping: do not have AVX2 implementation")
	}

	oldAVX, oldAVX2 := useAVX, useAVX2
	useAVX, useAVX2 = false, true
	defer func() {
		useAVX, useAVX2 = oldAVX, oldAVX2
	}()

	benchmarkSum(b, Sum, l)
}

func BenchmarkSumAVX2_32(b *testing.B) {
	benchmarkSumAVX2(b, 32)
}

func BenchmarkSumAVX2_128(b *testing.B) {
	benchmarkSumAVX2(b, 128)
}

func BenchmarkSumAVX2_1k(b *testing.B) {
	benchmarkSumAVX2(b, 1*1024)
}

func BenchmarkSumAVX2_16k(b *testing.B) {
	benchmarkSumAVX2(b, 16*1024)
}

func BenchmarkSumAVX2_128k(b *testing.B) {
	benchmarkSumAVX2(b, 128*1024)
}

func BenchmarkSumAVX2_1M(b *testing.B) {
	benchmarkSumAVX2(b, 1024*1024)
}

func benchmarkNew(b *testing.B, l int) {
	var key [KeySize]byte
	h, err := New(key[:])
	if err != nil {
		b.Fatal(err)
	}

	benchmarkHash(b, h, l)
}

func benchmarkNewx64(b *testing.B, l int) {
	if useRef {
		b.Skip("skipping: do not have x64 implementation")
	}

	oldAVX, oldAVX2 := useAVX, useAVX2
	useAVX, useAVX2 = false, false
	defer func() {
		useAVX, useAVX2 = oldAVX, oldAVX2
	}()

	benchmarkNew(b, l)
}

func BenchmarkNewx64_32(b *testing.B) {
	benchmarkNewx64(b, 32)
}

func BenchmarkNewx64_128(b *testing.B) {
	benchmarkNewx64(b, 128)
}

func BenchmarkNewx64_1k(b *testing.B) {
	benchmarkNewx64(b, 1*1024)
}

func BenchmarkNewx64_16k(b *testing.B) {
	benchmarkNewx64(b, 16*1024)
}

func BenchmarkNewx64_128k(b *testing.B) {
	benchmarkNewx64(b, 128*1024)
}

func BenchmarkNewx64_1M(b *testing.B) {
	benchmarkNewx64(b, 1024*1024)
}

func benchmarkNewAVX(b *testing.B, l int) {
	if !useAVX {
		b.Skip("skipping: do not have AVX implementation")
	}

	oldAVX, oldAVX2 := useAVX, useAVX2
	useAVX, useAVX2 = true, false
	defer func() {
		useAVX, useAVX2 = oldAVX, oldAVX2
	}()

	benchmarkNew(b, l)
}

func BenchmarkNewAVX_32(b *testing.B) {
	benchmarkNewAVX(b, 32)
}

func BenchmarkNewAVX_128(b *testing.B) {
	benchmarkNewAVX(b, 128)
}

func BenchmarkNewAVX_1k(b *testing.B) {
	benchmarkNewAVX(b, 1*1024)
}

func BenchmarkNewAVX_16k(b *testing.B) {
	benchmarkNewAVX(b, 16*1024)
}

func BenchmarkNewAVX_128k(b *testing.B) {
	benchmarkNewAVX(b, 128*1024)
}

func BenchmarkNewAVX_1M(b *testing.B) {
	benchmarkNewAVX(b, 1024*1024)
}

func benchmarkNewAVX2(b *testing.B, l int) {
	if !useAVX2 {
		b.Skip("skipping: do not have AVX2 implementation")
	}

	oldAVX, oldAVX2 := useAVX, useAVX2
	useAVX, useAVX2 = false, true
	defer func() {
		useAVX, useAVX2 = oldAVX, oldAVX2
	}()

	benchmarkNew(b, l)
}

func BenchmarkNewAVX2_32(b *testing.B) {
	benchmarkNewAVX2(b, 32)
}

func BenchmarkNewAVX2_128(b *testing.B) {
	benchmarkNewAVX2(b, 128)
}

func BenchmarkNewAVX2_1k(b *testing.B) {
	benchmarkNewAVX2(b, 1*1024)
}

func BenchmarkNewAVX2_16k(b *testing.B) {
	benchmarkNewAVX2(b, 16*1024)
}

func BenchmarkNewAVX2_128k(b *testing.B) {
	benchmarkNewAVX2(b, 128*1024)
}

func BenchmarkNewAVX2_1M(b *testing.B) {
	benchmarkNewAVX2(b, 1024*1024)
}

func benchmarkHMAC(b *testing.B, fn func() hash.Hash, l int) {
	var key [KeySize]byte
	h := hmac.New(fn, key[:])

	benchmarkHash(b, h, l)
}

func BenchmarkHMAC_MD5_32(b *testing.B) {
	benchmarkHMAC(b, md5.New, 32)
}

func BenchmarkHMAC_MD5_128(b *testing.B) {
	benchmarkHMAC(b, md5.New, 128)
}

func BenchmarkHMAC_MD5_1k(b *testing.B) {
	benchmarkHMAC(b, md5.New, 1*1024)
}

func BenchmarkHMAC_MD5_16k(b *testing.B) {
	benchmarkHMAC(b, md5.New, 16*1024)
}

func BenchmarkHMAC_MD5_128k(b *testing.B) {
	benchmarkHMAC(b, md5.New, 128*1024)
}

func BenchmarkHMAC_MD5_1M(b *testing.B) {
	benchmarkHMAC(b, md5.New, 1024*1024)
}

func BenchmarkHMAC_SHA1_32(b *testing.B) {
	benchmarkHMAC(b, sha1.New, 32)
}

func BenchmarkHMAC_SHA1_128(b *testing.B) {
	benchmarkHMAC(b, sha1.New, 128)
}

func BenchmarkHMAC_SHA1_1k(b *testing.B) {
	benchmarkHMAC(b, sha1.New, 1*1024)
}

func BenchmarkHMAC_SHA1_16k(b *testing.B) {
	benchmarkHMAC(b, sha1.New, 16*1024)
}

func BenchmarkHMAC_SHA1_128k(b *testing.B) {
	benchmarkHMAC(b, sha1.New, 128*1024)
}

func BenchmarkHMAC_SHA1_1M(b *testing.B) {
	benchmarkHMAC(b, sha1.New, 1024*1024)
}

func BenchmarkHMAC_SHA256_32(b *testing.B) {
	benchmarkHMAC(b, sha256.New, 32)
}

func BenchmarkHMAC_SHA256_128(b *testing.B) {
	benchmarkHMAC(b, sha256.New, 128)
}

func BenchmarkHMAC_SHA256_1k(b *testing.B) {
	benchmarkHMAC(b, sha256.New, 1*1024)
}

func BenchmarkHMAC_SHA256_16k(b *testing.B) {
	benchmarkHMAC(b, sha256.New, 16*1024)
}

func BenchmarkHMAC_SHA256_128k(b *testing.B) {
	benchmarkHMAC(b, sha256.New, 128*1024)
}

func BenchmarkHMAC_SHA256_1M(b *testing.B) {
	benchmarkHMAC(b, sha256.New, 1024*1024)
}
