// Copyright 2014 Coda Hale. All rights reserved.
// Use of this source code is governed by an MIT
// License that can be found in the LICENSE file.
//
// Copyright 2016 Tom Thorogood. All rights reserved.
// Use of this source code is governed by a
// Modified BSD License license that can be found in
// the LICENSE file.

package poly1305

import (
	"bytes"
	"math/rand"
	"reflect"
	"testing"
	"testing/quick"

	ref "golang.org/x/crypto/poly1305"
)

// stolen from https://github.com/golang/crypto/blob/master/poly1305/poly1305_test.go
var testData = []struct {
	in, k, correct []byte
}{
	{
		[]byte("Hello world!"),
		[]byte("this is 32-byte key for Poly1305"),
		[]byte{0xa6, 0xf7, 0x45, 0x00, 0x8f, 0x81, 0xc9, 0x16, 0xa2, 0x0d, 0xcc, 0x74, 0xee, 0xf2, 0xb2, 0xf0},
	},
	{
		make([]byte, 32),
		[]byte("this is 32-byte key for Poly1305"),
		[]byte{0x49, 0xec, 0x78, 0x09, 0x0e, 0x48, 0x1e, 0xc6, 0xc2, 0x6b, 0x33, 0xb9, 0x1c, 0xcc, 0x03, 0x07},
	},
	{
		make([]byte, 2007),
		[]byte("this is 32-byte key for Poly1305"),
		[]byte{0xda, 0x84, 0xbc, 0xab, 0x02, 0x67, 0x6c, 0x38, 0xcd, 0xb0, 0x15, 0x60, 0x42, 0x74, 0xc2, 0xaa},
	},
	{
		make([]byte, 2007),
		make([]byte, 32),
		make([]byte, 16),
	},
}

func testSum(t *testing.T) {
	var tag [TagSize]byte
	var key [KeySize]byte

	for i, vector := range testData {
		t.Logf("Running test vector %d", i)

		copy(key[:], vector.k)

		Sum(&tag, vector.in, &key)

		if !bytes.Equal(tag[:], vector.correct) {
			t.Errorf("%d: expected %x, got %x", i, vector.correct, tag[:])
		}
	}
}

func TestSumx64(t *testing.T) {
	if useRef {
		t.Skip("skipping: do not have x64 implementation")
	}

	oldAVX, oldAVX2 := useAVX, useAVX2
	useAVX, useAVX2 = false, false
	defer func() {
		useAVX, useAVX2 = oldAVX, oldAVX2
	}()

	testSum(t)
}

func TestSumAVX(t *testing.T) {
	if !useAVX {
		t.Skip("skipping: do not have AVX implementation")
	}

	oldAVX, oldAVX2 := useAVX, useAVX2
	useAVX, useAVX2 = true, false
	defer func() {
		useAVX, useAVX2 = oldAVX, oldAVX2
	}()

	testSum(t)
}

func TestSumAVX2(t *testing.T) {
	if !useAVX2 {
		t.Skip("skipping: do not have AVX2 implementation")
	}

	oldAVX, oldAVX2 := useAVX, useAVX2
	useAVX, useAVX2 = false, true
	defer func() {
		useAVX, useAVX2 = oldAVX, oldAVX2
	}()

	testSum(t)
}

func TestSumRef(t *testing.T) {
	if !useRef {
		t.Skip("skipping: not using reference implementation")
	}

	testSum(t)
}

func testNew(t *testing.T) {
	for i, vector := range testData {
		t.Logf("Running test vector %d", i)

		h, err := New(vector.k)
		if err != nil {
			t.Error(err)
		}

		h.Write(vector.in[:1])
		h.Write(vector.in[1:])

		tag := h.Sum(nil)

		if !bytes.Equal(tag, vector.correct) {
			t.Errorf("%d: expected %x, got %x", i, vector.correct, tag)
		}
	}
}

func TestNewx64(t *testing.T) {
	if useRef {
		t.Skip("skipping: do not have x64 implementation")
	}

	oldAVX, oldAVX2 := useAVX, useAVX2
	useAVX, useAVX2 = false, false
	defer func() {
		useAVX, useAVX2 = oldAVX, oldAVX2
	}()

	testNew(t)
}

func TestNewAVX(t *testing.T) {
	if !useAVX {
		t.Skip("skipping: do not have AVX implementation")
	}

	oldAVX, oldAVX2 := useAVX, useAVX2
	useAVX, useAVX2 = true, false
	defer func() {
		useAVX, useAVX2 = oldAVX, oldAVX2
	}()

	testNew(t)
}

func TestNewAVX2(t *testing.T) {
	if !useAVX2 {
		t.Skip("skipping: do not have AVX2 implementation")
	}

	oldAVX, oldAVX2 := useAVX, useAVX2
	useAVX, useAVX2 = false, true
	defer func() {
		useAVX, useAVX2 = oldAVX, oldAVX2
	}()

	testNew(t)
}

func TestNewRef(t *testing.T) {
	if !useRef {
		t.Skip("skipping: not using reference implementation")
	}

	testNew(t)
}

func TestEqual(t *testing.T) {
	t.Parallel()

	if useRef {
		t.Skip("skipping: using reference implementation already")
	}

	if err := quick.CheckEqual(func(key *[KeySize]byte, m []byte) [TagSize]byte {
		var tag [TagSize]byte
		ref.Sum(&tag, m, key)
		return tag
	}, func(key *[KeySize]byte, m []byte) [TagSize]byte {
		var tag [TagSize]byte
		Sum(&tag, m, key)
		return tag
	}, &quick.Config{
		Values: func(args []reflect.Value, rand *rand.Rand) {
			var key [KeySize]byte
			rand.Read(key[:])
			args[0] = reflect.ValueOf(&key)

			m := make([]byte, 1+rand.Intn(1024*1024))
			rand.Read(m)
			args[1] = reflect.ValueOf(m)
		},
	}); err != nil {
		t.Error(err)
	}
}

func TestEqualSumNew(t *testing.T) {
	t.Parallel()

	if err := quick.CheckEqual(func(key *[KeySize]byte, m []byte) []byte {
		var tag [TagSize]byte
		Sum(&tag, m, key)
		return tag[:]
	}, func(key *[KeySize]byte, m []byte) []byte {
		hash, err := New(key[:])
		if err != nil {
			panic(err)
		}

		hash.Write(m[:1])
		hash.Write(m[1:])
		return hash.Sum(nil)
	}, &quick.Config{
		Values: func(args []reflect.Value, rand *rand.Rand) {
			var key [KeySize]byte
			rand.Read(key[:])
			args[0] = reflect.ValueOf(&key)

			m := make([]byte, 1+rand.Intn(1024*1024))
			rand.Read(m)
			args[1] = reflect.ValueOf(m)
		},
	}); err != nil {
		t.Error(err)
	}
}
