// Copyright 2016 Tom Thorogood. All rights reserved.
// Use of this source code is governed by a
// Modified BSD License license that can be found in
// the LICENSE file.

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

const (
	// KeySize is the length of Poly1305 keys, in bytes.
	KeySize = 32

	// TagSize is the length of Poly1305 tags, in bytes.
	TagSize = 16
)
