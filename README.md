# poly1305

[![GoDoc](https://godoc.org/github.com/tmthrgd/poly1305?status.svg)](https://godoc.org/github.com/tmthrgd/poly1305)
[![Build Status](https://travis-ci.org/tmthrgd/poly1305.svg?branch=master)](https://travis-ci.org/tmthrgd/poly1305)

An AVX/AVX2 implementation of the Poly1305 MAC for Golang.

The AVX and AVX2 Poly1305 implementations were taken from
[cloudflare/sslconfig](https://github.com/cloudflare/sslconfig/blob/master/patches/openssl__chacha20_poly1305_cf.patch).

For systems with neither AVX nor AVX2, it falls back to
[golang.org/x/crypto/poly1305](https://godoc.org/golang.org/x/crypto/poly1305).

## Benchmark

```
BenchmarkXCryptoSum-8	    2000	    709006 ns/op	1478.94 MB/s	[golang.org/x/crypto/poly1305]
BenchmarkSum-8       	    5000	    365036 ns/op	2872.53 MB/s	[tmthrgd/poly1305 - AVX only]
BenchmarkNew-8       	    5000	    364626 ns/op	2875.76 MB/s	[tmthrgd/poly1305 - AVX only]
BenchmarkHMACMD5-8   	    1000	   1481835 ns/op	 707.62 MB/s	[crypto/hmac crypto/md5]
BenchmarkHMACSHA1-8  	    1000	   2253576 ns/op	 465.29 MB/s	[crypto/hmac crypto/sha1]
BenchmarkHMACSHA256-8	     300	   5629801 ns/op	 186.25 MB/s	[crypto/hmac crypto/sha256]
```

## License

Unless otherwise noted, the poly1305 source files are distributed under the Modified BSD License found in the LICENSE file.

This product includes software developed by the OpenSSL Project for use in the OpenSSL Toolkit (http://www.openssl.org/)
