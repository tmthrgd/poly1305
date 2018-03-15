# poly1305

[![GoDoc](https://godoc.org/github.com/tmthrgd/poly1305?status.svg)](https://godoc.org/github.com/tmthrgd/poly1305)
[![Build Status](https://travis-ci.org/tmthrgd/poly1305.svg?branch=master)](https://travis-ci.org/tmthrgd/poly1305)

An AVX/AVX2/x64 implementation of the Poly1305 MAC for Golang.

The AVX and AVX2 Poly1305 implementations were taken from
[cloudflare/sslconfig](https://github.com/cloudflare/sslconfig/blob/master/patches/openssl__chacha20_poly1305_cf.patch).

The x64 Poly1305 implementation was taken from
[cloudflare/sslconfig](https://github.com/cloudflare/sslconfig/blob/master/patches/openssl__chacha20_poly1305_draft_and_rfc_ossl102g.patch).

For non-x64 systems, it falls back to [golang.org/x/crypto/poly1305](https://godoc.org/golang.org/x/crypto/poly1305).

## Benchmark

```
BenchmarkXCryptoSum/1M-8   	    3000	    404575 ns/op	2591.79 MB/s	[golang.org/x/crypto/poly1305]
BenchmarkSumx64/1M-8       	    3000	    419194 ns/op	2501.41 MB/s	[tmthrgd/poly1305]
BenchmarkSumAVX/1M-8       	    5000	    364872 ns/op	2873.82 MB/s	[tmthrgd/poly1305]
BenchmarkNewx64/1M-8       	    3000	    424440 ns/op	2470.49 MB/s	[tmthrgd/poly1305]
BenchmarkNewAVX/1M-8       	    5000	    364626 ns/op	2875.76 MB/s	[tmthrgd/poly1305]
BenchmarkHMAC_MD5/1M-8     	    1000	   1481835 ns/op	 707.62 MB/s	[crypto/hmac crypto/md5]
BenchmarkHMAC_SHA1/1M-8    	    1000	   2253576 ns/op	 465.29 MB/s	[crypto/hmac crypto/sha1]
BenchmarkHMAC_SHA256/1M-8  	     300	   5617349 ns/op	 186.67 MB/s	[crypto/hmac crypto/sha256]
```

## License

Unless otherwise noted, the poly1305 source files are distributed under the Modified BSD License found in the LICENSE file.

This product includes software developed by the OpenSSL Project for use in the OpenSSL Toolkit (http://www.openssl.org/)
