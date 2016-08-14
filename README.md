# rust-native-tls

[![Build Status](https://travis-ci.org/sfackler/rust-native-tls.svg?branch=master)](https://travis-ci.org/sfackler/rust-native-tls)

[Documentation](https://sfackler.github.io/rust-native-tls/doc/v0.1.0/native_tls)

An abstraction over platform-specific TLS implementations.

Specifically, this crate uses SChannel on Windows (via the `schannel` crate), Secure Transport on OSX (via the
`security-framework` crate), and OpenSSL (via the `openssl` crate) on all other platforms.
