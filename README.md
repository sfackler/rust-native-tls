# rust-native-tls

[![Build Status](https://travis-ci.org/sfackler/rust-native-tls.svg?branch=master)](https://travis-ci.org/sfackler/rust-native-tls)

[Documentation](https://sfackler.github.io/rust-native-tls/doc/v0.1.0/native_tls)

An abstraction over platform-specific TLS implementations.

Specifically, this crate uses SChannel on Windows (via the [`schannel`] crate),
Secure Transport on OSX (via the [`security-framework`] crate), and OpenSSL (via
the [`openssl`] crate) on all other platforms.

[`schannel`]: https://crates.io/crates/schannel
[`security-framework`]: https://crates.io/crates/security-framework
[`openssl`]: https://crates.io/crates/openssl

## Installation

```toml
# Cargo.toml
[dependencies]
native-tls = { git = "https://github.com/sfackler/rust-native-tls" }
```

> **Note**: right now this crate is not published on crates.io, but it plans to
>           do so soon!

## Usage

An example client looks like:

```rust
extern crate native_tls;

use native_tls::ClientBuilder;
use std::io::{Read, Write};
use std::net::TcpStream;

fn main() {
    let stream = TcpStream::connect("google.com:443").unwrap();
    let mut stream = ClientBuilder::new()
                        .unwrap()
                        .handshake("google.com", stream)
                        .unwrap();
    stream.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
    let mut res = vec![];
    stream.read_to_end(&mut res).unwrap();
    println!("{}", String::from_utf8_lossy(&res));
}
```

To accept connections as a server from remote clients:

```rust,no_run
extern crate native_tls;

use native_tls::{Pkcs12, ServerBuilder, TlsStream};
use std::fs::File;
use std::io::{Read};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

fn main() {
    let mut file = File::open("identity.pfx").unwrap();
    let mut pkcs12 = vec![];
    file.read_to_end(&mut pkcs12).unwrap();
    let pkcs12 = Pkcs12::from_der(&pkcs12, "hunter2").unwrap();

    let listener = TcpListener::bind("0.0.0.0:8443").unwrap();
    let builder = Arc::new(ServerBuilder::new(pkcs12).unwrap());

    fn handle_client(stream: TlsStream<TcpStream>) {
        // ...
    }

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let builder = builder.clone();
                thread::spawn(move || {
                    let stream = builder.handshake(stream).unwrap();
                    handle_client(stream);
                });
            }
            Err(e) => { /* connection failed */ }
        }
    }
}
```

# License

`rust-native-tls` is primarily distributed under the terms of both the MIT
license and the Apache License (Version 2.0), with portions covered by various
BSD-like licenses.

See LICENSE-APACHE, and LICENSE-MIT for details.
