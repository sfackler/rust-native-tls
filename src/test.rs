use hex;

#[allow(unused_imports)]
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

use super::*;

macro_rules! p {
    ($e:expr) => {
        match $e {
            Ok(r) => r,
            Err(e) => panic!("{:?}", e),
        }
    };
}

// This nested mod is needed for ios testing with rust-test-ios
mod tests {
    #[cfg(feature = "alpn")]
    extern crate tokio;
    #[cfg(feature = "alpn")]
    extern crate tokio_rustls;
    #[cfg(feature = "alpn")]
    extern crate openssl;


    use super::*;

    #[test]
    fn connect_google() {
        let builder = p!(TlsConnector::new());
        let s = p!(TcpStream::connect("google.com:443"));
        let mut socket = p!(builder.connect("google.com", s));

        p!(socket.write_all(b"GET / HTTP/1.0\r\n\r\n"));
        let mut result = vec![];
        p!(socket.read_to_end(&mut result));

        println!("{}", String::from_utf8_lossy(&result));
        assert!(result.starts_with(b"HTTP/1.0"));
        assert!(result.ends_with(b"</HTML>\r\n") || result.ends_with(b"</html>"));
    }

    #[test]
    fn connect_bad_hostname() {
        let builder = p!(TlsConnector::new());
        let s = p!(TcpStream::connect("google.com:443"));
        builder.connect("goggle.com", s).unwrap_err();
    }

    #[test]
    fn connect_bad_hostname_ignored() {
        let builder = p!(TlsConnector::builder()
            .danger_accept_invalid_hostnames(true)
            .build());
        let s = p!(TcpStream::connect("google.com:443"));
        builder.connect("goggle.com", s).unwrap();
    }

    #[test]
    fn connect_no_root_certs() {
        let builder = p!(TlsConnector::builder().disable_built_in_roots(true).build());
        let s = p!(TcpStream::connect("google.com:443"));
        assert!(builder.connect("google.com", s).is_err());
    }

    #[test]
    fn server_no_root_certs() {
        let buf = include_bytes!("../test/identity.p12");
        let identity = p!(Identity::from_pkcs12(buf, "mypass"));
        let builder = p!(TlsAcceptor::new(identity));

        let listener = p!(TcpListener::bind("0.0.0.0:0"));
        let port = p!(listener.local_addr()).port();

        let j = thread::spawn(move || {
            let socket = p!(listener.accept()).0;
            let mut socket = p!(builder.accept(socket));

            let mut buf = [0; 5];
            p!(socket.read_exact(&mut buf));
            assert_eq!(&buf, b"hello");

            p!(socket.write_all(b"world"));
        });

        let root_ca = include_bytes!("../test/root-ca.der");
        let root_ca = Certificate::from_der(root_ca).unwrap();

        let socket = p!(TcpStream::connect(("localhost", port)));
        let builder = p!(TlsConnector::builder()
            .disable_built_in_roots(true)
            .add_root_certificate(root_ca)
            .build());
        let mut socket = p!(builder.connect("foobar.com", socket));

        p!(socket.write_all(b"hello"));
        let mut buf = vec![];
        p!(socket.read_to_end(&mut buf));
        assert_eq!(buf, b"world");

        p!(j.join());
    }

    #[test]
    fn server() {
        let buf = include_bytes!("../test/identity.p12");
        let identity = p!(Identity::from_pkcs12(buf, "mypass"));
        let builder = p!(TlsAcceptor::new(identity));

        let listener = p!(TcpListener::bind("0.0.0.0:0"));
        let port = p!(listener.local_addr()).port();

        let j = thread::spawn(move || {
            let socket = p!(listener.accept()).0;
            let mut socket = p!(builder.accept(socket));

            let mut buf = [0; 5];
            p!(socket.read_exact(&mut buf));
            assert_eq!(&buf, b"hello");

            p!(socket.write_all(b"world"));
        });

        let root_ca = include_bytes!("../test/root-ca.der");
        let root_ca = Certificate::from_der(root_ca).unwrap();

        let socket = p!(TcpStream::connect(("localhost", port)));
        let builder = p!(TlsConnector::builder()
            .add_root_certificate(root_ca)
            .build());
        let mut socket = p!(builder.connect("foobar.com", socket));

        p!(socket.write_all(b"hello"));
        let mut buf = vec![];
        p!(socket.read_to_end(&mut buf));
        assert_eq!(buf, b"world");

        p!(j.join());
    }

    #[test]
    #[cfg(not(target_os = "ios"))]
    fn server_pem() {
        let buf = include_bytes!("../test/identity.p12");
        let identity = p!(Identity::from_pkcs12(buf, "mypass"));
        let builder = p!(TlsAcceptor::new(identity));

        let listener = p!(TcpListener::bind("0.0.0.0:0"));
        let port = p!(listener.local_addr()).port();

        let j = thread::spawn(move || {
            let socket = p!(listener.accept()).0;
            let mut socket = p!(builder.accept(socket));

            let mut buf = [0; 5];
            p!(socket.read_exact(&mut buf));
            assert_eq!(&buf, b"hello");

            p!(socket.write_all(b"world"));
        });

        let root_ca = include_bytes!("../test/root-ca.pem");
        let root_ca = Certificate::from_pem(root_ca).unwrap();

        let socket = p!(TcpStream::connect(("localhost", port)));
        let builder = p!(TlsConnector::builder()
            .add_root_certificate(root_ca)
            .build());
        let mut socket = p!(builder.connect("foobar.com", socket));

        p!(socket.write_all(b"hello"));
        let mut buf = vec![];
        p!(socket.read_to_end(&mut buf));
        assert_eq!(buf, b"world");

        p!(j.join());
    }

    #[test]
    fn peer_certificate() {
        let buf = include_bytes!("../test/identity.p12");
        let identity = p!(Identity::from_pkcs12(buf, "mypass"));
        let builder = p!(TlsAcceptor::new(identity));

        let listener = p!(TcpListener::bind("0.0.0.0:0"));
        let port = p!(listener.local_addr()).port();

        let j = thread::spawn(move || {
            let socket = p!(listener.accept()).0;
            let socket = p!(builder.accept(socket));
            assert!(socket.peer_certificate().unwrap().is_none());
        });

        let root_ca = include_bytes!("../test/root-ca.der");
        let root_ca = Certificate::from_der(root_ca).unwrap();

        let socket = p!(TcpStream::connect(("localhost", port)));
        let builder = p!(TlsConnector::builder()
            .add_root_certificate(root_ca)
            .build());
        let socket = p!(builder.connect("foobar.com", socket));

        let cert_der = include_bytes!("../test/cert.der");
        let cert = socket.peer_certificate().unwrap().unwrap();
        assert_eq!(cert.to_der().unwrap(), &cert_der[..]);

        p!(j.join());
    }

    #[test]
    fn server_tls11_only() {
        let buf = include_bytes!("../test/identity.p12");
        let identity = p!(Identity::from_pkcs12(buf, "mypass"));
        let builder = p!(TlsAcceptor::builder(identity)
            .min_protocol_version(Some(Protocol::Tlsv11))
            .max_protocol_version(Some(Protocol::Tlsv11))
            .build());

        let listener = p!(TcpListener::bind("0.0.0.0:0"));
        let port = p!(listener.local_addr()).port();

        let j = thread::spawn(move || {
            let socket = p!(listener.accept()).0;
            let mut socket = p!(builder.accept(socket));

            let mut buf = [0; 5];
            p!(socket.read_exact(&mut buf));
            assert_eq!(&buf, b"hello");

            p!(socket.write_all(b"world"));
        });

        let root_ca = include_bytes!("../test/root-ca.der");
        let root_ca = Certificate::from_der(root_ca).unwrap();

        let socket = p!(TcpStream::connect(("localhost", port)));
        let builder = p!(TlsConnector::builder()
            .add_root_certificate(root_ca)
            .min_protocol_version(Some(Protocol::Tlsv11))
            .max_protocol_version(Some(Protocol::Tlsv11))
            .build());
        let mut socket = p!(builder.connect("foobar.com", socket));

        p!(socket.write_all(b"hello"));
        let mut buf = vec![];
        p!(socket.read_to_end(&mut buf));
        assert_eq!(buf, b"world");

        p!(j.join());
    }

    #[test]
    fn server_no_shared_protocol() {
        let buf = include_bytes!("../test/identity.p12");
        let identity = p!(Identity::from_pkcs12(buf, "mypass"));
        let builder = p!(TlsAcceptor::builder(identity)
            .min_protocol_version(Some(Protocol::Tlsv12))
            .build());

        let listener = p!(TcpListener::bind("0.0.0.0:0"));
        let port = p!(listener.local_addr()).port();

        let j = thread::spawn(move || {
            let socket = p!(listener.accept()).0;
            assert!(builder.accept(socket).is_err());
        });

        let root_ca = include_bytes!("../test/root-ca.der");
        let root_ca = Certificate::from_der(root_ca).unwrap();

        let socket = p!(TcpStream::connect(("localhost", port)));
        let builder = p!(TlsConnector::builder()
            .add_root_certificate(root_ca)
            .max_protocol_version(Some(Protocol::Tlsv11))
            .build());
        assert!(builder.connect("foobar.com", socket).is_err());

        p!(j.join());
    }

    #[test]
    fn server_untrusted() {
        let buf = include_bytes!("../test/identity.p12");
        let identity = p!(Identity::from_pkcs12(buf, "mypass"));
        let builder = p!(TlsAcceptor::new(identity));

        let listener = p!(TcpListener::bind("0.0.0.0:0"));
        let port = p!(listener.local_addr()).port();

        let j = thread::spawn(move || {
            let socket = p!(listener.accept()).0;
            // FIXME should assert error
            // https://github.com/steffengy/schannel-rs/issues/20
            let _ = builder.accept(socket);
        });

        let socket = p!(TcpStream::connect(("localhost", port)));
        let builder = p!(TlsConnector::new());
        builder.connect("foobar.com", socket).unwrap_err();

        p!(j.join());
    }

    #[test]
    fn server_untrusted_unverified() {
        let buf = include_bytes!("../test/identity.p12");
        let identity = p!(Identity::from_pkcs12(buf, "mypass"));
        let builder = p!(TlsAcceptor::new(identity));

        let listener = p!(TcpListener::bind("0.0.0.0:0"));
        let port = p!(listener.local_addr()).port();

        let j = thread::spawn(move || {
            let socket = p!(listener.accept()).0;
            let mut socket = p!(builder.accept(socket));

            let mut buf = [0; 5];
            p!(socket.read_exact(&mut buf));
            assert_eq!(&buf, b"hello");

            p!(socket.write_all(b"world"));
        });

        let socket = p!(TcpStream::connect(("localhost", port)));
        let builder = p!(TlsConnector::builder()
            .danger_accept_invalid_certs(true)
            .build());
        let mut socket = p!(builder.connect("foobar.com", socket));

        p!(socket.write_all(b"hello"));
        let mut buf = vec![];
        p!(socket.read_to_end(&mut buf));
        assert_eq!(buf, b"world");

        p!(j.join());
    }

    #[test]
    fn import_same_identity_multiple_times() {
        let buf = include_bytes!("../test/identity.p12");
        let _ = p!(Identity::from_pkcs12(buf, "mypass"));
        let _ = p!(Identity::from_pkcs12(buf, "mypass"));
    }

    #[test]
    fn shutdown() {
        let buf = include_bytes!("../test/identity.p12");
        let identity = p!(Identity::from_pkcs12(buf, "mypass"));
        let builder = p!(TlsAcceptor::new(identity));

        let listener = p!(TcpListener::bind("0.0.0.0:0"));
        let port = p!(listener.local_addr()).port();

        let j = thread::spawn(move || {
            let socket = p!(listener.accept()).0;
            let mut socket = p!(builder.accept(socket));

            let mut buf = [0; 5];
            p!(socket.read_exact(&mut buf));
            assert_eq!(&buf, b"hello");

            assert_eq!(p!(socket.read(&mut buf)), 0);
            p!(socket.shutdown());
        });

        let root_ca = include_bytes!("../test/root-ca.der");
        let root_ca = Certificate::from_der(root_ca).unwrap();

        let socket = p!(TcpStream::connect(("localhost", port)));
        let builder = p!(TlsConnector::builder()
            .add_root_certificate(root_ca)
            .build());
        let mut socket = p!(builder.connect("foobar.com", socket));

        p!(socket.write_all(b"hello"));
        p!(socket.shutdown());

        p!(j.join());
    }

    #[test]
    #[cfg_attr(target_os = "ios", ignore)]
    fn tls_server_end_point() {
        let expected = "4712b939fbcb42a6b5101b42139a25b14f81b418facabd378746f12f85cc6544";

        let buf = include_bytes!("../test/identity.p12");
        let identity = p!(Identity::from_pkcs12(buf, "mypass"));
        let builder = p!(TlsAcceptor::new(identity));

        let listener = p!(TcpListener::bind("0.0.0.0:0"));
        let port = p!(listener.local_addr()).port();

        let j = thread::spawn(move || {
            let socket = p!(listener.accept()).0;
            let mut socket = p!(builder.accept(socket));

            let binding = socket.tls_server_end_point().unwrap().unwrap();
            assert_eq!(hex::encode(binding), expected);

            let mut buf = [0; 5];
            p!(socket.read_exact(&mut buf));
            assert_eq!(&buf, b"hello");

            p!(socket.write_all(b"world"));
        });

        let root_ca = include_bytes!("../test/root-ca.der");
        let root_ca = Certificate::from_der(root_ca).unwrap();

        let socket = p!(TcpStream::connect(("localhost", port)));
        let builder = p!(TlsConnector::builder()
            .add_root_certificate(root_ca)
            .build());
        let mut socket = p!(builder.connect("foobar.com", socket));

        let binding = socket.tls_server_end_point().unwrap().unwrap();
        assert_eq!(hex::encode(binding), expected);

        p!(socket.write_all(b"hello"));
        let mut buf = vec![];
        p!(socket.read_to_end(&mut buf));
        assert_eq!(buf, b"world");

        p!(j.join());
    }

    #[cfg(feature = "alpn")]
    #[test]
    fn test_alpn_from_str() {
        let alpn = ApplicationProtocols::from(&["h2", "dot", "webrtc"]);
        assert_eq!(alpn.len(), 3);
        assert_eq!(format!("{:?}", alpn), format!("{:?}", &["h2", "dot", "webrtc"]));
    }

    #[cfg(feature = "alpn")]
    #[test]
    fn test_alpn_from_bytes() {
        use std::convert::TryFrom;

        let data: &[&[u8]] = &[b"h2", b"dot", b"webrtc"];
        let alpn = ApplicationProtocols::try_from(data);
        assert!(alpn.is_ok());
        let alpn = alpn.unwrap();
        assert_eq!(format!("{:?}", alpn), format!("{:?}", &["h2", "dot", "webrtc"]) );

        let data: &[&[u8]] = &[b"h2", b"dot", b"webrtc", b"\xe2\x82\x28"];
        let alpn = ApplicationProtocols::try_from(data);

        #[cfg(any(target_os = "macos", target_os = "ios"))]
        {
            assert!(alpn.is_err());
        }

        #[cfg(not(any(target_os = "macos", target_os = "ios")))]
        {
            assert!(alpn.is_ok());
            let alpn = alpn.unwrap();
            assert_eq!(format!("{:?}", alpn), r##"["h2", "dot", "webrtc", 0xe28228]"##.to_string());
        }
    }

    #[cfg(feature = "alpn")]
    #[tokio::test(core_threads = 2)]
    async fn test_alpn() {
        use openssl::pkcs12::Pkcs12;
        use openssl::pkcs12::ParsedPkcs12;

        use tokio_rustls::rustls;

        use std::io;
        use std::fs;
        use std::path::Path;
        use std::result::Result;

        fn loads_pkcs12<P: AsRef<Path>, S: AsRef<str>>(key_path: P, password: S) -> Result<ParsedPkcs12, Box<dyn std::error::Error>> {
            let pkcs12_data = fs::read(key_path)?;
            let pkcs12_key = Pkcs12::from_der(&pkcs12_data)?;
            let key = pkcs12_key.parse(password.as_ref())?;

            Ok(key)
        }

        pub fn load_certs<P: AsRef<Path>>(path: P) -> Result<Vec<rustls::Certificate>, io::Error> {
            rustls::internal::pemfile::certs(&mut io::BufReader::new(fs::File::open(path)?))
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid cert"))
        }
        
        async fn run_forever_with_rustls(listener: std::net::TcpListener) -> Result<(), Box<dyn std::error::Error + 'static + Send>> {
            let pkcs12 = loads_pkcs12("./test/identity.p12", "mypass").unwrap();
            let pkey = rustls::PrivateKey(pkcs12.pkey.private_key_to_der().unwrap());
            let mut certs = load_certs("./test/cert.pem").unwrap();
            certs.append(&mut load_certs("./test/cert.pem").unwrap());

            let mut config = rustls::ServerConfig::new(rustls::NoClientAuth::new());
            config.set_protocols(&[b"h2".to_vec(), b"dot".to_vec(), b"http/1.1".to_vec()]);
            config.set_single_cert(certs, pkey).unwrap();
            let config = std::sync::Arc::new(config);
            let acceptor = tokio_rustls::TlsAcceptor::from(config);

            let mut listener = tokio::net::TcpListener::from_std(listener).unwrap();
            
            let (tcp_stream, _peer_addr) = listener.accept().await.unwrap();

            let tls_stream = acceptor.accept(tcp_stream).await.unwrap();
            let (_, session) = tls_stream.get_ref();
            let alpn: Option<&[u8]> = tokio_rustls::rustls::Session::get_alpn_protocol(session);
            assert_eq!(alpn, Some("h2".as_bytes()));
            Ok(())
        }
        
        fn run_forever_with_openssl(listener: std::net::TcpListener) -> Result<(), Box<dyn std::error::Error + 'static + Send>> {
            use openssl::ssl::{SslMethod, SslAcceptor};

            let pkcs12 = loads_pkcs12("./test/identity.p12", "mypass").unwrap();
            let pkey = pkcs12.pkey.as_ref();
            let cert = pkcs12.cert.as_ref();

            let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
            acceptor.set_private_key(&pkey).unwrap();
            acceptor.set_certificate(&cert).unwrap();
            if let Some(mut cert_chain) = pkcs12.chain {
                while let Some(cert) = cert_chain.pop() {
                    acceptor.add_extra_chain_cert(cert).unwrap();
                }
            }
            acceptor.check_private_key().unwrap();
            acceptor.set_alpn_protos(b"\x02h2\x03dot\x08http/1.1").unwrap();

            let acceptor = acceptor.build();

            let (tcp_stream, _peer_addr) = listener.accept().unwrap();
            let tls_stream = acceptor.accept(tcp_stream).unwrap();
            let tls_session = tls_stream.ssl();
            let alpn: Option<&[u8]> = tls_session.selected_alpn_protocol();
            let right: &[u8] = b"h2";
            assert_eq!(alpn, Some(right));

            Ok(())
        }

        fn run_forever_with_schannel(listener: std::net::TcpListener) -> Result<(), Box<dyn std::error::Error + 'static + Send>> {
            use schannel::schannel_cred::SchannelCred;
            use schannel::schannel_cred::Protocol;
            use schannel::schannel_cred::Algorithm;
            use schannel::schannel_cred::Direction;
            use schannel::cert_context::CertContext;

            let pkcs12 = loads_pkcs12("./test/identity.p12", "mypass").unwrap();
            // let pkey = pkcs12.pkey.as_ref();
            let cert = pkcs12.cert.as_ref();
            let cert_der = cert.to_der().unwrap();

            let mut builder = SchannelCred::builder();
            builder.supported_algorithms(&[
                Algorithm::Aes, Algorithm::Aes128, Algorithm::Aes256,
                Algorithm::Ecdh, Algorithm::Ecdsa,
                Algorithm::Mac, Algorithm::Hmac,
                Algorithm::Sha1, Algorithm::Sha256,
            ]);
            builder.enabled_protocols(&[Protocol::Tls11, Protocol::Tls12]);
            builder.cert(CertContext::new(&cert_der).unwrap());
            if let Some(mut cert_chain) = pkcs12.chain {
                while let Some(cert) = cert_chain.pop() {
                    let cert_der = cert.to_der().unwrap();
                    let cert_ctx = CertContext::new(&cert_der).unwrap();
                    builder.cert(cert_ctx);
                }
            }

            let acceptor = builder.acquire(Direction::Inbound).unwrap();

            let (tcp_stream, _peer_addr) = listener.accept().unwrap();

            let mut builder = schannel::tls_stream::Builder::new();
            builder.domain("foobar.com");
            builder.request_application_protocols(&[b"h2", b"dot", b"http/1.1"]);
            builder.use_sni(true);
            let tls_stream = builder.accept(acceptor, tcp_stream).unwrap();

            let alpn: Option<Vec<u8>> = tls_stream.negotiated_application_protocol().unwrap();
            assert_eq!(alpn, Some(vec![b'h', b'2']));

            Ok(())
        }

        let listener = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        if cfg!(target_os = "windows") {
            std::thread::spawn(move || {
                run_forever_with_schannel(listener).unwrap();
            });
        } else {
            tokio::spawn(run_forever_with_rustls(listener));
        }

        // ----- Client ------
        let root_ca = include_bytes!("../test/root-ca.der");
        let root_ca = Certificate::from_der(root_ca).unwrap();

        let tls_connector = TlsConnector::builder()
            .use_sni(true)
            // .min_protocol_version(Some(Protocol::Tlsv12))
            // .max_protocol_version(Some(Protocol::Tlsv12))
            .alpn_protocols(&["h2", "dot", "http/1.1"])
            .add_root_certificate(root_ca)
            .danger_accept_invalid_certs(true)
            // .danger_accept_invalid_hostnames(true)
            .build()
            .unwrap();
        let tcp_stream = std::net::TcpStream::connect(("localhost", port)).unwrap();

        let tls_stream = tls_connector
            .connect("foobar.com", tcp_stream)
            .unwrap();

        let negotiated_alpn: Vec<u8> = tls_stream.negotiated_alpn().unwrap().unwrap().into_inner();
        assert_eq!(&negotiated_alpn, b"h2");
    }
}
