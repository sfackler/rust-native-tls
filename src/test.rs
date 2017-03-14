#[cfg(target_os = "macos")]
extern crate security_framework;

use openssl::ssl::{self, SslMethod, SslConnectorBuilder};
use openssl::pkcs12::Pkcs12 as OpenSSLPkcs12;
use openssl::x509::X509;
use std::io::{Read, Write};
use std::net::{TcpStream, TcpListener};
use std::thread;

use super::*;

macro_rules! p {
    ($e:expr) => {
        match $e {
            Ok(r) => r,
            Err(e) => panic!("{:?}", e),
        }
    }
}

#[test]
fn connect_google() {
    let builder = p!(TlsConnector::builder());
    let builder = p!(builder.build());
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
    let builder = p!(TlsConnector::builder());
    let builder = p!(builder.build());
    let s = p!(TcpStream::connect("google.com:443"));
    assert!(builder.connect("goggle.com", s).is_err());
}

#[test]
fn connect_bad_hostname_ignored() {
    let builder = p!(TlsConnector::builder());
    let builder = p!(builder.build());
    let s = p!(TcpStream::connect("google.com:443"));
    builder.danger_connect_without_providing_domain_for_certificate_verification_and_server_name_indication(s).unwrap();
}

#[test]
fn server() {
    let buf = include_bytes!("../test/identity.p12");
    let pkcs12 = p!(Pkcs12::from_der(buf, "mypass"));
    let builder = p!(TlsAcceptor::builder(pkcs12));
    let builder = p!(builder.build());

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
    let mut builder = p!(SslConnectorBuilder::new(SslMethod::tls()));
    p!(builder.builder_mut().set_ca_file("test/root-ca.pem"));
    let connector = builder.build();
    let mut socket = p!(connector.connect("foobar.com", socket));
    println!("{}",
             socket.ssl()
                 .current_cipher()
                 .unwrap()
                 .description());
    p!(socket.write_all(b"hello"));
    let mut buf = vec![];
    p!(socket.read_to_end(&mut buf));
    assert_eq!(buf, b"world");

    p!(j.join());
}

#[test]
fn server_tls11_only() {
    let buf = include_bytes!("../test/identity.p12");
    let pkcs12 = p!(Pkcs12::from_der(buf, "mypass"));
    let mut builder = p!(TlsAcceptor::builder(pkcs12));
    p!(builder.supported_protocols(&[Protocol::Tlsv11]));
    let builder = p!(builder.build());

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
    let mut builder = p!(SslConnectorBuilder::new(SslMethod::tls()));
    p!(builder.builder_mut().set_ca_file("test/root-ca.pem"));
    let options = ssl::SSL_OP_NO_SSLV3 | ssl::SSL_OP_NO_TLSV1 | ssl::SSL_OP_NO_TLSV1_2;
    builder.builder_mut().set_options(options);
    let connector = builder.build();
    let mut socket = p!(connector.connect("foobar.com", socket));
    println!("{}",
             socket.ssl()
                 .current_cipher()
                 .unwrap()
                 .description());
    p!(socket.write_all(b"hello"));
    let mut buf = vec![];
    p!(socket.read_to_end(&mut buf));
    assert_eq!(buf, b"world");

    p!(j.join());
}

#[test]
fn server_no_shared_protocol() {
    let buf = include_bytes!("../test/identity.p12");
    let pkcs12 = p!(Pkcs12::from_der(buf, "mypass"));
    let mut builder = p!(TlsAcceptor::builder(pkcs12));
    p!(builder.supported_protocols(&[Protocol::Tlsv11]));
    let builder = p!(builder.build());

    let listener = p!(TcpListener::bind("0.0.0.0:0"));
    let port = p!(listener.local_addr()).port();

    let j = thread::spawn(move || {
                              let socket = p!(listener.accept()).0;
                              assert!(builder.accept(socket).is_err());
                          });

    let socket = p!(TcpStream::connect(("localhost", port)));
    let mut builder = p!(SslConnectorBuilder::new(SslMethod::tls()));
    p!(builder.builder_mut().set_ca_file("test/root-ca.pem"));
    let options = ssl::SSL_OP_NO_TLSV1_1;
    builder.builder_mut().set_options(options);
    let connector = builder.build();
    assert!(connector.connect("foobar.com", socket).is_err());

    p!(j.join());
}

#[test]
fn shutdown() {
    let buf = include_bytes!("../test/identity.p12");
    let pkcs12 = p!(Pkcs12::from_der(buf, "mypass"));
    let builder = p!(TlsAcceptor::builder(pkcs12));
    let builder = p!(builder.build());

    let listener = p!(TcpListener::bind("0.0.0.0:0"));
    let port = p!(listener.local_addr()).port();

    let j = thread::spawn(move || {
        let socket = p!(listener.accept()).0;
        let mut socket = p!(builder.accept(socket));

        let mut buf = [0; 5];
        p!(socket.read_exact(&mut buf));
        assert_eq!(&buf, b"hello");

        assert_eq!(p!(socket.read(&mut buf)), 0);
    });

    let socket = p!(TcpStream::connect(("localhost", port)));
    let mut builder = p!(SslConnectorBuilder::new(SslMethod::tls()));
    p!(builder.builder_mut().set_ca_file("test/root-ca.pem"));
    let connector = builder.build();
    let mut socket = p!(connector.connect("foobar.com", socket));
    println!("{}",
             socket.ssl()
                 .current_cipher()
                 .unwrap()
                 .description());
    p!(socket.write_all(b"hello"));
    p!(socket.shutdown());

    p!(j.join());
}

#[test]
fn dynamic_auth() {
    let server_name = "server.example.com";
    let (server_id, server_cert) = cert(server_name);
    let server_id_bytes = server_id.to_der().unwrap();
    let server_id = p!(Pkcs12::from_der(&server_id_bytes, "mypass"));
    let builder = p!(TlsAcceptor::builder(server_id));
    let tls_acceptor = p!(builder.build());

    let listener = p!(TcpListener::bind("0.0.0.0:0"));
    let port = p!(listener.local_addr()).port();

    let j = thread::spawn(move || {
        let socket = p!(listener.accept()).0;
        let mut socket = p!(tls_acceptor.accept(socket));

        let mut buf = [0; 5];
        p!(socket.read_exact(&mut buf));
        assert_eq!(&buf, b"hello");

        p!(socket.write_all(b"world"));
    });

    let mut connect_builder = p!(TlsConnector::builder());

    configure_ca(&mut connect_builder, server_cert);

    let connector = p!(connect_builder.build());
    let s = p!(TcpStream::connect(("localhost", port)));
    let socket = connector.connect(server_name, s);

    let mut socket = match socket {
        Err(HandshakeError::Interrupted(mid_handshake)) => p!(mid_handshake.handshake()), 
        r @ _ => p!(r),
    };

    p!(socket.write_all(b"hello"));
    let mut buf = vec![];
    p!(socket.read_to_end(&mut buf));
    assert_eq!(buf, b"world");

    p!(j.join());
}

#[test]
fn client_auth() {
    use self::security_framework::certificate::SecCertificate;
    use self::security_framework::secure_transport::SslAuthenticate;
    use self::security_framework::policy::SecPolicy;
    use self::security_framework::trust::SecTrust;
    use imp::TlsAcceptorBuilderExt;
    use self::security_framework::secure_transport::ProtocolSide;
    use imp::MidHandshakeTlsStreamExt;
    use self::security_framework::trust::TrustResult;

    let server_name = "server.example.com";
    let (server_id, server_cert) = cert(server_name);
    let server_id_bytes = server_id.to_der().unwrap();
    let server_id = p!(Pkcs12::from_der(&server_id_bytes, "mypass"));
    let mut tls_builder = p!(TlsAcceptor::builder(server_id));

    let (client_id, client_cert) = cert("client.example.com");
    let buf = p!(client_cert.to_der());

    add_client_auth_ca(&mut tls_builder, client_cert);
    let tls_acceptor = p!(tls_builder.build());

    let listener = p!(TcpListener::bind("0.0.0.0:0"));
    let port = p!(listener.local_addr()).port();

    let j = thread::spawn(move || {
        let socket = p!(listener.accept()).0;
        let socket = tls_acceptor.accept(socket);

        let mut socket = match socket {
            Ok(_) => panic!("unexpected success"),
            Err(HandshakeError::Interrupted(mid_handshake)) => {
                let ca = p!(SecCertificate::from_der(&buf));

                let mut trust = p!(mid_handshake.context().peer_trust());
                p!(trust.set_anchor_certificates(&vec![ca]));
                p!(trust.set_trust_anchor_certificates_only(true));

                if !p!(trust.evaluate()).success() { panic!("Certificate failed evaluation") };
                p!(mid_handshake.handshake())
            } 
            Err(_) => panic!("failed"),
        };

        let mut buf = [0; 5];
        p!(socket.read_exact(&mut buf));
        assert_eq!(&buf, b"hello");

        p!(socket.write_all(b"world"));
    });

    let buf = p!(client_id.to_der());
    let pkcs12 = p!(Pkcs12::from_der(&buf, "mypass"));
    let mut connect_builder = p!(TlsConnector::builder());

    p!(connect_builder.identity(pkcs12));
    configure_ca(&mut connect_builder, server_cert);

    let connector = p!(connect_builder.build());
    let s = p!(TcpStream::connect(("localhost", port)));
    let socket = connector.connect(server_name, s);

    let mut socket = match socket {
        Err(HandshakeError::Interrupted(mid_handshake)) => p!(mid_handshake.handshake()), 
        r @ _ => p!(r),
    };

    p!(socket.write_all(b"hello"));
    let mut buf = vec![];
    p!(socket.read_to_end(&mut buf));
    assert_eq!(buf, b"world");

    p!(j.join());
}

#[cfg(target_os = "macos")]
fn add_client_auth_ca(accept_builder: &mut TlsAcceptorBuilder, client_cert: X509) {
    use self::security_framework::certificate::SecCertificate;
    use self::security_framework::secure_transport::SslAuthenticate;
    use imp::TlsAcceptorBuilderExt;

    let buf = p!(client_cert.to_der());
    let ca = p!(SecCertificate::from_der(&buf));

    p!(accept_builder.client_auth(SslAuthenticate::Always));

    //p!(accept_builder.additional_cas(vec![ca]));
}

#[cfg(target_os = "windows")]
fn add_client_auth_ca(connect_builder: &mut TlsAcceptorBuilder, client_cert: X509) {
    unimplemented!()
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn add_client_auth_ca(connect_builder: &mut TlsAcceptorBuilder, client_cert: X509) {
    use openssl::ssl::{SSL_VERIFY_FAIL_IF_NO_PEER_CERT, SSL_VERIFY_PEER};
    use openssl::x509::store::X509StoreBuilder;
    use imp::TlsAcceptorBuilderExt;

    let mut ssl_conn_builder = connect_builder.builder_mut();
    let mut ssl_ctx_builder = ssl_conn_builder.builder_mut();
    let verify = SSL_VERIFY_PEER;

    ssl_ctx_builder.set_verify(verify);

    let mut store = X509StoreBuilder::new().unwrap();
    store.add_cert(client_cert).unwrap();
    ssl_ctx_builder.set_verify_cert_store(store.build()).unwrap();
}

#[cfg(target_os = "macos")]
fn configure_ca(connect_builder: &mut TlsConnectorBuilder, cert: X509) {
    use imp::TlsConnectorBuilderExt;
    use self::security_framework::certificate::SecCertificate;

    let buf = cert.to_der().unwrap();
    let ca = p!(SecCertificate::from_der(&buf));

    connect_builder.anchor_certificates(&[ca]);
}

#[cfg(target_os = "windows")]
fn configure_ca(connect_builder: &mut TlsConnectorBuilder, cert: X509) {
    unimplemented!()
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn configure_ca(connect_builder: &mut TlsConnectorBuilder, cert: X509) {
    use openssl::ssl::{SSL_VERIFY_FAIL_IF_NO_PEER_CERT, SSL_VERIFY_PEER};
    use openssl::x509::store::X509StoreBuilder;
    use imp::TlsConnectorBuilderExt;

    let mut ssl_conn_builder = connect_builder.builder_mut();
    let mut ssl_ctx_builder = ssl_conn_builder.builder_mut();
    let verify = SSL_VERIFY_FAIL_IF_NO_PEER_CERT | SSL_VERIFY_PEER;

    ssl_ctx_builder.set_verify(verify);

    let mut store = X509StoreBuilder::new().unwrap();
    store.add_cert(cert).unwrap();
    ssl_ctx_builder.set_verify_cert_store(store.build()).unwrap();
}

fn cert(subject_name: &str) -> (OpenSSLPkcs12, X509) {
    use openssl::rsa::Rsa;
    use openssl::pkey::PKey;
    use openssl::x509::*;
    use openssl::x509::extension::*;
    use openssl::nid;
    use openssl::asn1::*;
    use openssl::hash::*;
    use openssl::bn::*;

    let rsa = Rsa::generate(2048).unwrap();
    let pkey = PKey::from_rsa(rsa).unwrap();

    let mut x509_name = X509NameBuilder::new().unwrap();
    x509_name.append_entry_by_nid(nid::COMMONNAME, subject_name).unwrap();
    let x509_name = x509_name.build();

    let mut serial: BigNum = BigNum::new().unwrap();
    serial.pseudo_rand(32, MSB_MAYBE_ZERO, false).unwrap();
    let serial = serial.to_asn1_integer().unwrap();

    let mut x509_build = X509::builder().unwrap();
    x509_build.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
    x509_build.set_not_after(&Asn1Time::days_from_now(256).unwrap()).unwrap();
    x509_build.set_issuer_name(&x509_name).unwrap();
    x509_build.set_subject_name(&x509_name).unwrap();
    x509_build.set_pubkey(&pkey).unwrap();
    x509_build.set_serial_number(&serial).unwrap();

    let ext_key_usage = ExtendedKeyUsage::new()
        .server_auth()
        .client_auth()
        .build()
        .unwrap();
    x509_build.append_extension(ext_key_usage).unwrap();

    let subject_key_identifier =
        SubjectKeyIdentifier::new().build(&x509_build.x509v3_context(None, None)).unwrap();
    x509_build.append_extension(subject_key_identifier).unwrap();

    let authority_key_identifier = AuthorityKeyIdentifier::new()
        .keyid(true)
        .build(&x509_build.x509v3_context(None, None))
        .unwrap();
    x509_build.append_extension(authority_key_identifier).unwrap();

    let subject_alternative_name = SubjectAlternativeName::new()
        .dns(subject_name)
        .build(&x509_build.x509v3_context(None, None))
        .unwrap();
    x509_build.append_extension(subject_alternative_name).unwrap();

    x509_build.sign(&pkey, MessageDigest::sha256()).unwrap();
    let cert = x509_build.build();

    let pkcs12_builder = OpenSSLPkcs12::builder();
    let pkcs12 = pkcs12_builder.build("mypass", subject_name, &pkey, &cert).unwrap();

    (pkcs12, cert)
}