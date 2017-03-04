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
    let s = p!(TcpStream::connect("wrong.host.badssl.com:443"));
    assert!(builder.connect("wrong.host.badssl.com", s).is_err());
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
    println!("{}", socket.ssl().current_cipher().unwrap().description());
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
    println!("{}", socket.ssl().current_cipher().unwrap().description());
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
    println!("{}", socket.ssl().current_cipher().unwrap().description());
    p!(socket.write_all(b"hello"));
    p!(socket.shutdown());

    p!(j.join());
}

#[test]
fn client_auth_no_verify() {
    let server_id_bytes = include_bytes!("../test/identity.p12");
    let server_id = p!(Pkcs12::from_der(server_id_bytes, "mypass"));
    let builder = p!(TlsAcceptor::builder(server_id));
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

    let mut connect_builder = p!(TlsConnector::builder());

    configure_ca(&mut connect_builder);

    let connector = p!(connect_builder.build());
    let s = p!(TcpStream::connect(("localhost", port)));
    let mut socket = p!(connector.connect("foobar.com", s));

    p!(socket.write_all(b"hello"));
    let mut buf = vec![];
    p!(socket.read_to_end(&mut buf));
    assert_eq!(buf, b"world");

    p!(j.join());
}

#[test]
fn client_auth() {
    let server_id_bytes = include_bytes!("../test/identity.p12");
    let server_id = p!(Pkcs12::from_der(server_id_bytes, "mypass"));
    let mut builder = p!(TlsAcceptor::builder(server_id));

    let (client_id, client_cert) = cert("client");

    add_client_auth_ca(&mut builder, client_cert);
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

    let buf = p!(client_id.to_der());
    let pkcs12 = p!(Pkcs12::from_der(&buf, "mypass"));
    let mut connect_builder = p!(TlsConnector::builder());

    p!(connect_builder.identity(pkcs12));
    configure_ca(&mut connect_builder);

    let connector = p!(connect_builder.build());
    let s = p!(TcpStream::connect(("localhost", port)));
    let mut socket = p!(connector.connect("foobar.com", s));

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
    p!(accept_builder.additional_cas(vec![ca]));
}

#[cfg(target_os = "windows")]
fn add_client_auth_ca(connect_builder: &mut TlsAcceptorBuilder, client_cert: X509) {
    unimplemented!()
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn add_client_auth_ca(connect_builder: &mut TlsAcceptorBuilder, client_cert: X509) {
    use openssl::ssl::{SSL_VERIFY_FAIL_IF_NO_PEER_CERT, SSL_VERIFY_PEER};
    use imp::TlsAcceptorBuilderExt;

    let mut ssl_conn_builder = connect_builder.builder_mut();
    let mut ssl_ctx_builder = ssl_conn_builder.builder_mut();
    let verify = SSL_VERIFY_FAIL_IF_NO_PEER_CERT | SSL_VERIFY_PEER;

    ssl_ctx_builder.set_verify(verify);

    let mut store = X509StoreBuilder::new().unwrap();
    let root_ca = X509::from_der(&root_cert_der_copy).unwrap();
    store.add_cert(root_ca).unwrap();
    ssl_ctx_builder.set_verify_cert_store(store.build()).unwrap();
}

#[cfg(target_os = "macos")]
fn configure_ca(connect_builder: &mut TlsConnectorBuilder) {
    use imp::TlsConnectorBuilderExt;
    use self::security_framework::certificate::SecCertificate;

    let buf = include_bytes!("../test/root-ca.der");
    let ca = p!(SecCertificate::from_der(buf));

    connect_builder.anchor_certificates(&[ca]);
}

#[cfg(target_os = "windows")]
fn configure_ca(connect_builder: &mut TlsConnectorBuilder) {
    unimplemented!()
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn configure_ca(connect_builder: &mut TlsConnectorBuilder) {
    use imp::TlsConnectorBuilderExt;

    let mut ssl_conn_builder = connect_builder.builder_mut();
    let mut ssl_ctx_builder = ssl_conn_builder.builder_mut();

    p!(ssl_ctx_builder.set_ca_file("test/root-ca.pem"));
}

fn cert(subject_name: &str) -> (OpenSSLPkcs12, X509) {
    use openssl::rsa::Rsa;
    use openssl::pkey::PKey;
    use openssl::x509::*;
    use openssl::x509::extension::*;
    use openssl::nid;
    use openssl::asn1::*;
    use openssl::hash::*;

    let rsa = Rsa::generate(2048).unwrap();
    let pkey = PKey::from_rsa(rsa).unwrap();

    let mut x509_name = X509NameBuilder::new().unwrap();
    x509_name.append_entry_by_nid(nid::COMMONNAME, subject_name).unwrap();
    let x509_name = x509_name.build();

    let mut x509_build = X509::builder().unwrap();
    x509_build.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
    x509_build.set_not_after(&Asn1Time::days_from_now(256).unwrap()).unwrap();
    x509_build.set_issuer_name(&x509_name).unwrap();
    x509_build.set_subject_name(&x509_name).unwrap();
    x509_build.set_pubkey(&pkey).unwrap();

    let basic_constraints = BasicConstraints::new().critical().ca().build().unwrap();
    x509_build.append_extension(basic_constraints).unwrap();

    let ext_key_usage = ExtendedKeyUsage::new()
        .server_auth()
        .client_auth()
        .build()
        .unwrap();
    x509_build.append_extension(ext_key_usage).unwrap();

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