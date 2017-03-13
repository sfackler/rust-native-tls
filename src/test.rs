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
fn load_pkcs12() {
    let (pkcs12, _) = cert("test");

    let buf = p!(pkcs12.to_der());
    p!(Pkcs12::from_der(&buf, "mypass"));
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