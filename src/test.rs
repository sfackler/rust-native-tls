#[cfg(target_os = "macos")]
extern crate security_framework;

use openssl::ssl::{self, SslMethod, SslConnectorBuilder};
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
fn client_auth_no_verify() {
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
    let buf = include_bytes!("../test/identity.p12");
    let pkcs12 = p!(Pkcs12::from_der(buf, "mypass"));
    let mut builder = p!(TlsAcceptor::builder(pkcs12));
    add_client_auth_ca(&mut builder);
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

    let buf = include_bytes!("../test/identity.p12");
    let pkcs12 = p!(Pkcs12::from_der(buf, "mypass"));
    let mut connect_builder = p!(TlsConnector::builder());

    p!(connect_builder.identity(pkcs12));
    //configure_ca(&mut connect_builder);

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
fn add_client_auth_ca(accept_builder: &mut TlsAcceptorBuilder) {
    use self::security_framework::certificate::SecCertificate;
    use self::security_framework::secure_transport::SslAuthenticate;
    use imp::TlsAcceptorBuilderExt;

    let buf = include_bytes!("../test/root-ca.der");
    let ca = p!(SecCertificate::from_der(buf));

    p!(accept_builder.client_auth(SslAuthenticate::Always));
    p!(accept_builder.additional_cas(vec![ca]));
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
