use openssl::ssl::{self, SslMethod, SslConnectorBuilder};
use std::io::{Read, Write};
use std::net::{TcpStream, TcpListener};
use std::thread;

use super::*;

#[test]
fn connect_google() {
    let builder = TlsConnector::builder().unwrap().build().unwrap();
    let s = TcpStream::connect("google.com:443").unwrap();
    let mut socket = builder.connect("google.com", s).unwrap();

    socket.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
    let mut result = vec![];
    socket.read_to_end(&mut result).unwrap();

    println!("{}", String::from_utf8_lossy(&result));
    assert!(result.starts_with(b"HTTP/1.0"));
    assert!(result.ends_with(b"</HTML>\r\n") || result.ends_with(b"</html>"));
}

#[test]
fn connect_bad_hostname() {
    let builder = TlsConnector::builder().unwrap().build().unwrap();
    let s = TcpStream::connect("wrong.host.badssl.com:443").unwrap();
    assert!(builder.connect("wrong.host.badssl.com", s).is_err());
}

#[test]
fn server() {
    let buf = include_bytes!("../test/identity.p12");
    let pkcs12 = Pkcs12::from_der(buf, "mypass").unwrap();
    let builder = TlsAcceptor::builder(pkcs12).unwrap().build().unwrap();

    let listener = TcpListener::bind("0.0.0.0:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    thread::spawn(move || {
        let socket = listener.accept().unwrap().0;
        let mut socket = builder.accept(socket).unwrap();

        let mut buf = [0; 5];
        socket.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"hello");

        socket.write_all(b"world").unwrap();
    });

    let socket = TcpStream::connect(("localhost", port)).unwrap();
    let mut builder = SslConnectorBuilder::new(SslMethod::tls()).unwrap();
    builder.builder_mut().set_ca_file("test/root-ca.pem").unwrap();
    let connector = builder.build();
    let mut socket = connector.connect("foobar.com", socket).unwrap();
    println!("{}", socket.ssl().current_cipher().unwrap().description());
    socket.write_all(b"hello").unwrap();
    let mut buf = vec![];
    socket.read_to_end(&mut buf).unwrap();
    assert_eq!(buf, b"world");
}

#[test]
fn server_tls12_only() {
    let buf = include_bytes!("../test/identity.p12");
    let pkcs12 = Pkcs12::from_der(buf, "mypass").unwrap();
    let mut builder = TlsAcceptor::builder(pkcs12).unwrap();
    builder.supported_protocols(&[Protocol::Tlsv12]).unwrap();
    let builder = builder.build().unwrap();

    let listener = TcpListener::bind("0.0.0.0:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let j = thread::spawn(move || {
        let socket = listener.accept().unwrap().0;
        let mut socket = builder.accept(socket).unwrap();

        let mut buf = [0; 5];
        socket.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"hello");

        socket.write_all(b"world").unwrap();
        socket.shutdown().unwrap();
    });

    let socket = TcpStream::connect(("localhost", port)).unwrap();
    let mut builder = SslConnectorBuilder::new(SslMethod::tls()).unwrap();
    builder.builder_mut().set_ca_file("test/root-ca.pem").unwrap();
    let options = ssl::SSL_OP_NO_SSLV3 | ssl::SSL_OP_NO_TLSV1 | ssl::SSL_OP_NO_TLSV1_1;
    builder.builder_mut().set_options(options);
    let connector = builder.build();
    let mut socket = connector.connect("foobar.com", socket).unwrap();
    println!("{}", socket.ssl().current_cipher().unwrap().description());
    socket.write_all(b"hello").unwrap();
    let mut buf = vec![];
    socket.read_to_end(&mut buf).unwrap();
    assert_eq!(buf, b"world");
    socket.shutdown().unwrap();

    j.join().unwrap();
}

#[test]
fn server_no_shared_protocol() {
    let buf = include_bytes!("../test/identity.p12");
    let pkcs12 = Pkcs12::from_der(buf, "mypass").unwrap();
    let mut builder = TlsAcceptor::builder(pkcs12).unwrap();
    builder.supported_protocols(&[Protocol::Tlsv11]).unwrap();
    let builder = builder.build().unwrap();

    let listener = TcpListener::bind("0.0.0.0:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let j = thread::spawn(move || {
        let socket = listener.accept().unwrap().0;
        assert!(builder.accept(socket).is_err());
    });

    let socket = TcpStream::connect(("localhost", port)).unwrap();
    let mut builder = SslConnectorBuilder::new(SslMethod::tls()).unwrap();
    builder.builder_mut().set_ca_file("test/root-ca.pem").unwrap();
    let options = ssl::SSL_OP_NO_SSLV3 | ssl::SSL_OP_NO_TLSV1 | ssl::SSL_OP_NO_TLSV1_1;
    builder.builder_mut().set_options(options);
    let connector = builder.build();
    assert!(connector.connect("foobar.com", socket).is_err());

    j.join().unwrap();
}
