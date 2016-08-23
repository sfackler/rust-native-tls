use openssl::ssl::{SslContext, SslMethod, SslStream, SSL_VERIFY_PEER};
use openssl_verify;
use std::io::{Read, Write};
use std::net::{TcpStream, TcpListener};
use std::thread;

use super::*;

#[test]
fn connect_google() {
    let builder = ClientBuilder::new().unwrap();
    let s = TcpStream::connect("google.com:443").unwrap();
    let mut socket = builder.handshake("google.com", s).unwrap();

    socket.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
    let mut result = vec![];
    socket.read_to_end(&mut result).unwrap();

    println!("{}", String::from_utf8_lossy(&result));
    assert!(result.starts_with(b"HTTP/1.0"));
    assert!(result.ends_with(b"</HTML>\r\n") || result.ends_with(b"</html>"));
}

#[test]
fn connect_bad_hostname() {
    let builder = ClientBuilder::new().unwrap();
    let s = TcpStream::connect("wrong.host.badssl.com:443").unwrap();
    assert!(builder.handshake("wrong.host.badssl.com", s).is_err());
}

#[test]
fn server() {
    let buf = include_bytes!("../test/identity.p12");
    let pkcs12 = Pkcs12::from_der(buf, "mypass").unwrap();
    let builder = ServerBuilder::new(pkcs12).unwrap();

    let listener = TcpListener::bind("0.0.0.0:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    thread::spawn(move || {
        let socket = listener.accept().unwrap().0;
        let mut socket = builder.handshake(socket).unwrap();

        let mut buf = [0; 5];
        socket.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"hello");

        socket.write_all(b"world").unwrap();
    });

    let socket = TcpStream::connect(("localhost", port)).unwrap();
    let mut ctx = SslContext::new(SslMethod::Sslv23).unwrap();
    ctx.set_CA_file("test/root-ca.pem").unwrap();
    ctx.set_verify_callback(SSL_VERIFY_PEER, |c, p| openssl_verify::verify_callback("foobar.com", c, p));
    let mut socket = SslStream::connect(&ctx, socket).unwrap();
    socket.write_all(b"hello").unwrap();
    let mut buf = vec![];
    socket.read_to_end(&mut buf).unwrap();
    assert_eq!(buf, b"world");
}
