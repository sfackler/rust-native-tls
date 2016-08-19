use std::io::{Read, Write};
use std::net::{TcpStream, TcpListener};
use std::process::Command;

use super::*;

#[test]
fn connect_google() {
    let mut builder = ClientBuilder::new().unwrap();
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
    let mut builder = ClientBuilder::new().unwrap();
    let s = TcpStream::connect("wrong.host.badssl.com:443").unwrap();
    assert!(builder.handshake("wrong.host.badssl.com", s).is_err());
}

#[test]
fn server() {
    let buf = include_bytes!("../test/identity.p12");
    let pkcs12 = Pkcs12::parse(buf, "mypass").unwrap();
    let mut builder = ServerBuilder::new(pkcs12.identity, pkcs12.chain).unwrap();

    let listener = TcpListener::bind("0.0.0.0:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let python = if cfg!(windows) {
        "python.exe"
    } else {
        "python"
    };

    let mut client = Command::new(python)
        .arg("client.py")
        .arg(port.to_string())
        .current_dir("test")
        .spawn()
        .unwrap();

    let socket = listener.accept().unwrap().0;
    let mut socket = builder.handshake(socket).unwrap();
    let mut buf = [0; 5];
    socket.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"hello");

    socket.write_all(b"world").unwrap();
    drop(socket);

    let status = client.wait().unwrap();
    assert!(status.success());
}
