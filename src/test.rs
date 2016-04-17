use std::net::TcpStream;
use std::io::{Read, Write};

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
