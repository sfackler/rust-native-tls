extern crate security_framework;

use self::security_framework::base;
use self::security_framework::secure_transport;
use std::fmt;
use std::io;

pub struct Error(base::Error);

impl fmt::Debug for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.0, fmt)
    }
}

impl From<base::Error> for Error {
    fn from(error: base::Error) -> Error {
        Error(error)
    }
}

pub struct ClientBuilder(secure_transport::ClientBuilder);

impl ClientBuilder {
    pub fn new() -> Result<ClientBuilder, Error> {
        Ok(ClientBuilder(secure_transport::ClientBuilder::new()))
    }

    pub fn handshake<S>(&mut self, domain: &str, stream: S) -> Result<SslStream<S>, Error>
        where S: io::Read + io::Write
    {
        let s = try!(self.0.handshake(domain, stream));
        Ok(SslStream(s))
    }
}

pub struct SslStream<S>(secure_transport::SslStream<S>);

impl<S> SslStream<S> {
    pub fn get_ref(&self) -> &S {
        self.0.get_ref()
    }

    pub fn get_mut(&mut self) -> &mut S {
        self.0.get_mut()
    }
}

impl<S: io::Read + io::Write> io::Read for SslStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl<S: io::Read + io::Write> io::Write for SslStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}
