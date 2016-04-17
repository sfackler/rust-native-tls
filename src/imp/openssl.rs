extern crate openssl;

use std::io;
use self::openssl::ssl::{self, SslContext, SslMethod};
use self::openssl::ssl::error::SslError;

pub struct Error(SslError);

impl From<SslError> for Error {
    fn from(err: SslError) -> Error {
        Error(err)
    }
}

pub struct ClientBuilder(SslContext);

impl ClientBuilder {
    pub fn new() -> Result<ClientBuilder, Error> {
        let ctx = try!(SslContext::new(SslMethod::Sslv23));
        Ok(ClientBuilder(ctx))
    }
}

pub struct SslStream<S>(ssl::SslStream<S>);

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
