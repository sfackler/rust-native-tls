extern crate schannel;

use std::sync::Arc;
use std::io;
use std::fmt;
use std::error;

pub struct Error(schannel::SslError);

impl error::Error for Error {
    fn description(&self) -> &str {
        error::Error::description(&self.0)
    }

    fn cause(&self) -> Option<&error::Error> {
        error::Error::cause(&self.0)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, fmt)
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.0, fmt)
    }
}

impl From<schannel::SslError> for Error {
    fn from(error: schannel::SslError) -> Error {
        Error(error)
    }
}

pub struct ClientBuilder(Arc<schannel::SslInfo>);

impl ClientBuilder {
	pub fn new() -> Result<ClientBuilder, Error> {
		Ok(ClientBuilder(Arc::new(schannel::SslInfo::Client(schannel::SslInfoClient::new()))))
	}

    pub fn handshake<S>(&mut self, domain: &str, stream: S) -> Result<SslStream<S>, Error>
        where S: io::Read + io::Write
    {
        let mut s = try!(schannel::SslStream::new(stream, &self.0));
        s.set_host(domain);
        match s.init() {
            Some(err) => Err(err.into()),
            None => Ok(SslStream(s))
        }
    }
}

pub struct SslStream<S>(schannel::SslStream<S>);

impl<S: io::Read + io::Write> SslStream<S> {
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
