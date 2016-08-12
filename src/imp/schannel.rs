extern crate schannel;

use std::io;
use std::fmt;
use std::error;
use self::schannel::schannel_cred::{Direction, SchannelCred};
use self::schannel::tls_stream;

pub struct Error(io::Error);

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

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Error {
        Error(error)
    }
}

pub struct MidHandshakeTlsStream<S>(tls_stream::MidHandshakeTlsStream<S>);

impl<S> fmt::Debug for MidHandshakeTlsStream<S>
    where S: fmt::Debug {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.0, fmt)
    }
}

impl<S> MidHandshakeTlsStream<S>
    where S: io::Read + io::Write
{
    pub fn get_ref(&self) -> &S {
        self.0.get_ref()
    }

    pub fn get_mut(&mut self) -> &mut S {
        self.0.get_mut()
    }

    pub fn handshake(self) -> Result<TlsStream<S>, HandshakeError<S>> {
        match self.0.handshake() {
            Ok(s) => Ok(TlsStream(s)),
            Err(e) => Err(e.into()),
        }
    }
}

pub enum HandshakeError<S> {
    Failure(Error),
    Interrupted(MidHandshakeTlsStream<S>),
}

impl<S> From<tls_stream::HandshakeError<S>> for HandshakeError<S> {
    fn from(e: tls_stream::HandshakeError<S>) -> HandshakeError<S> {
        match e {
            tls_stream::HandshakeError::Failure(e) => HandshakeError::Failure(e.into()),
            tls_stream::HandshakeError::Interrupted(s) => {
                HandshakeError::Interrupted(MidHandshakeTlsStream(s))
            }
        }
    }
}

impl<S> From<io::Error> for HandshakeError<S> {
    fn from(e: io::Error) -> HandshakeError<S> {
        HandshakeError::Failure(e.into())
    }
}

pub struct ClientBuilder;

impl ClientBuilder {
	pub fn new() -> Result<ClientBuilder, Error> {
        Ok(ClientBuilder)
	}

    pub fn handshake<S>(&mut self,
                        domain: &str,
                        stream: S)
                        -> Result<TlsStream<S>, HandshakeError<S>>
        where S: io::Read + io::Write
    {
        let cred = try!(SchannelCred::builder().acquire(Direction::Outbound));
        match tls_stream::Builder::new().domain(domain).connect(cred, stream) {
            Ok(s) => Ok(TlsStream(s)),
            Err(e) => Err(e.into()),
        }
    }
}

pub struct TlsStream<S>(tls_stream::TlsStream<S>);

impl<S: fmt::Debug> fmt::Debug for TlsStream<S> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.0, fmt)
    }
}

impl<S: io::Read + io::Write> TlsStream<S> {
    pub fn get_ref(&self) -> &S {
        self.0.get_ref()
    }

    pub fn get_mut(&mut self) -> &mut S {
        self.0.get_mut()
    }
}

impl<S: io::Read + io::Write> io::Read for TlsStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl<S: io::Read + io::Write> io::Write for TlsStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}
