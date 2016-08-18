//! An abstraction over platform-specific TLS implementations.
//!
//! Specifically, this crate uses SChannel on Windows (via the `schannel` crate), Secure Transport
//! on OSX (via the `security-framework` crate), and OpenSSL (via the `openssl` crate) on all other
//! platforms.
//!
//! # Examples
//!
//! ```rust
//! use native_tls::ClientBuilder;
//! use std::io::{Read, Write};
//! use std::net::TcpStream;
//!
//! let stream = TcpStream::connect("google.com:443").unwrap();
//! let mut stream = ClientBuilder::new()
//!                     .unwrap()
//!                     .handshake("google.com", stream)
//!                     .unwrap();
//! stream.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
//! let mut res = vec![];
//! stream.read_to_end(&mut res).unwrap();
//! println!("{}", String::from_utf8_lossy(&res));
//! ```
#![doc(html_root_url="https://sfackler.github.io/rust-native-tls/doc/v0.1.0")]
#![warn(missing_docs)]

use std::any::Any;
use std::error;
use std::error::Error as StdError;
use std::io;
use std::fmt;
use std::result;

pub mod backend;

#[cfg(target_os = "macos")]
#[path = "imp/security_framework.rs"]
mod imp;
#[cfg(target_os = "windows")]
#[path = "imp/schannel.rs"]
mod imp;
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
#[path = "imp/openssl.rs"]
mod imp;

#[cfg(test)]
mod test;

/// A typedef of the result type returned by many methods.
pub type Result<T> = result::Result<T, Error>;

/// An error returned from the TLS implementation.
pub struct Error(imp::Error);

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

impl From<imp::Error> for Error {
    fn from(err: imp::Error) -> Error {
        Error(err)
    }
}

pub struct Certificate(imp::Certificate);

pub struct Identity(imp::Identity);

pub struct Pkcs12 {
    pub identity: Identity,
    pub chain: Vec<Certificate>,
    _p: (),
}

impl Pkcs12 {
    pub fn parse(buf: &[u8], pass: &str) -> Result<Pkcs12> {
        let pkcs12 = try!(imp::Pkcs12::parse(buf, pass));

        Ok(Pkcs12 {
            identity: Identity(pkcs12.identity),
            chain: pkcs12.chain.into_iter().map(Certificate).collect(),
            _p: ()
        })
    }
}

/// A TLS stream which has been interrupted midway through the handshake process.
pub struct MidHandshakeTlsStream<S>(imp::MidHandshakeTlsStream<S>);

impl<S> fmt::Debug for MidHandshakeTlsStream<S>
    where S: fmt::Debug
{
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.0, fmt)
    }
}

impl<S> MidHandshakeTlsStream<S>
    where S: io::Read + io::Write
{
    /// Returns a shared reference to the inner stream.
    pub fn get_ref(&self) -> &S {
        self.0.get_ref()
    }

    /// Returns a mutable reference to the inner stream.
    pub fn get_mut(&mut self) -> &mut S {
        self.0.get_mut()
    }

    /// Restarts the handshake process.
    pub fn handshake(self) -> result::Result<TlsStream<S>, HandshakeError<S>> {
        match self.0.handshake() {
            Ok(s) => Ok(TlsStream(s)),
            Err(e) => Err(e.into()),
        }
    }
}

/// An error returned from `ClientBuilder::handshake`.
#[derive(Debug)]
pub enum HandshakeError<S> {
    /// A fatal error.
    Failure(Error),

    /// A stream interrupted midway through the handshake process due to a
    /// `WouldBlock` error.
    Interrupted(MidHandshakeTlsStream<S>),
}

impl<S> error::Error for HandshakeError<S>
    where S: Any + fmt::Debug
{
    fn description(&self) -> &str {
        match *self {
            HandshakeError::Failure(ref e) => e.description(),
            HandshakeError::Interrupted(_) => "the handshake process was interrupted",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            HandshakeError::Failure(ref e) => Some(e),
            HandshakeError::Interrupted(_) => None,
        }
    }
}

impl<S> fmt::Display for HandshakeError<S>
    where S: Any + fmt::Debug
{
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        try!(fmt.write_str(self.description()));
        if let Some(cause) = self.cause() {
            try!(write!(fmt, ": {}", cause));
        }
        Ok(())
    }
}

impl<S> From<imp::HandshakeError<S>> for HandshakeError<S> {
    fn from(e: imp::HandshakeError<S>) -> HandshakeError<S> {
        match e {
            imp::HandshakeError::Failure(e) => HandshakeError::Failure(Error(e)),
            imp::HandshakeError::Interrupted(s) => {
                HandshakeError::Interrupted(MidHandshakeTlsStream(s))
            }
        }
    }
}

/// A builder for client-side TLS connections.
pub struct ClientBuilder(imp::ClientBuilder);

impl ClientBuilder {
    /// Creates a new builder with default settings.
    pub fn new() -> Result<ClientBuilder> {
        match imp::ClientBuilder::new() {
            Ok(builder) => Ok(ClientBuilder(builder)),
            Err(err) => Err(Error(err)),
        }
    }

    /// Initiates a TLS handshake.
    ///
    /// The provided domain will be used for both SNI and certificate hostname
    /// validation.
    ///
    /// If the socket is nonblocking and a `WouldBlock` error is returned during
    /// the handshake, a `HandshakeError::Interrupted` error will be returned
    /// which can be used to restart the handshake when the socket is ready
    /// again.
    pub fn handshake<S>(&mut self,
                        domain: &str,
                        stream: S)
                        -> result::Result<TlsStream<S>, HandshakeError<S>>
        where S: io::Read + io::Write
    {
        match self.0.handshake(domain, stream) {
            Ok(s) => Ok(TlsStream(s)),
            Err(e) => Err(e.into()),
        }
    }
}

pub struct ServerBuilder(imp::ServerBuilder);

impl ServerBuilder {
    pub fn new<I>(identity: Identity, certs: I) -> Result<ServerBuilder>
        where I: IntoIterator<Item = Certificate>
    {
        match imp::ServerBuilder::new(identity.0, certs.into_iter().map(|c| c.0)) {
            Ok(builder) => Ok(ServerBuilder(builder)),
            Err(err) => Err(Error(err)),
        }
    }

    pub fn handshake<S>(&mut self, stream: S) -> result::Result<TlsStream<S>, HandshakeError<S>>
        where S: io::Read + io::Write
    {
        match self.0.handshake(stream) {
            Ok(s) => Ok(TlsStream(s)),
            Err(e) => Err(e.into()),
        }
    }
}

/// A stream managing a TLS session.
pub struct TlsStream<S>(imp::TlsStream<S>);

impl<S: fmt::Debug> fmt::Debug for TlsStream<S> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.0, fmt)
    }
}

impl<S: io::Read + io::Write> TlsStream<S> {
    /// Returns a shared reference to the inner stream.
    pub fn get_ref(&self) -> &S {
        self.0.get_ref()
    }

    /// Returns a mutable reference to the inner stream.
    pub fn get_mut(&mut self) -> &mut S {
        self.0.get_mut()
    }

    /// Returns the number of bytes that can be read without resulting in any network calls.
    pub fn buffered_read_size(&self) -> Result<usize> {
        Ok(try!(self.0.buffered_read_size()))
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

fn _check_kinds() {
    use std::net::TcpStream;

    fn is_sync<T: Sync>() {}
    fn is_send<T: Send>() {}
    is_sync::<Error>();
    is_send::<Error>();
    is_sync::<ClientBuilder>();
    is_send::<ClientBuilder>();
    is_sync::<TlsStream<TcpStream>>();
    is_send::<TlsStream<TcpStream>>();
}
