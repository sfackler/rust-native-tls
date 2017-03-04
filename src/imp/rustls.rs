extern crate rustls;
extern crate webpki_roots;

use std::error;
use std::fmt;
use std::io;
use std::marker::PhantomData;
use std::net::Shutdown;
use std::sync::Arc;

use self::rustls::Session;

use Protocol;

pub enum Error {
    IO(io::Error),
    Tls(rustls::TLSError),
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::IO(ref e) =>  error::Error::description(e),
            Error::Tls(ref e) => error::Error::description(e),
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::IO(ref e) =>  error::Error::cause(e),
            Error::Tls(ref e) => error::Error::cause(e),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::IO(ref e) =>  fmt::Display::fmt(e, fmt),
            Error::Tls(ref e) => fmt::Display::fmt(e, fmt),
        }
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::IO(ref e) =>  write!(fmt, "Error({:?})", e),
            Error::Tls(ref e) => write!(fmt, "Error({:?})", e),
        }
    }
}

pub struct Pkcs12;

impl Pkcs12 {
    pub fn from_der(buf: &[u8], pass: &str) -> Result<Pkcs12, Error> {
        // TODO: no pkcs12 parser in ring
        unimplemented!()
    }
}

pub struct MidHandshakeTlsStream<S>(TlsStream<S>);

impl<S> fmt::Debug for MidHandshakeTlsStream<S>
    where S: fmt::Debug
{
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "MidHandshakeTlsStream({:?})", self.0)
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
}

impl<S> MidHandshakeTlsStream<S>
    where S: io::Read + io::Write
{
    pub fn handshake(mut self) -> Result<TlsStream<S>, HandshakeError<S>> {
        // Push the handshake as far as possible since dependees seem to mostly
        // not bother handling Interrupted
        while (self.0.sess.wants_read() || self.0.sess.wants_write()) &&
              self.0.sess.is_handshaking() && !self.0.eof &&
              self.0.tls_error.is_none() && self.0.io_error.is_none()
        {
            self.0.underlying_io()
        }
        if let Some(err) = self.0.io_error.take() {
            Err(HandshakeError::Failure(Error::IO(err)))
        } else if let Some(err) = self.0.tls_error.take() {
            Err(HandshakeError::Failure(Error::Tls(err)))
        } else if !self.0.sess.is_handshaking() {
            Ok(self.0)
        } else if self.0.eof {
            // TODO: Not sure about this case
            Err(HandshakeError::Failure(Error::IO(io::Error::new(
                io::ErrorKind::UnexpectedEof, "eof before handshake"))))
        } else {
            // No error, still handshaking...though in theory this never happens
            // because of the underlying_io loop above
            Err(HandshakeError::Interrupted(self))
        }
    }
}

pub enum HandshakeError<S> {
    Failure(Error),
    Interrupted(MidHandshakeTlsStream<S>),
}

pub struct TlsConnectorBuilder;

impl TlsConnectorBuilder {
    pub fn identity(&mut self, pkcs12: Pkcs12) -> Result<(), Error> {
        unimplemented!()
    }

    pub fn supported_protocols(&mut self, protocols: &[Protocol]) -> Result<(), Error> {
        unimplemented!()
    }

    pub fn build(self) -> Result<TlsConnector, Error> {
        let mut tls_config = rustls::ClientConfig::new();
        let cache = rustls::ClientSessionMemoryCache::new(64);
        // XXX: do we want this?
        //tls_config.set_persistence(cache);
        tls_config.root_store.add_trust_anchors(&webpki_roots::ROOTS);
        Ok(TlsConnector(Arc::new(tls_config)))
    }
}

pub struct TlsConnector(Arc<rustls::ClientConfig>);

impl TlsConnector {
    pub fn builder() -> Result<TlsConnectorBuilder, Error> {
        Ok(TlsConnectorBuilder)
    }

    pub fn connect<S>(&self, domain: &str, stream: S) -> Result<TlsStream<S>, HandshakeError<S>>
        where S: io::Read + io::Write
    {
        let handshake_tlsstream = MidHandshakeTlsStream(TlsStream {
            sess: rustls::ClientSession::new(&self.0, domain),
            underlying: stream,
            eof: false,
            tls_error: None,
            io_error: None,
        });
        handshake_tlsstream.handshake()
    }
}

///// OpenSSL-specific extensions to `TlsConnectorBuilder`.
//pub trait TlsConnectorBuilderExt {
//    /// Returns a shared reference to the inner `SslConnectorBuilder`.
//    fn builder(&self) -> &SslConnectorBuilder;
//
//    /// Returns a mutable reference to the inner `SslConnectorBuilder`.
//    fn builder_mut(&mut self) -> &mut SslConnectorBuilder;
//}
//
//impl TlsConnectorBuilderExt for ::TlsConnectorBuilder {
//    fn builder(&self) -> &SslConnectorBuilder {
//        &(self.0).0
//    }
//
//    fn builder_mut(&mut self) -> &mut SslConnectorBuilder {
//        &mut (self.0).0
//    }
//}

pub struct TlsAcceptorBuilder;

impl TlsAcceptorBuilder {
    pub fn supported_protocols(&mut self, protocols: &[Protocol]) -> Result<(), Error> {
        unimplemented!()
    }

    pub fn build(self) -> Result<TlsAcceptor, Error> {
        unimplemented!()
    }
}

pub struct TlsAcceptor;

impl TlsAcceptor {
    pub fn builder(pkcs12: Pkcs12) -> Result<TlsAcceptorBuilder, Error> {
        unimplemented!()
    }

    pub fn accept<S>(&self, stream: S) -> Result<TlsStream<S>, HandshakeError<S>>
        where S: io::Read + io::Write
    {
        unimplemented!()
    }
}

///// OpenSSL-specific extensions to `TlsAcceptorBuilder`.
//pub trait TlsAcceptorBuilderExt {
//    /// Returns a shared reference to the inner `SslAcceptorBuilder`.
//    fn builder(&self) -> &SslAcceptorBuilder;
//
//    /// Returns a mutable reference to the inner `SslAcceptorBuilder`.
//    fn builder_mut(&mut self) -> &mut SslAcceptorBuilder;
//}
//
//impl TlsAcceptorBuilderExt for ::TlsAcceptorBuilder {
//    fn builder(&self) -> &SslAcceptorBuilder {
//        &(self.0).0
//    }
//
//    fn builder_mut(&mut self) -> &mut SslAcceptorBuilder {
//        &mut (self.0).0
//    }
//}

pub struct TlsStream<S> {
    sess: rustls::ClientSession,
    underlying: S,
    eof: bool,
    tls_error: Option<rustls::TLSError>,
    io_error: Option<io::Error>,
}

impl<S: io::Read + io::Write> TlsStream<S> {
    fn underlying_read(&mut self) {
        if self.io_error.is_some() || self.tls_error.is_some() {
            return
        }

        if self.sess.wants_read() {
            match self.sess.read_tls(&mut self.underlying) {
                Err(err) => {
                    if err.kind() != io::ErrorKind::WouldBlock {
                        self.io_error = Some(err);
                    }
                },
                Ok(0) => {
                    self.eof = true;
                },
                Ok(_) => ()
            }
        }

        if let Err(err) = self.sess.process_new_packets() {
            self.tls_error = Some(err);
        }
    }

    fn underlying_write(&mut self) {
        if self.io_error.is_some() || self.tls_error.is_some() {
            return;
        }

        while self.io_error.is_none() && self.sess.wants_write() {
            if let Err(err) = self.sess.write_tls(&mut self.underlying) {
                if err.kind() != io::ErrorKind::WouldBlock {
                    self.io_error = Some(err);
                }
            }
        }
    }

    fn underlying_io(&mut self) {
        self.underlying_write();
        self.underlying_read();
    }

    fn promote_tls_error(&mut self) -> io::Result<()> {
        match self.tls_error.take() {
            Some(err) => {
                return Err(io::Error::new(io::ErrorKind::ConnectionAborted, err));
            },
            None => return Ok(())
        };
    }

    fn check_io_error(&mut self) -> io::Result<()> {
        self.io_error.take().map(Err).unwrap_or(Ok(()))
    }
}

impl<S: fmt::Debug> fmt::Debug for TlsStream<S> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt,
            "TlsStream {{ sess: _, underlying: {:?}, eof: {:?}, \
            tls_error: {:?}, io_error: {:?} }}",
            self.underlying, self.eof, self.tls_error, self.io_error
        )
    }
}

impl<S: io::Read + io::Write> TlsStream<S> {
    pub fn buffered_read_size(&self) -> Result<usize, Error> {
        unimplemented!()
    }

    pub fn shutdown(&mut self) -> io::Result<()> {
        unimplemented!()
    }

    pub fn get_ref(&self) -> &S {
        &self.underlying
    }

    pub fn get_mut(&mut self) -> &mut S {
        &mut self.underlying
    }
}

impl<S: io::Read + io::Write> io::Read for TlsStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // This wants to block if we don't have any data ready.
        // underlying_read does this.
        loop {
            try!(self.check_io_error());
            try!(self.promote_tls_error());

            if self.eof {
                return Ok(0);
            }

            match self.sess.read(buf) {
                Ok(0) => self.underlying_io(),
                Ok(n) => return Ok(n),
                Err(e) => return Err(e)
            }
        }
    }
}

impl<S: io::Read + io::Write> io::Write for TlsStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let len = try!(self.sess.write(buf));
        try!(self.promote_tls_error());
        self.underlying_write();
        Ok(len)
    }

    fn flush(&mut self) -> io::Result<()> {
        let rc = self.sess.flush();
        try!(self.promote_tls_error());
        self.underlying_write();
        rc
    }
}

///// OpenSSL-specific extensions to `TlsStream`.
//pub trait TlsStreamExt<S> {
//    /// Returns a shared reference to the OpenSSL `SslStream`.
//    fn raw_stream(&self) -> &ssl::SslStream<S>;
//
//    /// Returns a mutable reference to the OpenSSL `SslStream`.
//    fn raw_stream_mut(&mut self) -> &mut ssl::SslStream<S>;
//}
//
//impl<S> TlsStreamExt<S> for ::TlsStream<S> {
//    fn raw_stream(&self) -> &ssl::SslStream<S> {
//        &(self.0).0
//    }
//
//    fn raw_stream_mut(&mut self) -> &mut ssl::SslStream<S> {
//        &mut (self.0).0
//    }
//}
//
///// OpenSSL-specific extensions to `Error`
//pub trait ErrorExt {
//    /// Extract the underlying OpenSSL error for inspection.
//    fn openssl_error(&self) -> &ssl::Error;
//}
//
//impl ErrorExt for ::Error {
//    fn openssl_error(&self) -> &ssl::Error {
//        &(self.0).0
//    }
//}
