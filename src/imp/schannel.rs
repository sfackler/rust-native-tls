extern crate schannel;

use std::io;
use std::fmt;
use std::error;
use self::schannel::cert_store::PfxImportOptions;
use self::schannel::cert_context::CertContext;
use self::schannel::schannel_cred::{Direction, SchannelCred, Protocol};
use self::schannel::tls_stream;

fn convert_protocols(protocols: &[::Protocol]) -> Vec<Protocol> {
    protocols.iter()
        .map(|p| {
            match *p {
                ::Protocol::Sslv3 => Protocol::Ssl3,
                ::Protocol::Tlsv10 => Protocol::Tls10,
                ::Protocol::Tlsv11 => Protocol::Tls11,
                ::Protocol::Tlsv12 => Protocol::Tls12,
                ::Protocol::__NonExhaustive => unreachable!(),
            }
        })
        .collect()
}

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

#[derive(Clone)]
pub struct Pkcs12 {
    cert: CertContext,
}

impl Pkcs12 {
    pub fn from_der(buf: &[u8], pass: &str) -> Result<Pkcs12, Error> {
        let mut store = try!(PfxImportOptions::new()
            .password(pass)
            .import(buf));
        let mut identity = None;

        for cert in store.certs() {
            if cert.private_key().silent(true).compare_key(true).acquire().is_ok() {
                identity = Some(cert);
            }
        }

        let identity = match identity {
            Some(identity) => identity,
            None => {
                return Err(io::Error::new(io::ErrorKind::InvalidInput,
                                          "No identity found in PKCS #12 archive").into());
            },
        };

        Ok(Pkcs12 {
            cert: identity,
        })
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

pub struct TlsConnectorBuilder(TlsConnector);

impl TlsConnectorBuilder {
    pub fn identity(&mut self, pkcs12: Pkcs12) -> Result<(), Error> {
        self.0.cert = Some(pkcs12.cert);
        Ok(())
    }

    pub fn supported_protocols(&mut self, protocols: &[::Protocol]) -> Result<(), Error> {
        self.0.protocols = convert_protocols(protocols);
        Ok(())
    }

    pub fn build(self) -> Result<TlsConnector, Error> {
        Ok(self.0)
    }
}

pub struct TlsConnector {
    cert: Option<CertContext>,
    protocols: Vec<Protocol>,
}

impl TlsConnector {
    pub fn builder() -> Result<TlsConnectorBuilder, Error> {
        Ok(TlsConnectorBuilder(TlsConnector {
            cert: None,
            protocols: vec![Protocol::Tls10, Protocol::Tls11, Protocol::Tls12],
        }))
    }

    pub fn connect<S>(&self,
                      domain: &str,
                      stream: S)
                      -> Result<TlsStream<S>, HandshakeError<S>>
        where S: io::Read + io::Write
    {
        let mut builder = SchannelCred::builder();
        builder.enabled_protocols(&self.protocols);
        if let Some(cert) = self.cert.as_ref() {
            builder.cert(cert.clone());
        }
        let cred = try!(builder.acquire(Direction::Outbound));
        match tls_stream::Builder::new().domain(domain).connect(cred, stream) {
            Ok(s) => Ok(TlsStream(s)),
            Err(e) => Err(e.into()),
        }
    }
}

pub struct TlsAcceptorBuilder(TlsAcceptor);

impl TlsAcceptorBuilder {
    pub fn supported_protocols(&mut self, protocols: &[::Protocol]) -> Result<(), Error> {
        self.0.protocols = convert_protocols(protocols);
        Ok(())
    }

    pub fn build(self) -> Result<TlsAcceptor, Error> {
        Ok(self.0)
    }
}

pub struct TlsAcceptor {
    cert: CertContext,
    protocols: Vec<Protocol>,
}

impl TlsAcceptor {
    pub fn builder(pkcs12: Pkcs12) -> Result<TlsAcceptorBuilder, Error> {
        Ok(TlsAcceptorBuilder(TlsAcceptor {
            cert: pkcs12.cert,
            protocols: vec![Protocol::Tls10, Protocol::Tls11, Protocol::Tls12],
        }))
    }

    pub fn accept<S>(&self, stream: S) -> Result<TlsStream<S>, HandshakeError<S>>
        where S: io::Read + io::Write
    {
        let mut builder = SchannelCred::builder();
        builder.enabled_protocols(&self.protocols);
        builder.cert(self.cert.clone());
        // FIXME we're probably missing the certificate chain?
        let cred = try!(builder.acquire(Direction::Inbound));
        match tls_stream::Builder::new().accept(cred, stream) {
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
    pub fn buffered_read_size(&self) -> Result<usize, Error> {
        Ok(self.0.get_buf().len())
    }

    pub fn shutdown(&mut self) -> io::Result<()> {
        try!(self.0.shutdown());
        Ok(())
    }

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

/// SChannel-specific extensions to `TlsStream`.
pub trait TlsStreamExt<S> {
    /// Returns a shared reference to the SChannel `TlsStream`.
    fn raw_stream(&self) -> &tls_stream::TlsStream<S>;

    /// Returns a mutable reference to the SChannel `TlsStream`.
    fn raw_stream_mut(&mut self) -> &mut tls_stream::TlsStream<S>;
}

impl<S> TlsStreamExt<S> for ::TlsStream<S> {
    fn raw_stream(&self) -> &tls_stream::TlsStream<S> {
        &(self.0).0
    }

    fn raw_stream_mut(&mut self) -> &mut tls_stream::TlsStream<S> {
        &mut (self.0).0
    }
}
