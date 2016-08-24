extern crate openssl;
extern crate openssl_verify;

use std::io;
use std::fmt;
use std::error;
use self::openssl::crypto::pkey::PKey;
use self::openssl::crypto::pkcs12;
use self::openssl::error::ErrorStack;
use self::openssl::ssl::{self, SslContext, SslMethod, SSL_VERIFY_PEER, IntoSsl, SSL_OP_NO_SSLV2,
                         SSL_OP_NO_SSLV3, SSL_OP_NO_COMPRESSION, MidHandshakeSslStream};
use self::openssl::x509::X509;
use self::openssl_verify::verify_callback;

pub struct Error(ssl::Error);

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

impl From<ssl::Error> for Error {
    fn from(err: ssl::Error) -> Error {
        Error(err)
    }
}

impl From<ErrorStack> for Error {
    fn from(err: ErrorStack) -> Error {
        ssl::Error::Ssl(err).into()
    }
}

pub struct Pkcs12 {
    cert: X509,
    pkey: PKey,
    chain: Vec<X509>,
}

impl Pkcs12 {
    pub fn from_der(buf: &[u8], pass: &str) -> Result<Pkcs12, Error> {
        let pkcs12 = try!(pkcs12::Pkcs12::from_der(buf));
        let parsed = try!(pkcs12.parse(pass));

        Ok(Pkcs12 {
            cert: parsed.cert,
            pkey: parsed.pkey,
            chain: parsed.chain.into_iter().collect(),
        })
    }
}

pub struct MidHandshakeTlsStream<S>(MidHandshakeSslStream<S>);

impl<S> fmt::Debug for MidHandshakeTlsStream<S>
    where S: fmt::Debug
{
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.0, fmt)
    }
}

impl<S> MidHandshakeTlsStream<S> {
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

impl<S> From<ssl::HandshakeError<S>> for HandshakeError<S> {
    fn from(e: ssl::HandshakeError<S>) -> HandshakeError<S> {
        match e {
            ssl::HandshakeError::Failure(e) => HandshakeError::Failure(Error(e)),
            ssl::HandshakeError::Interrupted(s) => {
                HandshakeError::Interrupted(MidHandshakeTlsStream(s))
            }
        }
    }
}

impl<S> From<ErrorStack> for HandshakeError<S> {
    fn from(e: ErrorStack) -> HandshakeError<S> {
        HandshakeError::Failure(e.into())
    }
}

fn ctx() -> Result<SslContext, Error> {
    let mut ctx = try!(SslContext::new(SslMethod::Sslv23));
    try!(ctx.set_default_verify_paths());
    Ok(ctx)
}

pub struct ClientBuilder(SslContext);

impl ClientBuilder {
    pub fn new() -> Result<ClientBuilder, Error> {
        ctx().map(ClientBuilder)
    }

    pub fn handshake<S>(&self,
                        domain: &str,
                        stream: S)
                        -> Result<TlsStream<S>, HandshakeError<S>>
        where S: io::Read + io::Write
    {
        let mut ssl = try!(self.0.into_ssl());
        try!(ssl.set_hostname(domain));
        let domain = domain.to_owned();
        ssl.set_verify_callback(SSL_VERIFY_PEER, move |p, x| verify_callback(&domain, p, x));

        let s = try!(ssl::SslStream::connect(ssl, stream));
        Ok(TlsStream(s))
    }
}

pub struct ServerBuilder(SslContext);

impl ServerBuilder {
    pub fn new(pkcs12: Pkcs12) -> Result<ServerBuilder, Error> {
        let mut ctx = try!(ctx());
        try!(ctx.set_certificate(&pkcs12.cert));
        try!(ctx.set_private_key(&pkcs12.pkey));
        try!(ctx.check_private_key());
        for cert in &pkcs12.chain {
            try!(ctx.add_extra_chain_cert(&cert));
        }
        Ok(ServerBuilder(ctx))
    }

    pub fn handshake<S>(&self, stream: S) -> Result<TlsStream<S>, HandshakeError<S>>
        where S: io::Read + io::Write
    {
        let s = try!(ssl::SslStream::accept(&self.0, stream));
        Ok(TlsStream(s))
    }
}

pub struct TlsStream<S>(ssl::SslStream<S>);

impl<S: fmt::Debug> fmt::Debug for TlsStream<S> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.0, fmt)
    }
}

impl<S: io::Read + io::Write> TlsStream<S> {
    pub fn buffered_read_size(&self) -> Result<usize, Error> {
        Ok(self.0.ssl().pending())
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

/// OpenSSL-specific extensions to `TlsStream`.
pub trait TlsStreamExt<S> {
    /// Returns a shared reference to the OpenSSL `SslStream`.
    fn raw_stream(&self) -> &ssl::SslStream<S>;

    /// Returns a mutable reference to the OpenSSL `SslStream`.
    fn raw_stream_mut(&mut self) -> &mut ssl::SslStream<S>;
}

impl<S> TlsStreamExt<S> for ::TlsStream<S> {
    fn raw_stream(&self) -> &ssl::SslStream<S> {
        &(self.0).0
    }

    fn raw_stream_mut(&mut self) -> &mut ssl::SslStream<S> {
        &mut (self.0).0
    }
}
