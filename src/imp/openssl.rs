extern crate openssl;

use self::openssl::error::ErrorStack;
use self::openssl::pkcs12;
use self::openssl::ssl::{self, MidHandshakeSslStream, SslAcceptor, SslAcceptorBuilder,
                         SslConnector, SslConnectorBuilder, SslContextBuilder, SslMethod,
                         SslOptions, SslVerifyMode};
use self::openssl::x509::X509;
use std::error;
use std::fmt;
use std::io;

use Protocol;

fn supported_protocols(protocols: &[Protocol], ctx: &mut SslContextBuilder) {
    #[cfg(no_ssl_mask)]
    let no_ssl_mask = SslOptions::NO_SSLV2 | SslOptions::NO_SSLV3 | SslOptions::NO_TLSV1
        | SslOptions::NO_TLSV1_1 | SslOptions::NO_TLSV1_2;
    #[cfg(not(no_ssl_mask))]
    let no_ssl_mask = SslOptions::NO_SSL_MASK;

    ctx.clear_options(no_ssl_mask);
    let mut options = no_ssl_mask;
    for protocol in protocols {
        let op = match *protocol {
            Protocol::Sslv3 => SslOptions::NO_SSLV3,
            Protocol::Tlsv10 => SslOptions::NO_TLSV1,
            Protocol::Tlsv11 => SslOptions::NO_TLSV1_1,
            Protocol::Tlsv12 => SslOptions::NO_TLSV1_2,
            Protocol::__NonExhaustive => unreachable!(),
        };
        options &= !op;
    }
    ctx.set_options(options);
}

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
        err.into()
    }
}

pub struct Pkcs12(pkcs12::ParsedPkcs12);

impl Pkcs12 {
    pub fn from_der(buf: &[u8], pass: &str) -> Result<Pkcs12, Error> {
        let pkcs12 = pkcs12::Pkcs12::from_der(buf)?;
        let parsed = pkcs12.parse(pass)?;
        Ok(Pkcs12(parsed))
    }
}

#[derive(Clone)]
pub struct Certificate(X509);

impl Certificate {
    pub fn from_der(buf: &[u8]) -> Result<Certificate, Error> {
        let cert = X509::from_der(buf)?;
        Ok(Certificate(cert))
    }
    pub fn from_pem(buf: &[u8]) -> Result<Certificate, Error> {
        let cert = X509::from_pem(buf)?;
        Ok(Certificate(cert))
    }
}

pub struct MidHandshakeTlsStream<S>(MidHandshakeSslStream<S>);

impl<S> fmt::Debug for MidHandshakeTlsStream<S>
where
    S: fmt::Debug,
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
where
    S: io::Read + io::Write,
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
    WouldBlock(MidHandshakeTlsStream<S>),
}

impl<S> From<ssl::HandshakeError<S>> for HandshakeError<S> {
    fn from(e: ssl::HandshakeError<S>) -> HandshakeError<S> {
        match e {
            ssl::HandshakeError::SetupFailure(e) => HandshakeError::Failure(e.into()),
            ssl::HandshakeError::Failure(e) => HandshakeError::Failure(Error(e.into_error())),
            ssl::HandshakeError::WouldBlock(s) => {
                HandshakeError::WouldBlock(MidHandshakeTlsStream(s))
            }
        }
    }
}

impl<S> From<ErrorStack> for HandshakeError<S> {
    fn from(e: ErrorStack) -> HandshakeError<S> {
        HandshakeError::Failure(e.into())
    }
}

pub struct TlsConnectorBuilder {
    connector: SslConnectorBuilder,
    use_sni: bool,
    accept_invalid_hostnames: bool,
    accept_invalid_certs: bool,
}

impl TlsConnectorBuilder {
    pub fn identity(&mut self, pkcs12: Pkcs12) -> Result<(), Error> {
        // FIXME clear chain certs to clean up if called multiple times
        self.connector.set_certificate(&pkcs12.0.cert)?;
        self.connector.set_private_key(&pkcs12.0.pkey)?;
        self.connector.check_private_key()?;
        if let Some(chain) = pkcs12.0.chain {
            for cert in chain {
                self.connector.add_extra_chain_cert(cert)?;
            }
        }
        Ok(())
    }

    pub fn add_root_certificate(&mut self, cert: Certificate) -> Result<(), Error> {
        self.connector.cert_store_mut().add_cert(cert.0)?;
        Ok(())
    }

    pub fn use_sni(&mut self, use_sni: bool) {
        self.use_sni = use_sni;
    }

    pub fn danger_accept_invalid_hostnames(&mut self, accept_invalid_hostnames: bool) {
        self.accept_invalid_hostnames = accept_invalid_hostnames;
    }

    pub fn danger_accept_invalid_certs(&mut self, accept_invalid_certs: bool) {
        self.accept_invalid_certs = accept_invalid_certs;
    }

    pub fn supported_protocols(&mut self, protocols: &[Protocol]) -> Result<(), Error> {
        supported_protocols(protocols, &mut self.connector);
        Ok(())
    }

    pub fn build(self) -> Result<TlsConnector, Error> {
        Ok(TlsConnector {
            connector: self.connector.build(),
            use_sni: self.use_sni,
            accept_invalid_hostnames: self.accept_invalid_hostnames,
            accept_invalid_certs: self.accept_invalid_certs,
        })
    }
}

#[derive(Clone)]
pub struct TlsConnector {
    connector: SslConnector,
    use_sni: bool,
    accept_invalid_hostnames: bool,
    accept_invalid_certs: bool,
}

impl TlsConnector {
    pub fn builder() -> Result<TlsConnectorBuilder, Error> {
        Ok(TlsConnectorBuilder {
            connector: SslConnector::builder(SslMethod::tls())?,
            use_sni: true,
            accept_invalid_hostnames: false,
            accept_invalid_certs: false,
        })
    }

    pub fn connect<S>(&self, domain: &str, stream: S) -> Result<TlsStream<S>, HandshakeError<S>>
    where
        S: io::Read + io::Write,
    {
        let mut ssl = self.connector
            .configure()?
            .use_server_name_indication(self.use_sni)
            .verify_hostname(!self.accept_invalid_hostnames);
        if self.accept_invalid_certs {
            ssl.set_verify(SslVerifyMode::NONE);
        }

        let s = ssl.connect(domain, stream)?;
        Ok(TlsStream(s))
    }
}

/// OpenSSL-specific extensions to `TlsConnectorBuilder`.
pub trait TlsConnectorBuilderExt {
    /// Initialize `TlsAcceptorBuilderExt` from an `SslAcceptorBuilder`.
    fn from_openssl(builder: SslConnectorBuilder) -> Self;

    /// Returns a shared reference to the inner `SslConnectorBuilder`.
    fn builder(&self) -> &SslConnectorBuilder;

    /// Returns a mutable reference to the inner `SslConnectorBuilder`.
    fn builder_mut(&mut self) -> &mut SslConnectorBuilder;
}

impl TlsConnectorBuilderExt for ::TlsConnectorBuilder {
    fn from_openssl(builder: SslConnectorBuilder) -> ::TlsConnectorBuilder {
        ::TlsConnectorBuilder(TlsConnectorBuilder {
            connector: builder,
            use_sni: true,
            accept_invalid_hostnames: false,
            accept_invalid_certs: false,
        })
    }

    fn builder(&self) -> &SslConnectorBuilder {
        &(self.0).connector
    }

    fn builder_mut(&mut self) -> &mut SslConnectorBuilder {
        &mut (self.0).connector
    }
}

pub struct TlsAcceptorBuilder(SslAcceptorBuilder);

impl TlsAcceptorBuilder {
    pub fn supported_protocols(&mut self, protocols: &[Protocol]) -> Result<(), Error> {
        supported_protocols(protocols, &mut self.0);
        Ok(())
    }

    pub fn build(self) -> Result<TlsAcceptor, Error> {
        Ok(TlsAcceptor(self.0.build()))
    }
}

#[derive(Clone)]
pub struct TlsAcceptor(SslAcceptor);

impl TlsAcceptor {
    pub fn builder(pkcs12: Pkcs12) -> Result<TlsAcceptorBuilder, Error> {
        let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
        builder.set_private_key(&pkcs12.0.pkey)?;
        builder.set_certificate(&pkcs12.0.cert)?;
        if let Some(chain) = pkcs12.0.chain {
            for cert in chain {
                builder.add_extra_chain_cert(cert)?;
            }
        }
        Ok(TlsAcceptorBuilder(builder))
    }

    pub fn accept<S>(&self, stream: S) -> Result<TlsStream<S>, HandshakeError<S>>
    where
        S: io::Read + io::Write,
    {
        let s = self.0.accept(stream)?;
        Ok(TlsStream(s))
    }
}

/// OpenSSL-specific extensions to `TlsAcceptorBuilder`.
pub trait TlsAcceptorBuilderExt {
    /// Initialize `TlsAcceptorBuilderExt` from an `SslAcceptorBuilder`.
    fn from_openssl(builder: SslAcceptorBuilder) -> Self;

    /// Returns a shared reference to the inner `SslAcceptorBuilder`.
    fn builder(&self) -> &SslAcceptorBuilder;

    /// Returns a mutable reference to the inner `SslAcceptorBuilder`.
    fn builder_mut(&mut self) -> &mut SslAcceptorBuilder;
}

impl TlsAcceptorBuilderExt for ::TlsAcceptorBuilder {
    fn from_openssl(builder: SslAcceptorBuilder) -> ::TlsAcceptorBuilder {
        ::TlsAcceptorBuilder(TlsAcceptorBuilder(builder))
    }

    fn builder(&self) -> &SslAcceptorBuilder {
        &(self.0).0
    }

    fn builder_mut(&mut self) -> &mut SslAcceptorBuilder {
        &mut (self.0).0
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

    pub fn shutdown(&mut self) -> io::Result<()> {
        match self.0.shutdown() {
            Ok(_) => Ok(()),
            Err(ref e) if e.code() == ssl::ErrorCode::ZERO_RETURN => Ok(()),
            Err(e) => Err(e.into_io_error()
                .unwrap_or_else(|e| io::Error::new(io::ErrorKind::Other, e))),
        }
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

/// OpenSSL-specific extensions to `Error`
pub trait ErrorExt {
    /// Extract the underlying OpenSSL error for inspection.
    fn openssl_error(&self) -> &ssl::Error;
}

impl ErrorExt for ::Error {
    fn openssl_error(&self) -> &ssl::Error {
        &(self.0).0
    }
}
