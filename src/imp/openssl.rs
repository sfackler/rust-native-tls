extern crate openssl;

use self::openssl::error::ErrorStack;
use self::openssl::pkcs12::{ParsedPkcs12, Pkcs12};
use self::openssl::ssl::{
    self, MidHandshakeSslStream, SslAcceptor, SslAcceptorBuilder, SslConnector,
    SslConnectorBuilder, SslContextBuilder, SslMethod, SslVerifyMode,
};
use self::openssl::x509::X509;
use std::error;
use std::fmt;
use std::io;

use Protocol;

#[cfg(have_min_max_version)]
fn supported_protocols(
    min: Option<Protocol>,
    max: Option<Protocol>,
    ctx: &mut SslContextBuilder,
) -> Result<(), ErrorStack> {
    use self::openssl::ssl::SslVersion;

    fn cvt(p: Protocol) -> SslVersion {
        match p {
            Protocol::Sslv3 => SslVersion::SSL3,
            Protocol::Tlsv10 => SslVersion::TLS1,
            Protocol::Tlsv11 => SslVersion::TLS1_1,
            Protocol::Tlsv12 => SslVersion::TLS1_2,
            Protocol::__NonExhaustive => unreachable!(),
        }
    }

    ctx.set_min_proto_version(min.map(cvt))?;
    ctx.set_max_proto_version(max.map(cvt))?;

    Ok(())
}

#[cfg(not(have_min_max_version))]
fn supported_protocols(
    min: Option<Protocol>,
    max: Option<Protocol>,
    ctx: &mut SslContextBuilder,
) -> Result<(), ErrorStack> {
    use self::openssl::ssl::SslOptions;

    let no_ssl_mask = SslOptions::NO_SSLV2
        | SslOptions::NO_SSLV3
        | SslOptions::NO_TLSV1
        | SslOptions::NO_TLSV1_1
        | SslOptions::NO_TLSV1_2;

    ctx.clear_options(no_ssl_mask);
    let mut options = SslOptions::NO_SSLV2;
    match min {
        None | Some(Protocol::Sslv3) => {}
        Some(Protocol::Tlsv10) => options |= SslOptions::NO_SSLV3,
        Some(Protocol::Tlsv11) => options |= SslOptions::NO_SSLV3 | SslOptions::NO_TLSV1,
        Some(Protocol::Tlsv12) => {
            options |= SslOptions::NO_SSLV3 | SslOptions::NO_TLSV1 | SslOptions::NO_TLSV1_1
        }
        Some(Protocol::__NonExhaustive) => unreachable!(),
    }
    match max {
        None | Some(Protocol::Tlsv12) => {}
        Some(Protocol::Tlsv11) => options |= SslOptions::NO_TLSV1_2,
        Some(Protocol::Tlsv10) => options |= SslOptions::NO_TLSV1_1 | SslOptions::NO_TLSV1_2,
        Some(Protocol::Sslv3) => {
            options |= SslOptions::NO_TLSV1_0 | SslOptions::NO_TLSV1_1 | SslOptions::NO_TLSV1_2
        }
    }

    ctx.set_options(options);

    Ok(())
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

pub struct Identity(ParsedPkcs12);

impl Identity {
    pub fn from_pkcs12(buf: &[u8], pass: &str) -> Result<Identity, Error> {
        let pkcs12 = Pkcs12::from_der(buf)?;
        let parsed = pkcs12.parse(pass)?;
        Ok(Identity(parsed))
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
    min_protocol: Option<Protocol>,
    max_protocol: Option<Protocol>,
}

impl TlsConnectorBuilder {
    pub fn identity(&mut self, identity: Identity) -> Result<(), Error> {
        // FIXME clear chain certs to clean up if called multiple times
        self.connector.set_certificate(&identity.0.cert)?;
        self.connector.set_private_key(&identity.0.pkey)?;
        self.connector.check_private_key()?;
        if let Some(chain) = identity.0.chain {
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

    pub fn min_protocol_version(&mut self, protocol: Option<Protocol>) -> Result<(), Error> {
        self.min_protocol = protocol;
        Ok(())
    }

    pub fn max_protocol_version(&mut self, protocol: Option<Protocol>) -> Result<(), Error> {
        self.max_protocol = protocol;
        Ok(())
    }

    pub fn build(mut self) -> Result<TlsConnector, Error> {
        supported_protocols(self.min_protocol, self.max_protocol, &mut self.connector)?;

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
            min_protocol: None,
            max_protocol: None,
        })
    }

    pub fn connect<S>(&self, domain: &str, stream: S) -> Result<TlsStream<S>, HandshakeError<S>>
    where
        S: io::Read + io::Write,
    {
        let mut ssl = self
            .connector
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

pub struct TlsAcceptorBuilder {
    acceptor: SslAcceptorBuilder,
    min_protocol: Option<Protocol>,
    max_protocol: Option<Protocol>,
}

impl TlsAcceptorBuilder {
    pub fn min_protocol_version(&mut self, protocol: Option<Protocol>) -> Result<(), Error> {
        self.min_protocol = protocol;
        Ok(())
    }

    pub fn max_protocol_version(&mut self, protocol: Option<Protocol>) -> Result<(), Error> {
        self.max_protocol = protocol;
        Ok(())
    }

    pub fn build(mut self) -> Result<TlsAcceptor, Error> {
        supported_protocols(self.min_protocol, self.max_protocol, &mut self.acceptor)?;

        Ok(TlsAcceptor(self.acceptor.build()))
    }
}

#[derive(Clone)]
pub struct TlsAcceptor(SslAcceptor);

impl TlsAcceptor {
    pub fn builder(identity: Identity) -> Result<TlsAcceptorBuilder, Error> {
        let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
        acceptor.set_private_key(&identity.0.pkey)?;
        acceptor.set_certificate(&identity.0.cert)?;
        if let Some(chain) = identity.0.chain {
            for cert in chain {
                acceptor.add_extra_chain_cert(cert)?;
            }
        }

        Ok(TlsAcceptorBuilder {
            acceptor,
            min_protocol: None,
            max_protocol: None,
        })
    }

    pub fn accept<S>(&self, stream: S) -> Result<TlsStream<S>, HandshakeError<S>>
    where
        S: io::Read + io::Write,
    {
        let s = self.0.accept(stream)?;
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

    pub fn shutdown(&mut self) -> io::Result<()> {
        match self.0.shutdown() {
            Ok(_) => Ok(()),
            Err(ref e) if e.code() == ssl::ErrorCode::ZERO_RETURN => Ok(()),
            Err(e) => Err(e
                .into_io_error()
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
