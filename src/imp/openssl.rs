extern crate openssl;
extern crate openssl_probe;

use self::openssl::error::ErrorStack;
use self::openssl::hash::MessageDigest;
use self::openssl::nid::Nid;
use self::openssl::pkcs12::Pkcs12;
use self::openssl::pkey::PKey;
use self::openssl::ssl::{
    self, MidHandshakeSslStream, SslAcceptor, SslConnector, SslContextBuilder, SslMethod,
    SslVerifyMode,
};
use self::openssl::x509::{X509, store::X509StoreBuilder, X509VerifyResult};
use std::error;
use std::fmt;
use std::io;
use std::sync::Once;

use crate::{Protocol, TlsAcceptorBuilder, TlsConnectorBuilder};
use self::openssl::pkey::Private;

#[cfg(feature = "alpn")]
use crate::ApplicationProtocol;


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
    let mut options = SslOptions::empty();
    options |= match min {
        None => SslOptions::empty(),
        Some(Protocol::Sslv3) => SslOptions::NO_SSLV2,
        Some(Protocol::Tlsv10) => SslOptions::NO_SSLV2 | SslOptions::NO_SSLV3,
        Some(Protocol::Tlsv11) => {
            SslOptions::NO_SSLV2 | SslOptions::NO_SSLV3 | SslOptions::NO_TLSV1
        }
        Some(Protocol::Tlsv12) => {
            SslOptions::NO_SSLV2
                | SslOptions::NO_SSLV3
                | SslOptions::NO_TLSV1
                | SslOptions::NO_TLSV1_1
        }
        Some(Protocol::__NonExhaustive) => unreachable!(),
    };
    options |= match max {
        None | Some(Protocol::Tlsv12) => SslOptions::empty(),
        Some(Protocol::Tlsv11) => SslOptions::NO_TLSV1_2,
        Some(Protocol::Tlsv10) => SslOptions::NO_TLSV1_1 | SslOptions::NO_TLSV1_2,
        Some(Protocol::Sslv3) => {
            SslOptions::NO_TLSV1 | SslOptions::NO_TLSV1_1 | SslOptions::NO_TLSV1_2
        }
        Some(Protocol::__NonExhaustive) => unreachable!(),
    };

    ctx.set_options(options);

    Ok(())
}

fn init_trust() {
    static ONCE: Once = Once::new();
    ONCE.call_once(openssl_probe::init_ssl_cert_env_vars);
}

#[cfg(target_os = "android")]
fn load_android_root_certs(connector: &mut SslContextBuilder) -> Result<(), Error> {
    use std::fs;

    if let Ok(dir) = fs::read_dir("/system/etc/security/cacerts") {
        let certs = dir
            .filter_map(|r| r.ok())
            .filter_map(|e| fs::read(e.path()).ok())
            .filter_map(|b| X509::from_pem(&b).ok());
        for cert in certs {
            if let Err(err) = connector.cert_store_mut().add_cert(cert) {
                debug!("load_android_root_certs error: {:?}", err);
            }
        }
    }

    Ok(())
}

#[derive(Debug)]
pub enum Error {
    Normal(ErrorStack),
    Ssl(ssl::Error, X509VerifyResult),
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            Error::Normal(ref e) => error::Error::source(e),
            Error::Ssl(ref e, _) => error::Error::source(e),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Normal(ref e) => fmt::Display::fmt(e, fmt),
            Error::Ssl(ref e, X509VerifyResult::OK) => fmt::Display::fmt(e, fmt),
            Error::Ssl(ref e, v) => write!(fmt, "{} ({})", e, v),
        }
    }
}

impl From<ErrorStack> for Error {
    fn from(err: ErrorStack) -> Error {
        Error::Normal(err)
    }
}

#[derive(Clone)]
pub struct Identity {
    pkey: PKey<Private>,
    cert: X509,
    chain: Vec<X509>,
}

impl Identity {
    pub fn from_pkcs12(buf: &[u8], pass: &str) -> Result<Identity, Error> {
        let pkcs12 = Pkcs12::from_der(buf)?;
        let parsed = pkcs12.parse(pass)?;
        Ok(Identity {
            pkey: parsed.pkey,
            cert: parsed.cert,
            chain: parsed.chain.into_iter().flatten().collect(),
        })
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

    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        let der = self.0.to_der()?;
        Ok(der)
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
            ssl::HandshakeError::Failure(e) => {
                let v = e.ssl().verify_result();
                HandshakeError::Failure(Error::Ssl(e.into_error(), v))
            }
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

#[derive(Clone)]
pub struct TlsConnector {
    connector: SslConnector,
    use_sni: bool,
    accept_invalid_hostnames: bool,
    accept_invalid_certs: bool,
}

impl TlsConnector {
    pub fn new(builder: &TlsConnectorBuilder) -> Result<TlsConnector, Error> {
        init_trust();

        let mut connector = SslConnector::builder(SslMethod::tls())?;
        if let Some(ref identity) = builder.identity {
            connector.set_certificate(&identity.0.cert)?;
            connector.set_private_key(&identity.0.pkey)?;
            for cert in identity.0.chain.iter().rev() {
                connector.add_extra_chain_cert(cert.to_owned())?;
            }
        }

        supported_protocols(builder.min_protocol, builder.max_protocol, &mut connector)?;

        if builder.disable_built_in_roots {
            connector.set_cert_store(X509StoreBuilder::new()?.build());
        }

        for cert in &builder.root_certificates {
            if let Err(err) = connector.cert_store_mut().add_cert((cert.0).0.clone()) {
                debug!("add_cert error: {:?}", err);
            }
        }

        #[cfg(target_os = "android")]
        load_android_root_certs(&mut connector)?;

        #[cfg(feature = "alpn")]
        {
            if let Some(alpn) = &builder.alpn {
                if !alpn.is_empty() {
                    connector.set_alpn_protos(alpn.as_ref())?;
                }
            }
        }

        Ok(TlsConnector {
            connector: connector.build(),
            use_sni: builder.use_sni,
            accept_invalid_hostnames: builder.accept_invalid_hostnames,
            accept_invalid_certs: builder.accept_invalid_certs,
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

#[derive(Clone)]
pub struct TlsAcceptor(SslAcceptor);

impl TlsAcceptor {
    pub fn new(builder: &TlsAcceptorBuilder) -> Result<TlsAcceptor, Error> {
        let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
        acceptor.set_private_key(&builder.identity.0.pkey)?;
        acceptor.set_certificate(&builder.identity.0.cert)?;
        for cert in builder.identity.0.chain.iter().rev() {
            acceptor.add_extra_chain_cert(cert.to_owned())?;
        }
        supported_protocols(builder.min_protocol, builder.max_protocol, &mut acceptor)?;

        Ok(TlsAcceptor(acceptor.build()))
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

impl<S> TlsStream<S> {
    pub fn get_ref(&self) -> &S {
        self.0.get_ref()
    }

    pub fn get_mut(&mut self) -> &mut S {
        self.0.get_mut()
    }

    #[cfg(feature = "alpn")]
    pub fn negotiated_alpn(&self) -> Result<Option<ApplicationProtocol<Vec<u8>>>, Error> {
        let ssl = self.0.ssl();
        match ssl.selected_alpn_protocol() {
            Some(proto) => Ok(Some(ApplicationProtocol::new(proto.to_vec()))),
            None => Ok(None),
        }
    }
}

impl<S: io::Read + io::Write> TlsStream<S> {
    pub fn buffered_read_size(&self) -> Result<usize, Error> {
        Ok(self.0.ssl().pending())
    }

    pub fn peer_certificate(&self) -> Result<Option<Certificate>, Error> {
        Ok(self.0.ssl().peer_certificate().map(Certificate))
    }

    pub fn tls_server_end_point(&self) -> Result<Option<Vec<u8>>, Error> {
        let cert = if self.0.ssl().is_server() {
            self.0.ssl().certificate().map(|x| x.to_owned())
        } else {
            self.0.ssl().peer_certificate()
        };

        let cert = match cert {
            Some(cert) => cert,
            None => return Ok(None),
        };

        let algo_nid = cert.signature_algorithm().object().nid();
        let signature_algorithms = match algo_nid.signature_algorithms() {
            Some(algs) => algs,
            None => return Ok(None),
        };

        let md = match signature_algorithms.digest {
            Nid::MD5 | Nid::SHA1 => MessageDigest::sha256(),
            nid => match MessageDigest::from_nid(nid) {
                Some(md) => md,
                None => return Ok(None),
            },
        };

        let digest = cert.digest(md)?;

        Ok(Some(digest.to_vec()))
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


#[cfg(feature = "alpn")]
pub use self::alpn::*;

#[cfg(feature = "alpn")]
mod alpn {
    use crate::ApplicationProtocol;

    /// Application-Layer Protocol list
    #[derive(Clone)]
    pub struct ApplicationProtocols {
        inner: Vec<u8>,
    }

    impl ApplicationProtocols {
        /// Returns the number of protocols.
        pub fn len(&self) -> usize {
            let mut n = 0usize;
            let mut idx = 0usize;
            loop {
                if idx >= self.inner.len() {
                    break;
                }

                let len = self.inner[idx] as usize;
                idx += len + 1;
                n += 1;
            }

            n
        }

        /// Returns true if the protocols is empty.
        pub fn is_empty(&self) -> bool {
            self.len() == 0
        }

        /// Returns an iterator over the protocols.
        pub fn iter<'a>(&'a self) -> ApplicationProtocolIter<'a> {
            ApplicationProtocolIter { protos: &self.inner, index: 0 }
        }

        /// Unwraps the value.
        pub fn into_inner(self) -> Vec<u8> {
            self.inner
        }
    }

    impl AsRef<[u8]> for ApplicationProtocols {
        #[inline]
        fn as_ref(&self) -> &[u8] {
            &self.inner
        }
    }

    /// Immutable ApplicationProtocol iterator
    pub struct ApplicationProtocolIter<'a> {
        protos: &'a [u8],
        index: usize,
    }

    impl<'a> Iterator for ApplicationProtocolIter<'a> {
        type Item = ApplicationProtocol<&'a [u8]>;

        fn count(self) -> usize {
            self.protos.len()
        }

        fn next(&mut self) -> Option<Self::Item> {
            let protos = &self.protos;
            
            if self.index >= protos.len() {
                return None;
            }

            let item = {
                let len = protos[self.index] as usize;
                let start = self.index + 1;
                let end = start + len;
                let proto = &protos[start..end];
                self.index += len + 1;

                proto
            };
            
            Some(ApplicationProtocol::new(item))
        }
    }


    fn from_str<T: AsRef<[P]>, P: AsRef<str>>(protos: T) -> ApplicationProtocols {
        let protos = protos.as_ref();
        let inner = {
            let capacity = protos.len();
            protos.iter().fold(Vec::with_capacity(capacity), |mut acc, proto| {
                let proto = proto.as_ref().as_bytes();
                let len = proto.len();

                if len > 0 && len <= std::u8::MAX as usize {
                    acc.push(len as u8);
                    acc.extend_from_slice(proto);
                }

                acc
            })
        };
        
        ApplicationProtocols { inner }
    }

    fn try_from_slice<T: AsRef<[P]>, P: AsRef<[u8]>>(protos: T) -> Result<ApplicationProtocols, std::str::Utf8Error> {
        let protos = protos.as_ref();
        let inner = {
            let capacity = protos.len();
            protos.iter().fold(Vec::with_capacity(capacity), |mut acc, proto| {
                let proto = proto.as_ref();
                let len = proto.len();

                if len > 0 && len <= std::u8::MAX as usize {
                    acc.push(len as u8);
                    acc.extend_from_slice(proto);
                }

                acc
            })
        };

        Ok(ApplicationProtocols { inner })
    }

    impl From<Vec<String>> for ApplicationProtocols {
        fn from(protos: Vec<String>) -> Self {
            from_str(protos)
        }
    }

    impl From<&[&str]> for ApplicationProtocols {
        fn from(protos: &[&str]) -> Self {
            from_str(protos)
        }
    }

    macro_rules! str_impls {
        ($($N:literal)+) => {
            $(
                impl From<&[&str; $N]> for ApplicationProtocols {
                    fn from(protos: &[&str; $N]) -> Self {
                        from_str(protos)
                    }
                }
            )+
        }
    }

    str_impls! {
         0  1  2  3  4  5  6  7  8  9
        10 11 12 13 14 15 16 17 18 19
        20 21 22 23 24 25 26 27 28 29
        30 31 32
    }



    impl std::convert::TryFrom<Vec<Vec<u8>>> for ApplicationProtocols {
        type Error = std::str::Utf8Error;

        fn try_from(protos: Vec<Vec<u8>>) -> Result<Self, Self::Error> {
            try_from_slice(protos)
        }
    }

    impl std::convert::TryFrom<&[&[u8]]> for ApplicationProtocols {
        type Error = std::str::Utf8Error;

        fn try_from(protos: &[&[u8]]) -> Result<Self, Self::Error> {
            try_from_slice(protos)
        }
    }

    macro_rules! slice_impls {
        ($($N:literal)+) => {
            $(
                impl std::convert::TryFrom<&[&[u8]; $N]> for ApplicationProtocols {
                    type Error = std::str::Utf8Error;

                    fn try_from(protos: &[&[u8]; $N]) -> Result<Self, Self::Error> {
                        try_from_slice(protos)
                    }
                }
            )+
        }
    }

    slice_impls! {
         0  1  2  3  4  5  6  7  8  9
        10 11 12 13 14 15 16 17 18 19
        20 21 22 23 24 25 26 27 28 29
        30 31 32
    }
}