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
use self::openssl::x509::{store::X509StoreBuilder, X509VerifyResult, X509};
use std::borrow;
use std::collections::HashSet;
use std::error;
use std::fmt;
use std::io;
use std::sync::Once;

use self::openssl::pkey::Private;
use {
    CipherSuiteSet, Protocol, TlsAcceptorBuilder, TlsBulkEncryptionAlgorithm, TlsConnectorBuilder,
    TlsHashAlgorithm, TlsKeyExchangeAlgorithm, TlsSignatureAlgorithm,
};

const CIPHER_STRING_SUFFIX: &[&str] = &[
    "!aNULL",
    "!eNULL",
    "!IDEA",
    "!SEED",
    "!SRP",
    "!PSK",
    "@STRENGTH",
];

fn cartesian_product(
    xs: impl IntoIterator<Item = Vec<&'static str>>,
    ys: impl IntoIterator<Item = &'static str> + Clone,
) -> Vec<Vec<&'static str>> {
    xs.into_iter()
        .flat_map(move |x| ys.clone().into_iter().map(move |y| [&x, &[y][..]].concat()))
        .collect()
}

/// AES-GCM ciphersuites aren't included in AES128 or AES256. However, specifying `AESGCM` in the
/// cipher string doesn't allow us to specify the bitwidth of the AES cipher used, nor does it
/// allow us to specify the bitwidth of the SHA algorithm.
fn expand_gcm_algorithms(cipher_suites: &CipherSuiteSet) -> Vec<&'static str> {
    let first = cipher_suites
        .key_exchange
        .iter()
        .flat_map(|alg| -> &[&str] {
            match alg {
                TlsKeyExchangeAlgorithm::Dhe => &[
                    "DHE-RSA-AES128-GCM-SHA256",
                    "DHE-RSA-AES256-GCM-SHA384",
                    "DHE-DSS-AES128-GCM-SHA256",
                    "DHE-DSS-AES256-GCM-SHA384",
                ],
                TlsKeyExchangeAlgorithm::Ecdhe => &[
                    "ECDHE-RSA-AES128-GCM-SHA256",
                    "ECDHE-RSA-AES256-GCM-SHA384",
                    "ECDHE-ECDSA-AES128-GCM-SHA256",
                    "ECDHE-ECDSA-AES256-GCM-SHA384",
                ],
                TlsKeyExchangeAlgorithm::Rsa => &["AES128-GCM-SHA256", "AES256-GCM-SHA384"],
                TlsKeyExchangeAlgorithm::__NonExhaustive => unreachable!(),
            }
        })
        .copied();
    let rest: &[HashSet<_>] = &[
        cipher_suites
            .signature
            .iter()
            .flat_map(|alg| -> &[&str] {
                match alg {
                    TlsSignatureAlgorithm::Dss => &[
                        "DH-DSS-AES128-GCM-SHA256",
                        "DH-DSS-AES256-GCM-SHA384",
                        "DHE-DSS-AES128-GCM-SHA256",
                        "DHE-DSS-AES256-GCM-SHA384",
                    ],
                    TlsSignatureAlgorithm::Ecdsa => &[
                        "ECDH-ECDSA-AES128-GCM-SHA256",
                        "ECDH-ECDSA-AES256-GCM-SHA384",
                        "ECDHE-ECDSA-AES128-GCM-SHA256",
                        "ECDHE-ECDSA-AES256-GCM-SHA384",
                    ],
                    TlsSignatureAlgorithm::Rsa => &[
                        "AES128-GCM-SHA256",
                        "AES256-GCM-SHA384",
                        "DH-RSA-AES128-GCM-SHA256",
                        "DH-RSA-AES256-GCM-SHA384",
                        "DHE-RSA-AES128-GCM-SHA256",
                        "DHE-RSA-AES256-GCM-SHA384",
                        "ECDH-RSA-AES128-GCM-SHA256",
                        "ECDH-RSA-AES256-GCM-SHA384",
                        "ECDHE-RSA-AES128-GCM-SHA256",
                        "ECDHE-RSA-AES256-GCM-SHA384",
                    ],
                    TlsSignatureAlgorithm::__NonExhaustive => unreachable!(),
                }
            })
            .copied()
            .collect(),
        cipher_suites
            .bulk_encryption
            .iter()
            .flat_map(|alg| -> &[&str] {
                match alg {
                    TlsBulkEncryptionAlgorithm::Aes128 => &[
                        "AES128-GCM-SHA256",
                        "DH-RSA-AES128-GCM-SHA256",
                        "DH-DSS-AES128-GCM-SHA256",
                        "DHE-RSA-AES128-GCM-SHA256",
                        "DHE-DSS-AES128-GCM-SHA256",
                        "ECDH-RSA-AES128-GCM-SHA256",
                        "ECDH-ECDSA-AES128-GCM-SHA256",
                        "ECDHE-RSA-AES128-GCM-SHA256",
                        "ECDHE-ECDSA-AES128-GCM-SHA256",
                    ],
                    TlsBulkEncryptionAlgorithm::Aes256 => &[
                        "AES256-GCM-SHA384",
                        "DH-RSA-AES256-GCM-SHA384",
                        "DH-DSS-AES256-GCM-SHA384",
                        "DHE-RSA-AES256-GCM-SHA384",
                        "DHE-DSS-AES256-GCM-SHA384",
                        "ECDH-RSA-AES256-GCM-SHA384",
                        "ECDH-ECDSA-AES256-GCM-SHA384",
                        "ECDHE-RSA-AES256-GCM-SHA384",
                        "ECDHE-ECDSA-AES256-GCM-SHA384",
                    ],
                    TlsBulkEncryptionAlgorithm::Des => &[],
                    TlsBulkEncryptionAlgorithm::Rc2 => &[],
                    TlsBulkEncryptionAlgorithm::Rc4 => &[],
                    TlsBulkEncryptionAlgorithm::TripleDes => &[],
                    TlsBulkEncryptionAlgorithm::__NonExhaustive => unreachable!(),
                }
            })
            .copied()
            .collect(),
        cipher_suites
            .hash
            .iter()
            .flat_map(|alg| -> &[&str] {
                match alg {
                    TlsHashAlgorithm::Md5 => &[],
                    TlsHashAlgorithm::Sha1 => &[],
                    TlsHashAlgorithm::Sha256 => &[
                        "AES128-GCM-SHA256",
                        "DH-RSA-AES128-GCM-SHA256",
                        "DH-DSS-AES128-GCM-SHA256",
                        "DHE-RSA-AES128-GCM-SHA256",
                        "DHE-DSS-AES128-GCM-SHA256",
                        "ECDH-RSA-AES128-GCM-SHA256",
                        "ECDH-ECDSA-AES128-GCM-SHA256",
                        "ECDHE-RSA-AES128-GCM-SHA256",
                        "ECDHE-ECDSA-AES128-GCM-SHA256",
                    ],
                    TlsHashAlgorithm::Sha384 => &[
                        "AES256-GCM-SHA384",
                        "DH-RSA-AES256-GCM-SHA384",
                        "DH-DSS-AES256-GCM-SHA384",
                        "DHE-RSA-AES256-GCM-SHA384",
                        "DHE-DSS-AES256-GCM-SHA384",
                        "ECDH-RSA-AES256-GCM-SHA384",
                        "ECDH-ECDSA-AES256-GCM-SHA384",
                        "ECDHE-RSA-AES256-GCM-SHA384",
                        "ECDHE-ECDSA-AES256-GCM-SHA384",
                    ],
                    TlsHashAlgorithm::__NonExhaustive => unreachable!(),
                }
            })
            .copied()
            .collect(),
    ];

    first
        .filter(|alg| rest.iter().all(|algs| algs.contains(alg)))
        .collect()
}

fn expand_algorithms(cipher_suites: &CipherSuiteSet) -> String {
    let mut cipher_suite_strings: Vec<Vec<&'static str>> = vec![];

    cipher_suite_strings.extend(cipher_suites.key_exchange.iter().map(|alg| {
        vec![match alg {
            TlsKeyExchangeAlgorithm::Dhe => "DHE",
            TlsKeyExchangeAlgorithm::Ecdhe => "ECDHE",
            TlsKeyExchangeAlgorithm::Rsa => "kRSA",
            TlsKeyExchangeAlgorithm::__NonExhaustive => unreachable!(),
        }]
    }));

    cipher_suite_strings = cartesian_product(
        cipher_suite_strings,
        cipher_suites.signature.iter().map(|alg| match alg {
            TlsSignatureAlgorithm::Dss => "aDSS",
            TlsSignatureAlgorithm::Ecdsa => "aECDSA",
            TlsSignatureAlgorithm::Rsa => "aRSA",
            TlsSignatureAlgorithm::__NonExhaustive => unreachable!(),
        }),
    );
    cipher_suite_strings = cartesian_product(
        cipher_suite_strings,
        cipher_suites.bulk_encryption.iter().map(|alg| match alg {
            TlsBulkEncryptionAlgorithm::Aes128 => "AES128",
            TlsBulkEncryptionAlgorithm::Aes256 => "AES256",
            TlsBulkEncryptionAlgorithm::Des => "DES",
            TlsBulkEncryptionAlgorithm::Rc2 => "RC2",
            TlsBulkEncryptionAlgorithm::Rc4 => "RC4",
            TlsBulkEncryptionAlgorithm::TripleDes => "3DES",
            TlsBulkEncryptionAlgorithm::__NonExhaustive => unreachable!(),
        }),
    );
    cipher_suite_strings = cartesian_product(
        cipher_suite_strings,
        cipher_suites.hash.iter().map(|alg| match alg {
            TlsHashAlgorithm::Md5 => "MD5",
            TlsHashAlgorithm::Sha1 => "SHA1",
            TlsHashAlgorithm::Sha256 => "SHA256",
            TlsHashAlgorithm::Sha384 => "SHA384",
            TlsHashAlgorithm::__NonExhaustive => unreachable!(),
        }),
    );

    // GCM first, as `@STRENGTH` sorts purely on bitwidth, and otherwise respects the initial
    // ordering. GCM is generally preferred over CBC for performance and security reasons.
    expand_gcm_algorithms(cipher_suites)
        .into_iter()
        .map(borrow::Cow::Borrowed)
        .chain(
            cipher_suite_strings
                .into_iter()
                .map(|parts| borrow::Cow::Owned(parts.join("+"))),
        )
        .chain(
            CIPHER_STRING_SUFFIX
                .iter()
                .map(|s| borrow::Cow::Borrowed(*s)),
        )
        .collect::<Vec<_>>()
        .join(":")
}

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
        if let Some(ref cipher_suites) = builder.cipher_suites {
            connector.set_cipher_list(&expand_algorithms(cipher_suites))?;
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

        #[cfg(feature = "alpn")]
        {
            if !builder.alpn.is_empty() {
                // Wire format is each alpn preceded by its length as a byte.
                let mut alpn_wire_format = Vec::with_capacity(
                    builder
                        .alpn
                        .iter()
                        .map(|s| s.as_bytes().len())
                        .sum::<usize>()
                        + builder.alpn.len(),
                );
                for alpn in builder.alpn.iter().map(|s| s.as_bytes()) {
                    alpn_wire_format.push(alpn.len() as u8);
                    alpn_wire_format.extend(alpn);
                }
                connector.set_alpn_protos(&alpn_wire_format)?;
            }
        }

        #[cfg(target_os = "android")]
        load_android_root_certs(&mut connector)?;

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

impl fmt::Debug for TlsConnector {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("TlsConnector")
            // n.b. SslConnector is a newtype on SslContext which implements a noop Debug so it's omitted
            .field("use_sni", &self.use_sni)
            .field("accept_invalid_hostnames", &self.accept_invalid_hostnames)
            .field("accept_invalid_certs", &self.accept_invalid_certs)
            .finish()
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
}

impl<S: io::Read + io::Write> TlsStream<S> {
    pub fn buffered_read_size(&self) -> Result<usize, Error> {
        Ok(self.0.ssl().pending())
    }

    pub fn peer_certificate(&self) -> Result<Option<Certificate>, Error> {
        Ok(self.0.ssl().peer_certificate().map(Certificate))
    }

    #[cfg(feature = "alpn")]
    pub fn negotiated_alpn(&self) -> Result<Option<Vec<u8>>, Error> {
        Ok(self
            .0
            .ssl()
            .selected_alpn_protocol()
            .map(|alpn| alpn.to_vec()))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_algorithms_basic() {
        assert_eq!(
            expand_algorithms(&CipherSuiteSet {
                key_exchange: vec![TlsKeyExchangeAlgorithm::Dhe, TlsKeyExchangeAlgorithm::Ecdhe],
                signature: vec![TlsSignatureAlgorithm::Rsa],
                bulk_encryption: vec![
                    TlsBulkEncryptionAlgorithm::Aes128,
                    TlsBulkEncryptionAlgorithm::Aes256
                ],
                hash: vec![TlsHashAlgorithm::Sha256, TlsHashAlgorithm::Sha384],
            }),
            "\
            DHE-RSA-AES128-GCM-SHA256:\
            DHE-RSA-AES256-GCM-SHA384:\
            ECDHE-RSA-AES128-GCM-SHA256:\
            ECDHE-RSA-AES256-GCM-SHA384:\
            DHE+aRSA+AES128+SHA256:\
            DHE+aRSA+AES128+SHA384:\
            DHE+aRSA+AES256+SHA256:\
            DHE+aRSA+AES256+SHA384:\
            ECDHE+aRSA+AES128+SHA256:\
            ECDHE+aRSA+AES128+SHA384:\
            ECDHE+aRSA+AES256+SHA256:\
            ECDHE+aRSA+AES256+SHA384:\
            !aNULL:!eNULL:!IDEA:!SEED:!SRP:!PSK:@STRENGTH\
            ",
        );
    }
}
