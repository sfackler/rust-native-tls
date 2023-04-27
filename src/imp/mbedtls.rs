extern crate mbedtls;

use self::mbedtls::alloc::{Box as MbedtlsBox, List as MbedtlsList};
use self::mbedtls::hash::{Md, Type as MdType};
use self::mbedtls::pk::Pk;
use self::mbedtls::rng::{CtrDrbg, Rdseed};
#[cfg(feature = "alpn")]
use self::mbedtls::ssl::config::NullTerminatedStrList;
use self::mbedtls::ssl::config::{Endpoint, Preset, Transport};
use self::mbedtls::ssl::{Config, Context, Version};
use self::mbedtls::x509::certificate::Certificate as MbedtlsCert;
use self::mbedtls::Error as TlsError;

use std::convert::TryFrom;
use std::error;
use std::fmt::{self, Debug};
use std::io;
use std::sync::Arc;

use {Protocol, TlsAcceptorBuilder, TlsConnectorBuilder};

#[derive(Debug)]
pub enum Error {
    Tls(TlsError),
    Pkcs12(yasna::ASN1Error),
    Pkcs5(pkcs5::Error),
    Der(pkcs5::der::Error),
    Custom(String),
}

impl From<TlsError> for Error {
    fn from(err: TlsError) -> Error {
        Error::Tls(err)
    }
}

impl From<yasna::ASN1Error> for Error {
    fn from(err: yasna::ASN1Error) -> Error {
        Error::Pkcs12(err)
    }
}

impl From<pkcs5::Error> for Error {
    fn from(err: pkcs5::Error) -> Error {
        Error::Pkcs5(err)
    }
}

impl From<pkcs5::der::Error> for Error {
    fn from(err: pkcs5::der::Error) -> Error {
        Error::Der(err)
    }
}

impl<S> From<TlsError> for HandshakeError<S> {
    fn from(e: TlsError) -> HandshakeError<S> {
        HandshakeError::Failure(e.into())
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            Error::Tls(ref e) => e.source(),
            Error::Pkcs12(ref e) => e.source(),
            Error::Pkcs5(_) => None,
            Error::Der(_) => None,
            Error::Custom(_) => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Tls(ref e) => fmt::Display::fmt(e, fmt),
            Error::Pkcs12(ref e) => fmt::Display::fmt(e, fmt),
            Error::Pkcs5(ref e) => fmt::Display::fmt(e, fmt),
            Error::Der(ref e) => fmt::Display::fmt(e, fmt),
            Error::Custom(ref e) => fmt::Display::fmt(e, fmt),
        }
    }
}

fn to_mbedtls_version(protocol: Protocol) -> Version {
    match protocol {
        Protocol::Sslv3 => Version::Ssl3,
        Protocol::Tlsv10 => Version::Tls1_0,
        Protocol::Tlsv11 => Version::Tls1_1,
        Protocol::Tlsv12 => Version::Tls1_2,
    }
}

trait NullTerminated {
    fn null_terminated(&self) -> Vec<u8>;
}

impl<T: AsRef<[u8]>> NullTerminated for T {
    fn null_terminated(&self) -> Vec<u8> {
        let mut buf = self.as_ref().to_vec();
        buf.push(0);
        buf
    }
}

fn pkcs12_decode_key_bag<B: AsRef<[u8]>>(
    key_bag: &p12::EncryptedPrivateKeyInfo,
    pass: B,
) -> Result<Vec<u8>, Error> {
    // try to decrypt the key with algorithms supported by p12 crate
    if let Some(decrypted) = key_bag.decrypt(pass.as_ref()) {
        Ok(decrypted)
    // try to decrypt the key with algorithms supported by pkcs5 standard
    } else if let p12::AlgorithmIdentifier::OtherAlg(_) = key_bag.encryption_algorithm {
        // write the algorithm identifier back to DER format
        let algorithm_der =
            yasna::construct_der(|writer| key_bag.encryption_algorithm.write(writer));
        // and construct pkcs5 decoder from it
        let scheme = pkcs5::EncryptionScheme::try_from(&algorithm_der[..])?;

        Ok(scheme.decrypt(pass.as_ref(), &key_bag.encrypted_data)?)
    } else {
        Err(Error::Custom(
            "Unsupported key encryption algorithm".to_owned(),
        ))
    }
}

#[derive(Clone)]
pub struct Identity {
    key: Arc<Pk>,
    certificates: Arc<MbedtlsList<MbedtlsCert>>,
}

impl Identity {
    pub fn from_pkcs12(buf: &[u8], pass: &str) -> Result<Identity, Error> {
        let pfx = p12::PFX::parse(buf)?;
        let key = pfx
            .bags(pass)?
            .iter()
            .find_map(|safe_bag| {
                if let p12::SafeBagKind::Pkcs8ShroudedKeyBag(ref key_bag) = safe_bag.bag {
                    Some(pkcs12_decode_key_bag(key_bag, pass))
                } else {
                    None
                }
            })
            .ok_or(Error::Custom("No private key in pkcs12 DER".to_owned()))?
            .map(|key| Pk::from_private_key(&key, Some(pass.as_bytes())))??;
        let certificates: MbedtlsList<_> = pfx
            .cert_bags(pass)?
            .iter()
            .map(|cert| MbedtlsCert::from_der(cert))
            .collect::<Result<_, _>>()?;

        if !certificates.is_empty() {
            Ok(Identity {
                key: Arc::new(key),
                certificates: Arc::new(certificates),
            })
        } else {
            Err(Error::Custom(
                "PKCS12 file is missing certificate chain".to_owned(),
            ))
        }
    }

    pub fn from_pkcs8(buf: &[u8], key: &[u8]) -> Result<Identity, Error> {
        let key = Pk::from_private_key(&key.null_terminated(), None)?;
        let certificates = MbedtlsCert::from_pem_multiple(&buf.null_terminated())?;

        if !certificates.is_empty() {
            Ok(Identity {
                key: Arc::new(key),
                certificates: Arc::new(certificates),
            })
        } else {
            Err(Error::Custom(
                "X509 chain file is missing certificate chain".to_owned(),
            ))
        }
    }

    fn certificates(&self) -> Arc<MbedtlsList<MbedtlsCert>> {
        self.certificates.clone()
    }

    fn private_key(&self) -> Arc<Pk> {
        self.key.clone()
    }
}

impl Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field(
                "certificates",
                &self
                    .certificates
                    .iter()
                    .map(|cert| cert.as_der().to_vec())
                    .collect::<Vec<_>>(),
            )
            .field(
                "key_name",
                &self.key.name().map(String::from).map_err(Error::Tls),
            )
            .finish()
    }
}

#[derive(Clone)]
pub struct Certificate(MbedtlsBox<MbedtlsCert>);

impl Certificate {
    pub fn from_der(buf: &[u8]) -> Result<Certificate, Error> {
        let cert = MbedtlsCert::from_der(buf).map_err(Error::Tls)?;
        Ok(Certificate(cert))
    }

    pub fn from_pem(buf: &[u8]) -> Result<Certificate, Error> {
        let cert = MbedtlsCert::from_pem(&buf.null_terminated()).map_err(Error::Tls)?;
        Ok(Certificate(cert))
    }

    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        let der = self.0.as_der().to_vec();
        Ok(der)
    }
}

impl Debug for Certificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Certificate")
            .field(&self.0.as_der())
            .finish()
    }
}

pub struct TlsStream<S> {
    ctx: Context<S>,
    role: Endpoint,
    identity: Option<Identity>,
}

impl<S> TlsStream<S> {
    pub fn get_ref(&self) -> &S {
        self.ctx.io().expect("Not connected")
    }

    pub fn get_mut(&mut self) -> &mut S {
        self.ctx.io_mut().expect("Not connected")
    }

    pub fn buffered_read_size(&self) -> Result<usize, Error> {
        Ok(self.ctx.bytes_available())
    }

    #[cfg(feature = "alpn")]
    pub fn negotiated_alpn(&self) -> Result<Option<Vec<u8>>, Error> {
        Ok(self.ctx.get_alpn_protocol()?.map(|s| s.as_bytes().to_vec()))
    }

    pub fn peer_certificate(&self) -> Result<Option<Certificate>, Error> {
        let cert = match self.ctx.peer_cert() {
            Ok(Some(certs)) => certs.iter().next().map(|cert| Certificate(cert.clone())),
            Ok(_) => None,
            Err(e) => match e {
                TlsError::SslBadInputData => None,
                _ => return Err(Error::Tls(e)),
            },
        };
        Ok(cert)
    }

    fn server_certificate(&self) -> Result<Option<Certificate>, Error> {
        match self.role {
            Endpoint::Client => self.peer_certificate(),
            Endpoint::Server => match self.identity {
                Some(ref idt) => Ok(idt
                    .certificates()
                    .iter()
                    .map(|cert| Certificate(cert.clone()))
                    .next()),
                None => Ok(None),
            },
        }
    }

    pub fn tls_server_end_point(&self) -> Result<Option<Vec<u8>>, Error> {
        let cert = match self.server_certificate()? {
            Some(cert) => cert,
            None => return Ok(None),
        };

        let md = match cert.0.digest_type() {
            MdType::Md5 | MdType::Sha1 => MdType::Sha256,
            md => md,
        };

        let der = cert.to_der()?;
        let mut digest = vec![0; 64];
        let len = Md::hash(md, &der, &mut digest).map_err(Error::Tls)?;
        digest.truncate(len);

        Ok(Some(digest))
    }

    pub fn shutdown(&mut self) -> io::Result<()> {
        self.ctx.close();
        Ok(())
    }
}

impl<S: io::Read + io::Write> io::Read for TlsStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.ctx.read(buf)
    }
}

impl<S: io::Read + io::Write> io::Write for TlsStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.ctx.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.ctx.flush()
    }
}

impl<S> Debug for TlsStream<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsStream")
            .field(
                "role",
                &match self.role {
                    Endpoint::Client => "client",
                    Endpoint::Server => "server",
                },
            )
            .field("identity", &self.identity)
            .finish()
    }
}

#[derive(Debug)]
pub struct MidHandshakeTlsStream<S>(TlsStream<S>);

pub enum HandshakeError<S> {
    Failure(Error),
    // this is actually unused
    WouldBlock(MidHandshakeTlsStream<S>),
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
        Ok(self.0)
    }
}

#[derive(Clone)]
pub struct TlsConnector {
    config: Arc<Config>,
    identity: Option<::Identity>,
    accept_invalid_hostnames: bool,
}

impl Debug for TlsConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsConnector")
            .field("identity", &self.identity.as_ref().map(|idt| &idt.0))
            .field("accept_invalid_hostnames", &self.accept_invalid_hostnames)
            .finish()
    }
}

impl TlsConnector {
    pub fn new(builder: &TlsConnectorBuilder) -> Result<TlsConnector, Error> {
        let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);

        // Set Rng
        let entropy = Arc::new(Rdseed);
        let rng = Arc::new(CtrDrbg::new(entropy, None)?);
        config.set_rng(rng);

        // Set root certificates
        let ca_list = builder
            .root_certificates
            .iter()
            .map(|cert| (cert.0).0.clone())
            .collect();
        config.set_ca_list(Arc::new(ca_list), None);

        // Add identity certificates and key
        if let Some(identity) = &builder.identity {
            config.push_cert(identity.0.certificates(), identity.0.private_key())?;
        }

        // Set authmode
        if builder.accept_invalid_certs {
            config.set_authmode(mbedtls::ssl::config::AuthMode::None);
        }

        // Set minimum protocol version
        if let Some(min_version) = builder.min_protocol.map(to_mbedtls_version) {
            config.set_min_version(min_version)?;
        }

        // Set maximum protocol version
        if let Some(max_version) = builder.max_protocol.map(to_mbedtls_version) {
            config.set_max_version(max_version)?;
        }

        #[cfg(feature = "alpn")]
        {
            if !builder.alpn.is_empty() {
                let alpns: Vec<_> = builder
                    .alpn
                    .iter()
                    .map(|protocol| protocol.as_str())
                    .collect();
                config.set_alpn_protocols(Arc::new(NullTerminatedStrList::new(&alpns)?))?;
            }
        }

        Ok(TlsConnector {
            config: Arc::new(config),
            identity: builder.identity.clone(),
            accept_invalid_hostnames: builder.accept_invalid_hostnames,
        })
    }

    pub fn connect<S>(&self, domain: &str, stream: S) -> Result<TlsStream<S>, HandshakeError<S>>
    where
        S: io::Read + io::Write,
    {
        // Create mbedtls context
        let mut ctx = Context::new(self.config.clone());

        // Establish connection
        let hostname = if self.accept_invalid_hostnames {
            None
        } else {
            Some(domain)
        };

        ctx.establish(stream, hostname)?;

        Ok(TlsStream {
            ctx,
            role: Endpoint::Client,
            identity: self.identity.clone().map(|idt| idt.0),
        })
    }
}

#[derive(Clone)]
pub struct TlsAcceptor {
    config: Arc<Config>,
    identity: Identity,
}

impl TlsAcceptor {
    pub fn new(builder: &TlsAcceptorBuilder) -> Result<TlsAcceptor, Error> {
        let mut config = Config::new(Endpoint::Server, Transport::Stream, Preset::Default);

        // Set Rng
        let entropy = Arc::new(Rdseed);
        let rng = Arc::new(CtrDrbg::new(entropy, None)?);
        config.set_rng(rng);

        // Add identity certificates and key
        config.push_cert(
            builder.identity.0.certificates(),
            builder.identity.0.private_key(),
        )?;

        // Set minimum protocol version
        if let Some(min_version) = builder.min_protocol.map(to_mbedtls_version) {
            config.set_min_version(min_version)?;
        }

        // Set maximum protocol version
        if let Some(max_version) = builder.max_protocol.map(to_mbedtls_version) {
            config.set_max_version(max_version)?;
        }

        Ok(TlsAcceptor {
            config: Arc::new(config),
            identity: (builder.identity.0).clone(),
        })
    }

    pub fn accept<S>(&self, stream: S) -> Result<TlsStream<S>, HandshakeError<S>>
    where
        S: io::Read + io::Write,
    {
        // Create mbedtls context
        let mut ctx = Context::new(self.config.clone());

        // Establish connection
        ctx.establish(stream, None)?;

        Ok(TlsStream {
            ctx,
            role: Endpoint::Server,
            identity: Some(self.identity.clone()),
        })
    }
}
