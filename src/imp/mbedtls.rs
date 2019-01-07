extern crate mbedtls;

use self::mbedtls::pk::Pk;
use self::mbedtls::x509::certificate::{Certificate as MbedtlsCert, LinkedCertificate};
use self::mbedtls::pkcs12::{Pfx, Pkcs12Error};
use self::mbedtls::hash::{Md, Type as MdType};
use self::mbedtls::ssl::config::{Endpoint, Preset, Transport};
use self::mbedtls::ssl::{Config, Context, Session, Version};
use self::mbedtls::x509::certificate::List as CertList;
use self::mbedtls::rng::{OsEntropy, CtrDrbg};
use self::mbedtls::Error as TlsError;
use self::mbedtls::Result as TlsResult;

use std::error;
use std::fmt;
use std::io::{self, Read};
use std::fs;

use {Protocol, TlsAcceptorBuilder, TlsConnectorBuilder};

fn load_ca_certs(dir: &str) -> TlsResult<Vec<::Certificate>> {
    let paths = fs::read_dir(dir).map_err(|_| TlsError::X509FileIoError)?;

    let mut certs = Vec::new();

    for path in paths {
        if let Ok(mut file) = fs::File::open(path.unwrap().path()) {
            let mut contents = Vec::new();
            if let Ok(_) = file.read_to_end(&mut contents) {
                contents.push(0); // needs NULL terminator
                if let Ok(cert) = ::Certificate::from_pem(&contents) {
                    certs.push(cert);
                }
            }
        }
    }

    Ok(certs)
}

fn load_system_trust_roots() -> Result<Vec<::Certificate>, Error> {
    let paths = [
        "/etc/pki/CA/certs", // Fedora, RHEL
        "/usr/share/ca-certificates/mozilla", // Ubuntu, Debian, Arch, Gentoo
    ];

    for path in paths.iter() {
        if let Ok(certs) = load_ca_certs(path) {
            return Ok(certs);
        }
    }

    Err(Error::Custom("Could not load system default trust roots".to_owned()))
}


#[derive(Debug)]
pub enum Error {
    Normal(TlsError),
    Pkcs12(Pkcs12Error),
    Custom(String),
}

#[derive(Debug, Copy, Clone)]
enum ProtocolRole {
    Client,
    Server
}

impl From<TlsError> for Error {
    fn from(err: TlsError) -> Error {
        Error::Normal(err)
    }
}

impl From<Pkcs12Error> for Error {
    fn from(err: Pkcs12Error) -> Error {
        Error::Pkcs12(err)
    }
}

impl<S> From<TlsError> for HandshakeError<S> {
    fn from(e: TlsError) -> HandshakeError<S> {
        HandshakeError::Failure(e.into())
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::Normal(ref e) => error::Error::description(e),
            Error::Pkcs12(ref e) => error::Error::description(e),
            Error::Custom(ref e) => &e,
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::Normal(ref e) => error::Error::cause(e),
            Error::Pkcs12(ref e) => error::Error::cause(e),
            Error::Custom(ref _e) => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Normal(ref e) => fmt::Display::fmt(e, fmt),
            Error::Pkcs12(ref e) => fmt::Display::fmt(e, fmt),
            Error::Custom(ref e) => fmt::Display::fmt(e, fmt),
        }
    }
}

fn map_version(protocol: Option<Protocol>) -> Option<Version> {
    if let Some(protocol) = protocol {
        match protocol {
            Protocol::Sslv3 => Some(Version::Ssl3),
            Protocol::Tlsv10 => Some(Version::Tls1_0),
            Protocol::Tlsv11 => Some(Version::Tls1_1),
            Protocol::Tlsv12 => Some(Version::Tls1_2),
            _ => None
        }
    } else {
        None
    }
}

pub struct Identity(Pfx);

impl Identity {
    pub fn from_pkcs12(buf: &[u8], pass: &str) -> Result<Identity, Error> {
        let pkcs12 = Pfx::parse(buf).map_err(Error::Pkcs12)?;
        let decrypted = pkcs12.decrypt(&pass, None).map_err(Error::Pkcs12)?;
        Ok(Identity(decrypted))
    }
}

impl Clone for Identity {
    fn clone(&self) -> Self {
        Identity(self.0.clone())
    }
}


#[derive(Clone)]
pub struct Certificate(MbedtlsCert);
unsafe impl Sync for Certificate {}

impl Certificate {
    pub fn from_der(buf: &[u8]) -> Result<Certificate, Error> {
        let cert = MbedtlsCert::from_der(buf).map_err(Error::Normal)?;
        Ok(Certificate(cert))
    }

    pub fn from_pem(buf: &[u8]) -> Result<Certificate, Error> {
        // Mbedtls needs there to be a trailing NULL byte ...
        let mut pem = buf.to_vec();
        pem.push(0);
        let cert = MbedtlsCert::from_pem(&pem).map_err(Error::Normal)?;
        Ok(Certificate(cert))
    }

    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        let der = self.0.as_der().to_vec();
        Ok(der)
    }
}

fn cert_to_vec(certs_in: &[::Certificate]) -> Vec<MbedtlsCert> {
    certs_in.iter().map(|cert| (cert.0).0.clone()).collect()
}

#[derive(Debug)]
pub struct TlsStream<S> {
    role: ProtocolRole,
    ca_certs: *mut Vec<MbedtlsCert>,
    ca_cert_list: *mut CertList<'static>,
    cred_pk: *mut Pk,
    cred_certs: *mut Vec<MbedtlsCert>,
    cred_cert_list: *mut CertList<'static>,
    entropy: *mut OsEntropy<'static>,
    rng: *mut CtrDrbg<'static>,
    config: *mut Config<'static>,
    ctx: *mut Context<'static>,
    session: *mut Session<'static>,
    socket: *mut S,
}

unsafe impl<S> Sync for TlsStream<S> {}
unsafe impl<S> Send for TlsStream<S> {}

impl<S> Drop for TlsStream<S> {
    fn drop(&mut self) {
        unsafe {
            if self.session != ::std::ptr::null_mut() {
                Box::from_raw(self.session);
            }
            Box::from_raw(self.socket);

            Box::from_raw(self.ctx);
            Box::from_raw(self.config);
            Box::from_raw(self.rng);
            Box::from_raw(self.entropy);

            if self.cred_cert_list != ::std::ptr::null_mut() {
                Box::from_raw(self.cred_cert_list);
            }
            if self.cred_certs != ::std::ptr::null_mut() {
                Box::from_raw(self.cred_certs);
            }
            if self.cred_pk != ::std::ptr::null_mut() {
                Box::from_raw(self.cred_pk);
            }

            if self.ca_cert_list != ::std::ptr::null_mut() {
                Box::from_raw(self.ca_cert_list);
            }

            if self.ca_certs != ::std::ptr::null_mut() {
                Box::from_raw(self.ca_certs);
            }
        }
    }
}

#[derive(Debug)]
pub struct MidHandshakeTlsStream<S> {
    stream: TlsStream<S>,
    error: Error,
}

pub enum HandshakeError<S> {
    Failure(Error),
    WouldBlock(MidHandshakeTlsStream<S>),
}

impl<S> MidHandshakeTlsStream<S> {
    pub fn get_ref(&self) -> &S {
        self.stream.get_ref()
    }

    pub fn get_mut(&mut self) -> &mut S {
        self.stream.get_mut()
    }
}

impl<S> MidHandshakeTlsStream<S>
where
    S: io::Read + io::Write,
{
    pub fn handshake(self) -> Result<TlsStream<S>, HandshakeError<S>> {
        Ok(self.stream)
    }
}

#[derive(Clone)]
pub struct TlsConnector {
    min_protocol: Option<Protocol>,
    max_protocol: Option<Protocol>,
    root_certificates: Vec<::Certificate>,
    identity: Option<::Identity>,
    accept_invalid_certs: bool,
    accept_invalid_hostnames: bool,
    use_sni: bool,
}

impl TlsConnector {
    pub fn new(builder: &TlsConnectorBuilder) -> Result<TlsConnector, Error> {
        let trust_roots = if builder.root_certificates.len() > 0 {
            builder.root_certificates.clone()
        } else {
            load_system_trust_roots()?
        };

        Ok(TlsConnector {
            min_protocol: builder.min_protocol,
            max_protocol: builder.max_protocol,
            root_certificates: trust_roots,
            identity: builder.identity.clone(),
            accept_invalid_certs: builder.accept_invalid_certs,
            accept_invalid_hostnames: builder.accept_invalid_hostnames,
            use_sni: builder.use_sni
        })
    }

    pub fn connect<S>(&self, domain: &str, stream: S) -> Result<TlsStream<S>, HandshakeError<S>>
    where
        S: io::Read + io::Write
    {
        // If any of the ? fail then memory leaks ...

        let identity = if let Some(identity) = &self.identity {
            let mut keys = (identity.0).0.private_keys().collect::<Vec<_>>();
            let certificates = (identity.0).0.certificates().collect::<Vec<_>>();

            if keys.len() != 1 {
                return Err(HandshakeError::Failure(Error::Custom("Unexpected number of keys in PKCS12 file".to_owned())))
            }
            if certificates.len() == 0 {
                return Err(HandshakeError::Failure(Error::Custom("PKCS12 file is missing certificate chain".to_owned())))
            }

            let mut cert_chain = vec![];
            for cert in certificates {
                cert_chain.push(cert.0?);
            }

            fn pk_clone(pk: &mut Pk) -> TlsResult<Pk> {
                let der = pk.write_private_der_vec()?;
                Pk::from_private_key(&der, None)
            }
            let key = Box::new(keys.pop().unwrap().0.map_err(|_| TlsError::PkInvalidAlg)?);

            Some((cert_chain, key))
        } else {
            None
        };

        unsafe {
            let ca_vec = Box::into_raw(Box::new(cert_to_vec(&self.root_certificates)));
            let ca_list = Box::into_raw(Box::new(CertList::from_vec(&mut *ca_vec).ok_or(TlsError::AesInvalidKeyLength)?));
            let entropy = Box::into_raw(Box::new(OsEntropy::new()));
            let rng = Box::into_raw(Box::new(CtrDrbg::new(&mut *entropy, None)?));
            let config = Box::into_raw(Box::new(Config::new(Endpoint::Client, Transport::Stream, Preset::Default)));
            (*config).set_rng(Some(&mut *rng));
            (*config).set_ca_list(Some(&mut *ca_list), None);

            let mut cred_certs = ::std::ptr::null_mut();
            let mut cred_cert_list = ::std::ptr::null_mut();
            let mut cred_pk = ::std::ptr::null_mut();

            if let Some((certificates,mut pk)) = identity {
                cred_certs = Box::into_raw(Box::new(certificates.to_vec()));
                cred_cert_list = Box::into_raw(Box::new(CertList::from_vec(&mut *cred_certs).ok_or(TlsError::CamelliaInvalidInputLength)?));
                cred_pk = Box::into_raw(Box::new(Pk::from_private_key(&pk.write_private_der_vec()?, None)?));
                (*config).push_cert(&mut *cred_cert_list, &mut *cred_pk)?;
            }

            if self.accept_invalid_certs {
                (*config).set_authmode(mbedtls::ssl::config::AuthMode::None);
            }

            if let Some(min_version) = map_version(self.min_protocol) {
                (*config).set_min_version(min_version)?;
            }
            if let Some(max_version) = map_version(self.max_protocol) {
                (*config).set_max_version(max_version)?;
            }

            let ctx = Box::into_raw(Box::new(Context::new(&*config)?));

            let hostname = if self.accept_invalid_hostnames { None } else { Some(domain) };

            let stream_ptr = Box::into_raw(Box::new(stream));
            let session = (*ctx).establish(&mut *stream_ptr, hostname)?;
            let session = Box::into_raw(Box::new(std::mem::transmute::<Session<'_>, Session<'static>>(session))); // yolo

            Ok(TlsStream {
                role: ProtocolRole::Client,
                ca_certs: ca_vec,
                ca_cert_list: ca_list,
                cred_pk: cred_pk,
                cred_certs: cred_certs,
                cred_cert_list: cred_cert_list,
                entropy: entropy,
                rng: rng,
                config: config,
                ctx: ctx,
                session: session,
                socket: stream_ptr,
            })
        }
    }
}

#[derive(Clone)]
pub struct TlsAcceptor {
    identity: Pfx,
    min_protocol: Option<Protocol>,
    max_protocol: Option<Protocol>,
}

impl TlsAcceptor {
    pub fn new(builder: &TlsAcceptorBuilder) -> Result<TlsAcceptor, Error> {
        Ok(TlsAcceptor {
            identity: (builder.identity.0).0.clone(),
            min_protocol: builder.min_protocol,
            max_protocol: builder.max_protocol
        })
    }

    pub fn accept<S>(&self, stream: S) -> Result<TlsStream<S>, HandshakeError<S>>
    where
        S: io::Read + io::Write
    {
        let mut keys = self.identity.private_keys().collect::<Vec<_>>();
        let certificates = self.identity.certificates().collect::<Vec<_>>();

        if keys.len() != 1 {
            return Err(HandshakeError::Failure(Error::Custom("Unexpected number of keys in PKCS12 file".to_owned())))
        }
        if certificates.len() == 0 {
            return Err(HandshakeError::Failure(Error::Custom("PKCS12 file is missing certificate chain".to_owned())))
        }

        let mut cert_chain = vec![];
        for cert in certificates {
            cert_chain.push(cert.0?);
        }

        let key : &mut Pk = &mut keys.pop().unwrap().0.map_err(|_| TlsError::PkInvalidAlg)?;

        unsafe {
            let pk = Box::into_raw(Box::new(Pk::from_private_key(&key.write_private_der_vec()?, None)?));
            let cert_chain = Box::into_raw(Box::new(cert_chain.to_vec()));
            let cert_list = Box::into_raw(Box::new(CertList::from_vec(&mut *cert_chain).ok_or(TlsError::CamelliaInvalidInputLength)?));
            let entropy = Box::into_raw(Box::new(OsEntropy::new()));
            let rng = Box::into_raw(Box::new(CtrDrbg::new(&mut *entropy, None)?));
            let config = Box::into_raw(Box::new(Config::new(Endpoint::Server, Transport::Stream, Preset::Default)));
            (*config).set_rng(Some(&mut *rng));
            (*config).push_cert(&mut *cert_list, &mut *pk)?;

            if let Some(min_version) = map_version(self.min_protocol) {
                (*config).set_min_version(min_version)?;
            }
            if let Some(max_version) = map_version(self.max_protocol) {
                (*config).set_max_version(max_version)?;
            }

            let ctx = Box::into_raw(Box::new(Context::new(&*config)?));

            let stream_ptr = Box::into_raw(Box::new(stream));
            let session = (*ctx).establish(&mut *stream_ptr, None)?;
            let session = Box::into_raw(Box::new(std::mem::transmute::<Session<'_>, Session<'static>>(session))); // yolo

            Ok(TlsStream {
                role: ProtocolRole::Server,
                ca_certs: ::std::ptr::null_mut(),
                ca_cert_list: ::std::ptr::null_mut(),
                cred_pk: pk,
                cred_certs: cert_chain,
                cred_cert_list: cert_list,
                entropy: entropy,
                rng: rng,
                config: config,
                ctx: ctx,
                session: session,
                socket: stream_ptr,
            })
        }
    }
}

impl<S> TlsStream<S> {

    pub fn get_ref(&self) -> &S {
        unsafe { self.socket.as_ref().unwrap() }
    }

    pub fn get_mut(&mut self) -> &mut S {
        unsafe { self.socket.as_mut().unwrap() }
    }

    pub fn buffered_read_size(&self) -> Result<usize, Error> {
        Ok(unsafe { (*self.session).bytes_available() })
    }

    pub fn peer_certificate(&self) -> Result<Option<Certificate>, Error> {
        match unsafe { (*self.session).peer_cert() } {
            None => Ok(None),
            Some(mut certs) => {
                match certs.next() {
                    None => Ok(None),
                    Some(c) => Ok(Some(Certificate::from_der(c.as_der())?))
                }
            }
        }
    }

    fn server_certificate(&self) -> Result<Option<Certificate>, Error> {
        match self.role {
            ProtocolRole::Client => self.peer_certificate(),
            ProtocolRole::Server => {
                match unsafe { (*self.cred_certs).first() } {
                    None => Ok(None),
                    Some(c) => Ok(Some(Certificate::from_der(c.as_der())?))
                }
            }
        }
    }

    pub fn tls_server_end_point(&self) -> Result<Option<Vec<u8>>, Error> {
        let cert = match self.server_certificate()? {
            Some(cert) => cert,
            None => return Ok(None),
        };

        let lcert : &LinkedCertificate = &*(cert.0);

        let md = match lcert.digest_type() {
            MdType::Md5 | MdType::Sha1 => MdType::Sha256,
            md => md,
        };

        let der = cert.to_der()?;
        let mut digest = vec![0; 64];
        let len = Md::hash(md, &der, &mut digest).map_err(Error::Normal)?;
        digest.truncate(len);

        Ok(Some(digest))
    }

    pub fn shutdown(&mut self) -> io::Result<()> {
        // Shutdown happens as a result of drop ...
        unsafe {
            Box::from_raw(self.session);
            self.session = ::std::ptr::null_mut();
        }
        Ok(())
    }
}

impl<S: io::Read + io::Write> io::Read for TlsStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        unsafe {
            (*self.session).read(buf)
        }
    }
}

impl<S: io::Read + io::Write> io::Write for TlsStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        unsafe {
            (*self.session).write(buf)
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        unsafe {
            (*self.session).flush()
        }
    }
}

