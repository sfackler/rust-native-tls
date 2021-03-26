extern crate linked_hash_set;
extern crate once_cell;
extern crate openssl;
extern crate openssl_probe;

use self::linked_hash_set::LinkedHashSet;
use self::once_cell::sync::OnceCell;
use self::openssl::error::ErrorStack;
use self::openssl::ex_data::Index;
use self::openssl::hash::MessageDigest;
use self::openssl::nid::Nid;
use self::openssl::pkcs12::Pkcs12;
use self::openssl::pkey::PKey;
use self::openssl::ssl::{
    self, MidHandshakeSslStream, Ssl, SslAcceptor, SslConnector, SslContextBuilder, SslMethod,
    SslSession, SslSessionCacheMode, SslSessionRef, SslVerifyMode,
};
use self::openssl::x509::{store::X509StoreBuilder, X509VerifyResult, X509};
use std::borrow::Borrow;
use std::collections::hash_map::{Entry, HashMap};
use std::error;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::io;
use std::sync::{Arc, Mutex, Once};

use self::openssl::pkey::Private;
use {Protocol, TlsAcceptorBuilder, TlsConnectorBuilder};

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
    session_tickets_enabled: bool,
    session_cache: Arc<Mutex<SessionCache>>,
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

        let session_cache = Arc::new(Mutex::new(SessionCache::new()));
        if builder.session_tickets_enabled {
            connector.set_session_cache_mode(SslSessionCacheMode::CLIENT);

            connector.set_new_session_callback({
                let session_cache = session_cache.clone();
                move |ssl, session| {
                    if let Some(key) = key_index().ok().and_then(|idx| ssl.ex_data(idx)) {
                        if let Ok(mut session_cache) = session_cache.lock() {
                            session_cache.insert(key.clone(), session);
                        }
                    }
                }
            });
            connector.set_remove_session_callback({
                let session_cache = session_cache.clone();
                move |_, session| {
                    if let Ok(mut session_cache) = session_cache.lock() {
                        session_cache.remove(session);
                    }
                }
            });
        }

        Ok(TlsConnector {
            connector: connector.build(),
            use_sni: builder.use_sni,
            accept_invalid_hostnames: builder.accept_invalid_hostnames,
            accept_invalid_certs: builder.accept_invalid_certs,
            session_tickets_enabled: builder.session_tickets_enabled,
            session_cache,
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
        if self.session_tickets_enabled {
            let key = SessionKey {
                host: domain.to_string(),
            };

            if let Ok(mut session_cache) = self.session_cache.lock() {
                if let Some(session) = session_cache.get(&key) {
                    // Note: the `unsafe`-ty here is because the `session` is required to come from the
                    // same SSL_CTX that the ssl object (`ssl`) is from, since it maintains internal
                    // pointers and refcounts. Here, we only have one SSL_CTX, so this is safe.
                    unsafe { ssl.set_session(&session)? };
                }
            }

            let idx = key_index()?;
            ssl.set_ex_data(idx, key);
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

fn key_index() -> Result<Index<Ssl, SessionKey>, ErrorStack> {
    static IDX: OnceCell<Index<Ssl, SessionKey>> = OnceCell::new();
    IDX.get_or_try_init(|| Ssl::new_ex_index()).map(|v| *v)
}

#[derive(Hash, PartialEq, Eq, Clone)]
pub struct SessionKey {
    pub host: String,
}

#[derive(Clone)]
struct HashSession(SslSession);

impl PartialEq for HashSession {
    fn eq(&self, other: &HashSession) -> bool {
        self.0.id() == other.0.id()
    }
}

impl Eq for HashSession {}

impl Hash for HashSession {
    fn hash<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        self.0.id().hash(state);
    }
}

impl Borrow<[u8]> for HashSession {
    fn borrow(&self) -> &[u8] {
        self.0.id()
    }
}

pub struct SessionCache {
    sessions: HashMap<SessionKey, LinkedHashSet<HashSession>>,
    reverse: HashMap<HashSession, SessionKey>,
}

impl SessionCache {
    pub fn new() -> SessionCache {
        SessionCache {
            sessions: HashMap::new(),
            reverse: HashMap::new(),
        }
    }

    pub fn insert(&mut self, key: SessionKey, session: SslSession) {
        let session = HashSession(session);

        self.sessions
            .entry(key.clone())
            .or_insert_with(LinkedHashSet::new)
            .insert(session.clone());
        self.reverse.insert(session.clone(), key);
    }

    pub fn get(&mut self, key: &SessionKey) -> Option<SslSession> {
        let session = {
            let sessions = self.sessions.get_mut(key)?;
            sessions.front().cloned()?.0
        };

        #[cfg(ossl111)]
        {
            use self::openssl::ssl::SslVersion;

            // https://tools.ietf.org/html/rfc8446#appendix-C.4
            // OpenSSL will remove the session from its cache after the handshake completes anyway, but this ensures
            // that concurrent handshakes don't end up with the same session.
            if session.protocol_version() == SslVersion::TLS1_3 {
                self.remove(&session);
            }
        }

        Some(session)
    }

    pub fn remove(&mut self, session: &SslSessionRef) {
        let key = match self.reverse.remove(session.id()) {
            Some(key) => key,
            None => return,
        };

        if let Entry::Occupied(mut sessions) = self.sessions.entry(key) {
            sessions.get_mut().remove(session.id());
            if sessions.get().is_empty() {
                sessions.remove();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    use crate::TlsConnector;

    fn connect_and_assert(tls: &TlsConnector, domain: &str, port: u16, should_resume: bool) {
        let s = TcpStream::connect((domain, port)).unwrap();
        let mut stream = tls.connect(domain, s).unwrap();

        // Must write to the stream, as OpenSSL doesn't appear to call the
        // session callback until we do.
        stream.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
        let mut result = vec![];
        stream.read_to_end(&mut result).unwrap();

        assert_eq!((stream.0).0.ssl().session_reused(), should_resume);

        // Must shut down properly, or OpenSSL will invalidate the session.
        stream.shutdown().unwrap();
    }

    #[test]
    fn connect_no_session_ticket_resumption() {
        let tls = TlsConnector::new().unwrap();
        connect_and_assert(&tls, "google.com", 443, false);
        connect_and_assert(&tls, "google.com", 443, false);
    }

    #[test]
    fn connect_session_ticket_resumption() {
        let mut builder = TlsConnector::builder();
        builder.session_tickets_enabled(true);
        let tls = builder.build().unwrap();

        connect_and_assert(&tls, "google.com", 443, false);
        connect_and_assert(&tls, "google.com", 443, true);
    }

    #[test]
    fn connect_session_ticket_resumption_two_sites() {
        let mut builder = TlsConnector::builder();
        builder.session_tickets_enabled(true);
        let tls = builder.build().unwrap();

        connect_and_assert(&tls, "google.com", 443, false);
        connect_and_assert(&tls, "mozilla.org", 443, false);
        connect_and_assert(&tls, "google.com", 443, true);
        connect_and_assert(&tls, "mozilla.org", 443, true);
    }
}
