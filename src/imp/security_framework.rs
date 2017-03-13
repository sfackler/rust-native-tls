extern crate security_framework;
extern crate security_framework_sys;

use self::security_framework::base;
use self::security_framework::certificate::SecCertificate;
use self::security_framework::identity::SecIdentity;
use self::security_framework::import_export::Pkcs12ImportOptions;
use self::security_framework::secure_transport::{self, SslContext, ProtocolSide, ConnectionType,
                                                 SslAuthenticate, SslProtocol, ClientBuilder};
use imp::security_framework::os::macos::secure_transport::SslContextExt;
use std::fmt;
use std::io;
use std::error;

use Protocol;

fn convert_protocol(protocol: Protocol) -> SslProtocol {
    match protocol {
        Protocol::Sslv3 => SslProtocol::Ssl3,
        Protocol::Tlsv10 => SslProtocol::Tls1,
        Protocol::Tlsv11 => SslProtocol::Tls11,
        Protocol::Tlsv12 => SslProtocol::Tls12,
        Protocol::__NonExhaustive => unreachable!(),
    }
}

fn protocol_min_max(protocols: &[Protocol]) -> (SslProtocol, SslProtocol) {
    let mut min = Protocol::Tlsv12;
    let mut max = Protocol::Sslv3;
    for protocol in protocols {
        if (*protocol as usize) < (min as usize) {
            min = *protocol;
        }
        if (*protocol as usize) > (max as usize) {
            max = *protocol;
        }
    }
    (convert_protocol(min), convert_protocol(max))
}

pub struct Error(base::Error);

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

impl From<base::Error> for Error {
    fn from(error: base::Error) -> Error {
        Error(error)
    }
}

pub struct Pkcs12 {
    identity: SecIdentity,
    chain: Vec<SecCertificate>,
}

impl Pkcs12 {
    pub fn from_der(buf: &[u8], pass: &str) -> Result<Pkcs12, Error> {
        let mut options = Pkcs12ImportOptions::new();
        options.passphrase(pass);

        let mut imported_identities = try!(options.import(buf));
        imported_identities.truncate(1);
        let imported_identity = imported_identities.pop().unwrap();

        // FIXME: Compare the certificates for equality using CFEqual
        let identity_cert = try!(imported_identity.identity.certificate()).to_der();

        Ok(Pkcs12 {
            identity: imported_identity.identity,
            chain: imported_identity.cert_chain
                .into_iter()
                .filter(|c| c.to_der() != identity_cert)
                .collect(),
        })
    }
}

pub enum HandshakeError<S> {
    Interrupted(MidHandshakeTlsStream<S>),
    Failure(Error),
}

impl<S> From<secure_transport::HandshakeError<S>> for HandshakeError<S> {
    fn from(e: secure_transport::HandshakeError<S>) -> HandshakeError<S> {
        match e {
            secure_transport::HandshakeError::Failure(e) => HandshakeError::Failure(e.into()),
            secure_transport::HandshakeError::Interrupted(s) => {
                HandshakeError::Interrupted(MidHandshakeTlsStream::Server(s))
            }
        }
    }
}

impl<S> From<secure_transport::ClientHandshakeError<S>> for HandshakeError<S> {
    fn from(e: secure_transport::ClientHandshakeError<S>) -> HandshakeError<S> {
        match e {
            secure_transport::ClientHandshakeError::Failure(e) => HandshakeError::Failure(e.into()),
            secure_transport::ClientHandshakeError::Interrupted(s) => {
                HandshakeError::Interrupted(MidHandshakeTlsStream::Client(s))
            }
        }
    }
}

impl<S> From<base::Error> for HandshakeError<S> {
    fn from(e: base::Error) -> HandshakeError<S> {
        HandshakeError::Failure(e.into())
    }
}

pub enum MidHandshakeTlsStream<S> {
    Server(secure_transport::MidHandshakeSslStream<S>),
    Client(secure_transport::MidHandshakeClientBuilder<S>),
}

impl<S> fmt::Debug for MidHandshakeTlsStream<S>
    where S: fmt::Debug
{
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            MidHandshakeTlsStream::Server(ref s) => s.fmt(fmt),
            MidHandshakeTlsStream::Client(ref s) => s.fmt(fmt),
        }
    }
}

impl<S> MidHandshakeTlsStream<S>
    where S: io::Read + io::Write
{
    pub fn get_ref(&self) -> &S {
        match *self {
            MidHandshakeTlsStream::Server(ref s) => s.get_ref(),
            MidHandshakeTlsStream::Client(ref s) => s.get_ref(),
        }
    }

    pub fn get_mut(&mut self) -> &mut S {
        match *self {
            MidHandshakeTlsStream::Server(ref mut s) => s.get_mut(),
            MidHandshakeTlsStream::Client(ref mut s) => s.get_mut(),
        }
    }

    pub fn handshake(self) -> Result<TlsStream<S>, HandshakeError<S>> {
        match self {
            MidHandshakeTlsStream::Server(s) => {
                match s.handshake() {
                    Ok(s) => Ok(TlsStream(s)),
                    Err(e) => Err(e.into()),
                }
            }
            MidHandshakeTlsStream::Client(s) => {
                match s.handshake() {
                    Ok(s) => Ok(TlsStream(s)),
                    Err(e) => Err(e.into()),
                }
            }
        }
    }
}

pub struct TlsConnectorBuilder(TlsConnector);

impl TlsConnectorBuilder {
    pub fn identity(&mut self, pkcs12: Pkcs12) -> Result<(), Error> {
        self.0.pkcs12 = Some(pkcs12);
        Ok(())
    }

    pub fn supported_protocols(&mut self, protocols: &[Protocol]) -> Result<(), Error> {
        self.0.protocols = protocols.to_vec();
        Ok(())
    }

    pub fn build(self) -> Result<TlsConnector, Error> {
        Ok(self.0)
    }
}

pub struct TlsConnector {
    pkcs12: Option<Pkcs12>,
    protocols: Vec<Protocol>,
    anchor_certificates: Option<Vec<SecCertificate>>,
}

impl TlsConnector {
    pub fn builder() -> Result<TlsConnectorBuilder, Error> {
        Ok(TlsConnectorBuilder(TlsConnector {
            pkcs12: None,
            protocols: vec![Protocol::Tlsv10, Protocol::Tlsv11, Protocol::Tlsv12],
            anchor_certificates: None,
        }))
    }

    pub fn connect<S>(&self, domain: &str, stream: S) -> Result<TlsStream<S>, HandshakeError<S>>
        where S: io::Read + io::Write
    {
        self.connect_inner(Some(domain), stream)
    }

    pub fn connect_no_domain<S>(&self, stream: S) -> Result<TlsStream<S>, HandshakeError<S>>
        where S: io::Read + io::Write
    {
        self.connect_inner(None, stream)
    }

    fn connect_inner<S>(&self,
                   domain: Option<&str>,
                   stream: S)
                   -> Result<TlsStream<S>, HandshakeError<S>>
        where S: io::Read + io::Write
    {
        let mut builder = ClientBuilder::new();
        let (min, max) = protocol_min_max(&self.protocols);
        builder.protocol_min(min);
        builder.protocol_max(max);
        if let Some(pkcs12) = self.pkcs12.as_ref() {
            builder.identity(&pkcs12.identity, &pkcs12.chain);
        }
        if let Some(anchors) = self.anchor_certificates.as_ref() {
            builder.anchor_certificates(anchors);
        }

        let r = match domain {
            Some(domain) => builder.handshake2(domain, stream),
            None => builder.danger_handshake_without_providing_domain_for_certificate_validation_and_server_name_indication(stream),
        };
        match r {
            Ok(s) => Ok(TlsStream(s)),
            Err(e) => Err(e.into()),
        }
    }
}

pub struct TlsAcceptorBuilder(TlsAcceptor);

impl TlsAcceptorBuilder {
    pub fn supported_protocols(&mut self, protocols: &[Protocol]) -> Result<(), Error> {
        self.0.protocols = protocols.to_vec();
        Ok(())
    }

    pub fn build(self) -> Result<TlsAcceptor, Error> {
        Ok(self.0)
    }
}

pub struct TlsAcceptor {
    pkcs12: Pkcs12,
    protocols: Vec<Protocol>,
    client_auth: Option<SslAuthenticate>,
    additional_cas: Vec<SecCertificate>,
}

impl TlsAcceptor {
    pub fn builder(pkcs12: Pkcs12) -> Result<TlsAcceptorBuilder, Error> {
        Ok(TlsAcceptorBuilder(TlsAcceptor {
            pkcs12: pkcs12,
            protocols: vec![Protocol::Tlsv10, Protocol::Tlsv11, Protocol::Tlsv12],
            client_auth: None,
            additional_cas: vec![],
        }))
    }

    pub fn accept<S>(&self, stream: S) -> Result<TlsStream<S>, HandshakeError<S>>
        where S: io::Read + io::Write
    {
        let mut ctx = try!(SslContext::new(ProtocolSide::Server, ConnectionType::Stream));

        let (min, max) = protocol_min_max(&self.protocols);
        try!(ctx.set_protocol_version_min(min));
        try!(ctx.set_protocol_version_max(max));
        try!(ctx.set_certificate(&self.pkcs12.identity, &self.pkcs12.chain));
        if let Some(client_auth) = self.client_auth {
            try!(ctx.set_client_side_authenticate(client_auth))
        };
        if !self.additional_cas.is_empty() {
            try!(ctx.add_certificate_authorities(&self.additional_cas));
        }
        match ctx.handshake(stream) {
            Ok(s) => Ok(TlsStream(s)),
            Err(e) => Err(e.into()),
        }
    }
}

/// OpenSSL-specific extensions to `TlsConnectorBuilder`.
pub trait TlsAcceptorBuilderExt {
    /// Specifies the authenication requirement for ClientAuth type connections.
    fn client_auth(&mut self, auth: SslAuthenticate) -> Result<(), Error>;

    /// Appends these additional certificates to the acceptors list of CAs.
    ///
    /// This is useful for associating CAs to verify client_auth connections.
    fn additional_cas(&mut self, cas: Vec<SecCertificate>) -> Result<(), Error>;
}

impl TlsAcceptorBuilderExt for ::TlsAcceptorBuilder {
    fn client_auth(&mut self, auth: SslAuthenticate) -> Result<(), Error> {
        (self.0).0.client_auth = Some(auth);
        Ok(())
    }

    fn additional_cas(&mut self, cas: Vec<SecCertificate>) -> Result<(), Error> {
        (self.0).0.additional_cas = cas;
        Ok(())
    }
}

pub struct TlsStream<S>(secure_transport::SslStream<S>);

impl<S: fmt::Debug> fmt::Debug for TlsStream<S> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.0, fmt)
    }
}

impl<S: io::Read + io::Write> TlsStream<S> {
    pub fn get_ref(&self) -> &S {
        self.0.get_ref()
    }

    pub fn get_mut(&mut self) -> &mut S {
        self.0.get_mut()
    }

    pub fn buffered_read_size(&self) -> Result<usize, Error> {
        Ok(try!(self.0.context().buffered_read_size()))
    }

    pub fn shutdown(&mut self) -> io::Result<()> {
        try!(self.0.close());
        Ok(())
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

/// Security Framework-specific extensions to `TlsStream`.
pub trait TlsStreamExt<S> {
    /// Returns a shared reference to the Security Framework `SslStream`.
    fn raw_stream(&self) -> &secure_transport::SslStream<S>;

    /// Returns a mutable reference to the Security Framework `SslStream`.
    fn raw_stream_mut(&mut self) -> &mut secure_transport::SslStream<S>;
}

impl<S> TlsStreamExt<S> for ::TlsStream<S> {
    fn raw_stream(&self) -> &secure_transport::SslStream<S> {
        &(self.0).0
    }

    fn raw_stream_mut(&mut self) -> &mut secure_transport::SslStream<S> {
        &mut (self.0).0
    }
}

/// Security Framework-specific extensions to `TlsConnectorBuilder`.
pub trait TlsConnectorBuilderExt {
    /// Specifies the set of additional root certificates to trust when
    /// verifying the server's certificate.
    fn anchor_certificates(&mut self, certs: &[SecCertificate]) -> &mut Self;
}

impl TlsConnectorBuilderExt for ::TlsConnectorBuilder {
    fn anchor_certificates(&mut self, certs: &[SecCertificate]) -> &mut Self {
        (self.0).0.anchor_certificates = Some(certs.to_owned());
        self
    }
}

/// Security Framework-specific extensions to `Error`
pub trait ErrorExt {
    /// Extract the underlying Security Framework error for inspection.
    fn security_framework_error(&self) -> &base::Error;
}

impl ErrorExt for ::Error {
    fn security_framework_error(&self) -> &base::Error {
        &(self.0).0
    }
}
