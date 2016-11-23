extern crate security_framework;
extern crate security_framework_sys;
extern crate tempdir;

use self::security_framework::base;
use self::security_framework::certificate::SecCertificate;
use self::security_framework::identity::SecIdentity;
use self::security_framework::import_export::Pkcs12ImportOptions;
use self::security_framework::secure_transport::{self, SslContext, ProtocolSide, ConnectionType,
                                                 SslProtocol};
use self::security_framework::os::macos::keychain;
use self::security_framework_sys::base::errSecIO;
use self::tempdir::TempDir;
use std::fmt;
use std::io;
use std::error;

use Protocol;

fn convert_protocols(protocols: &[Protocol]) -> Vec<SslProtocol> {
    protocols.iter()
        .map(|p| {
            match *p {
                Protocol::Sslv3 => SslProtocol::Ssl3,
                Protocol::Tlsv10 => SslProtocol::Tls1,
                Protocol::Tlsv11 => SslProtocol::Tls11,
                Protocol::Tlsv12 => SslProtocol::Tls12,
                Protocol::__NonExhaustive => unreachable!(),
            }
        })
        .collect()
}

// FIXME A bandaid until the next security-framework release happens
fn clone_protocol(protocol: &SslProtocol) -> SslProtocol {
    match *protocol {
        SslProtocol::Ssl3 => SslProtocol::Ssl3,
        SslProtocol::Tls1 => SslProtocol::Tls1,
        SslProtocol::Tls11 => SslProtocol::Tls11,
        SslProtocol::Tls12 => SslProtocol::Tls12,
        _ => unreachable!(),
    }
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

#[derive(Clone)]
pub struct Pkcs12 {
    identity: SecIdentity,
    chain: Vec<SecCertificate>,
}

impl Pkcs12 {
    pub fn from_der(buf: &[u8], pass: &str) -> Result<Pkcs12, Error> {
        let dir = match TempDir::new("native_tls") {
            Ok(dir) => dir,
            // Gotta throw away the real error :(
            Err(_) => return Err(Error(base::Error::from(errSecIO))),
        };

        let keychain = try!(keychain::CreateOptions::new()
            .password(pass) // FIXME maybe generate a secure random password here?
            .create(dir.path().join("keychain")));

        let mut import = try!(Pkcs12ImportOptions::new()
            .passphrase(pass)
            .keychain(keychain)
            .import(buf));
        let import = import.pop().unwrap();

        // The identity's cert shows up in the chain, so filter it out to avoid sending twice
        // FIXME should probably use CFEquals here
        let identity_cert = try!(import.identity.certificate()).to_der();

        Ok(Pkcs12 {
            identity: import.identity,
            // FIXME possibly use the chain from the trust result instead?
            chain: import.cert_chain
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
                HandshakeError::Interrupted(MidHandshakeTlsStream(s))
            }
        }
    }
}

impl<S> From<base::Error> for HandshakeError<S> {
    fn from(e: base::Error) -> HandshakeError<S> {
        HandshakeError::Failure(e.into())
    }
}

pub struct MidHandshakeTlsStream<S>(secure_transport::MidHandshakeSslStream<S>);

impl<S> fmt::Debug for MidHandshakeTlsStream<S>
    where S: fmt::Debug
{
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

pub struct TlsConnectorBuilder(TlsConnector);

impl TlsConnectorBuilder {
    pub fn identity(&mut self, pkcs12: Pkcs12) -> Result<(), Error> {
        self.0.pkcs12 = Some(pkcs12);
        Ok(())
    }

    pub fn supported_protocols(&mut self, protocols: &[Protocol]) -> Result<(), Error> {
        self.0.protocols = convert_protocols(protocols);
        Ok(())
    }

    pub fn build(self) -> Result<TlsConnector, Error> {
        Ok(self.0)
    }
}

pub struct TlsConnector {
    pkcs12: Option<Pkcs12>,
    protocols: Vec<SslProtocol>,
}

impl TlsConnector {
    pub fn builder() -> Result<TlsConnectorBuilder, Error> {
        Ok(TlsConnectorBuilder(TlsConnector {
            pkcs12: None,
            protocols: vec![SslProtocol::Tls1, SslProtocol::Tls11, SslProtocol::Tls12],
        }))
    }

    pub fn connect<S>(&self,
                      domain: &str,
                      stream: S)
                      -> Result<TlsStream<S>, HandshakeError<S>>
        where S: io::Read + io::Write
    {
        let mut ctx = try!(SslContext::new(ProtocolSide::Client, ConnectionType::Stream));
        try!(ctx.set_protocol_version_enabled(SslProtocol::All, false));
        for protocol in &self.protocols {
            try!(ctx.set_protocol_version_enabled(clone_protocol(protocol), true));
        }
        try!(ctx.set_peer_domain_name(domain));
        if let Some(pkcs12) = self.pkcs12.as_ref() {
            try!(ctx.set_certificate(&pkcs12.identity, &pkcs12.chain));
        }
        match ctx.handshake(stream) {
            Ok(s) => Ok(TlsStream(s)),
            Err(e) => Err(e.into()),
        }
    }
}

pub struct TlsAcceptorBuilder(TlsAcceptor);

impl TlsAcceptorBuilder {
    pub fn supported_protocols(&mut self, protocols: &[Protocol]) -> Result<(), Error> {
        self.0.protocols = convert_protocols(protocols);
        Ok(())
    }

    pub fn build(self) -> Result<TlsAcceptor, Error> {
        Ok(self.0)
    }
}

pub struct TlsAcceptor {
    pkcs12: Pkcs12,
    protocols: Vec<SslProtocol>,
}

impl TlsAcceptor {
    pub fn builder(pkcs12: Pkcs12) -> Result<TlsAcceptorBuilder, Error> {
        Ok(TlsAcceptorBuilder(TlsAcceptor {
            pkcs12: pkcs12,
            protocols: vec![SslProtocol::Tls1, SslProtocol::Tls11, SslProtocol::Tls12],
        }))
    }

    pub fn accept<S>(&self, stream: S) -> Result<TlsStream<S>, HandshakeError<S>>
        where S: io::Read + io::Write
    {
        let mut ctx = try!(SslContext::new(ProtocolSide::Server, ConnectionType::Stream));
        try!(ctx.set_protocol_version_enabled(SslProtocol::All, false));
        for protocol in &self.protocols {
            try!(ctx.set_protocol_version_enabled(clone_protocol(protocol), true));
        }
        try!(ctx.set_certificate(&self.pkcs12.identity, &self.pkcs12.chain));
        match ctx.handshake(stream) {
            Ok(s) => Ok(TlsStream(s)),
            Err(e) => Err(e.into()),
        }
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
