extern crate openssl;
extern crate openssl_verify;

use std::io;
use std::fmt;
use std::error;
use self::openssl::ssl::{self, SslContext, SslMethod, SSL_VERIFY_PEER, IntoSsl, SSL_OP_NO_SSLV2,
                         SSL_OP_NO_SSLV3, SSL_OP_NO_COMPRESSION};
use self::openssl::ssl::error::SslError;
use self::openssl_verify::verify_callback;

pub struct Error(SslError);

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

impl From<SslError> for Error {
    fn from(err: SslError) -> Error {
        Error(err)
    }
}

pub struct ClientBuilder(SslContext);

impl ClientBuilder {
    pub fn new() -> Result<ClientBuilder, Error> {
        let mut ctx = try!(SslContext::new(SslMethod::Sslv23));
        ctx.set_options(SSL_OP_NO_SSLV2 | SSL_OP_NO_SSLV3 | SSL_OP_NO_COMPRESSION);
        try!(ctx.set_default_verify_paths());
        try!(ctx.set_cipher_list("ALL!EXPORT!EXPORT40!EXPORT56!aNULL!LOW!RC4@STRENGTH"));
        Ok(ClientBuilder(ctx))
    }

    pub fn handshake<S>(&mut self, domain: &str, stream: S) -> Result<TlsStream<S>, Error>
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

pub struct TlsStream<S>(ssl::SslStream<S>);

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
