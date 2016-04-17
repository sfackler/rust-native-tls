use std::error;
use std::io;
use std::fmt;

#[cfg(target_os = "macos")]
#[path = "imp/security_framework.rs"]
mod imp;
#[cfg(not(target_os = "macos"))]
#[path = "imp/openssl.rs"]
mod imp;
#[cfg(test)]
mod test;

pub type Result<T> = std::result::Result<T, Error>;

pub struct Error(imp::Error);

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

pub struct ClientBuilder(imp::ClientBuilder);

impl ClientBuilder {
    pub fn new() -> Result<ClientBuilder> {
        match imp::ClientBuilder::new() {
            Ok(builder) => Ok(ClientBuilder(builder)),
            Err(err) => Err(Error(err)),
        }
    }

    pub fn handshake<S>(&mut self, domain: &str, stream: S) -> Result<SslStream<S>>
        where S: io::Read + io::Write
    {
        match self.0.handshake(domain, stream) {
            Ok(s) => Ok(SslStream(s)),
            Err(err) => Err(Error(err)),
        }
    }
}

pub struct SslStream<S>(imp::SslStream<S>);

impl<S> SslStream<S> {
    pub fn get_ref(&self) -> &S {
        self.0.get_ref()
    }

    pub fn get_mut(&mut self) -> &mut S {
        self.0.get_mut()
    }
}

impl<S: io::Read + io::Write> io::Read for SslStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl<S: io::Read + io::Write> io::Write for SslStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}
