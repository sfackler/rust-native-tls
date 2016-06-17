use std::error;
use std::io;
use std::fmt;

#[cfg(target_os = "macos")]
#[path = "imp/security_framework.rs"]
mod imp;
#[cfg(target_os = "windows")]
#[path = "imp/schannel.rs"]
mod imp;
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
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

    pub fn handshake<S>(&mut self, domain: &str, stream: S) -> Result<TlsStream<S>>
        where S: io::Read + io::Write
    {
        match self.0.handshake(domain, stream) {
            Ok(s) => Ok(TlsStream(s)),
            Err(err) => Err(Error(err)),
        }
    }
}

pub struct TlsStream<S>(imp::TlsStream<S>);

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

fn _check_kinds() {
    use std::net::TcpStream;

    fn is_sync<T: Sync>() {}
    fn is_send<T: Send>() {}
    is_sync::<Error>();
    is_send::<Error>();
    is_sync::<ClientBuilder>();
    is_send::<ClientBuilder>();
    is_sync::<TlsStream<TcpStream>>();
    is_send::<TlsStream<TcpStream>>();
}
