use std::io;

#[cfg(target_os = "macos")]
#[path = "imp/security_framework.rs"]
mod imp;

#[cfg(not(target_os = "macos"))]
#[path = "imp/openssl.rs"]
mod imp;

pub type Result<T> = std::result::Result<T, Error>;

pub struct Error(imp::Error);

pub struct ClientBuilder(imp::ClientBuilder);

impl ClientBuilder {
    pub fn new() -> Result<ClientBuilder> {
        match imp::ClientBuilder::new() {
            Ok(builder) => Ok(ClientBuilder(builder)),
            Err(err) => Err(Error(err)),
        }
    }
}

pub struct SslStream<S>(imp::SslStream<S>);

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
