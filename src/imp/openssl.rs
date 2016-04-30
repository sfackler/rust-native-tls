extern crate openssl;

use std::io;
use std::fmt;
use std::error;
use std::net::IpAddr;
use self::openssl::ssl::{self, SslContext, SslMethod, SSL_VERIFY_PEER, IntoSsl};
use self::openssl::ssl::error::SslError;
use self::openssl::x509::X509;
use self::openssl::nid::Nid;

// This logic is based heavily off of libcurl's
fn verify_hostname(domain: &str, cert: &X509) -> bool {
    let ip = domain.parse();
    match cert.subject_alt_names() {
        Some(names) => {
            for i in 0..names.len() {
                let name = names.get(i);
                match ip {
                    Ok(ip) => {
                        if let Some(actual) = name.ipadd() {
                            if matches_ip(&ip, actual) {
                                return true;
                            }
                        }
                    }
                    Err(_) => {
                        if let Some(pattern) = name.dns() {
                            if matches_dns(pattern, domain, false) {
                                return true;
                            }
                        }
                    }
                }
            }
        }
        None => {
            let subject_name = cert.subject_name();
            if let Some(pattern) = subject_name.text_by_nid(Nid::CN) {
                if matches_dns(&pattern, domain, ip.is_ok()) {
                    return true;
                }
            }
        }
    }

    false
}

// CF curl/lib/hostcheck.c
fn matches_dns(mut pattern: &str, mut hostname: &str, is_ip: bool) -> bool {
    // first strip trailing . off of pattern and hostname to normalize
    if pattern.ends_with('.') {
        pattern = &pattern[..pattern.len() - 1];
    }
    if hostname.ends_with('.') {
        hostname = &hostname[..hostname.len() - 1];
    }

    matches_wildcard(pattern, hostname, is_ip).unwrap_or_else(|| pattern == hostname)
}

fn matches_wildcard(pattern: &str, hostname: &str, is_ip: bool) -> Option<bool> {
    // IP addresses and internationalized domains can't involved in wildcards
    if is_ip || pattern.starts_with("xn--") {
        return None;
    }

    let wildcard_location = match pattern.find('*') {
        Some(l) => l,
        None => return None,
    };

    let mut dot_idxs = pattern.match_indices('.').map(|(l, _)| l);
    let wildcard_end = match dot_idxs.next() {
        Some(l) => l,
        None => return None,
    };

    // Never match wildcards if the pattern has less than 2 '.'s (no *.com)
    if dot_idxs.next().is_none() {
        return None;
    }

    // Wildcards can only be in the first component
    if wildcard_location > wildcard_end {
        return None;
    }

    let hostname_label_end = match hostname.find('.') {
        Some(l) => l,
        None => return None,
    };

    if pattern[wildcard_end..] != hostname[hostname_label_end..] {
        return Some(false);
    }

    let wildcard_prefix = &pattern[..wildcard_location];
    let wildcard_suffix = &pattern[wildcard_location + 1..wildcard_end];

    let hostname_label = &hostname[..hostname_label_end];

    if !hostname_label.starts_with(wildcard_prefix) {
        return Some(false);
    }

    if !hostname_label[wildcard_prefix.len()..].ends_with(wildcard_suffix) {
        return Some(false);
    }

    Some(true)
}

fn matches_ip(expected: &IpAddr, actual: &[u8]) -> bool {
    match (expected, actual.len()) {
        (&IpAddr::V4(ref addr), 4) => actual == addr.octets(),
        (&IpAddr::V6(ref addr), 16) => {
            let segments = [((actual[0] as u16) << 8) | actual[1] as u16,
                            ((actual[2] as u16) << 8) | actual[3] as u16,
                            ((actual[4] as u16) << 8) | actual[5] as u16,
                            ((actual[6] as u16) << 8) | actual[7] as u16,
                            ((actual[8] as u16) << 8) | actual[9] as u16,
                            ((actual[10] as u16) << 8) | actual[11] as u16,
                            ((actual[12] as u16) << 8) | actual[13] as u16,
                            ((actual[14] as u16) << 8) | actual[15] as u16];
            segments == addr.segments()
        }
        _ => false,
    }
}

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
        try!(ctx.set_default_verify_paths());
        Ok(ClientBuilder(ctx))
    }

    pub fn handshake<S>(&mut self, domain: &str, stream: S) -> Result<TlsStream<S>, Error>
        where S: io::Read + io::Write
    {
        let mut ssl = try!(self.0.into_ssl());
        try!(ssl.set_hostname(domain));
        let domain = domain.to_owned();
        ssl.set_verify(SSL_VERIFY_PEER, move |preverify_ok, x509_ctx| {
            if !preverify_ok || x509_ctx.error_depth() != 0 {
                return preverify_ok;
            }

            if let Some(x509) = x509_ctx.get_current_cert() {
                verify_hostname(&domain, &x509)
            } else {
                true
            }
        });

        let s = try!(ssl::SslStream::connect(ssl, stream));
        Ok(TlsStream(s))
    }
}

pub struct TlsStream<S>(ssl::SslStream<S>);

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
