#![allow(unused)]
use rustc_serialize::base64::{self, FromBase64, ToBase64};

/// Type of the various `PEM_*` constants supplied to `pem_to_der` / `der_to_pem`.
pub struct PemGuard {
    begin: &'static str,
    end: &'static str,
}

macro_rules! pem_guard {
    ($n:expr) => {
        &PemGuard {
            begin: concat!("-----BEGIN ", $n, "-----"),
            end: concat!("-----END ", $n, "-----"),
        }
    }
}

// Ref. RFC7468, although these are not universally respected.
pub const PEM_CERTIFICATE: &'static PemGuard = pem_guard!("CERTIFICATE");
pub const PEM_CERTIFICATE_REQUEST: &'static PemGuard = pem_guard!("CERTIFICATE REQUEST");
pub const PEM_ENCRYPTED_PRIVATE_KEY: &'static PemGuard = pem_guard!("ENCRYPTED PRIVATE KEY");
pub const PEM_PRIVATE_KEY: &'static PemGuard = pem_guard!("PRIVATE KEY");
pub const PEM_PUBLIC_KEY: &'static PemGuard = pem_guard!("PUBLIC KEY");
pub const PEM_CMS: &'static PemGuard = pem_guard!("CMS");

const BASE64_PEM_WRAP: usize = 64;

lazy_static!{
    static ref BASE64_PEM: base64::Config = base64::Config {
        char_set: base64::CharacterSet::Standard,
        newline: base64::Newline::LF,
        pad: true,
        line_length: Some(BASE64_PEM_WRAP),
    };
}

/// Split data by PEM guard lines
pub struct PemBlock<'a> {
    pem_block: &'a str,
    cur_end: usize,
}

impl<'a> PemBlock<'a> {
    pub fn new(data: &'a [u8]) -> PemBlock<'a> {
        let s = ::std::str::from_utf8(data).unwrap();
        PemBlock {
            pem_block: s,
            cur_end: s.find("-----BEGIN").unwrap_or(s.len()),
        }
    }
}

impl<'a> Iterator for PemBlock<'a> {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<Self::Item> {
        let last = self.pem_block.len();
        if self.cur_end >= last {
            return None;
        }
        let begin = self.cur_end;
        let pos = self.pem_block[begin + 1..].find("-----BEGIN");
        self.cur_end = match pos {
            Some(end) => end + begin + 1,
            None => last,
        };
        return Some(&self.pem_block[begin..self.cur_end].as_bytes());
    }
}

#[test]
fn test_split() {
    // Split three certs, CRLF line terminators.
    assert_eq!(PemBlock::new(b"-----BEGIN FIRST-----\r\n-----END FIRST-----\r\n\
        -----BEGIN SECOND-----\r\n-----END SECOND\r\n\
        -----BEGIN THIRD-----\r\n-----END THIRD\r\n").collect::<Vec<&[u8]>>(),
        vec![b"-----BEGIN FIRST-----\r\n-----END FIRST-----\r\n" as &[u8],
             b"-----BEGIN SECOND-----\r\n-----END SECOND\r\n",
             b"-----BEGIN THIRD-----\r\n-----END THIRD\r\n"]);
    // Split three certs, CRLF line terminators except at EOF.
    assert_eq!(PemBlock::new(b"-----BEGIN FIRST-----\r\n-----END FIRST-----\r\n\
        -----BEGIN SECOND-----\r\n-----END SECOND-----\r\n\
        -----BEGIN THIRD-----\r\n-----END THIRD-----").collect::<Vec<&[u8]>>(),
        vec![b"-----BEGIN FIRST-----\r\n-----END FIRST-----\r\n" as &[u8],
             b"-----BEGIN SECOND-----\r\n-----END SECOND-----\r\n",
             b"-----BEGIN THIRD-----\r\n-----END THIRD-----"]);
    // Split two certs, LF line terminators.
    assert_eq!(PemBlock::new(b"-----BEGIN FIRST-----\n-----END FIRST-----\n\
        -----BEGIN SECOND-----\n-----END SECOND\n").collect::<Vec<&[u8]>>(),
        vec![b"-----BEGIN FIRST-----\n-----END FIRST-----\n" as &[u8],
             b"-----BEGIN SECOND-----\n-----END SECOND\n"]);
    // Split two certs, CR line terminators.
    assert_eq!(PemBlock::new(b"-----BEGIN FIRST-----\r-----END FIRST-----\r\
        -----BEGIN SECOND-----\r-----END SECOND\r").collect::<Vec<&[u8]>>(),
        vec![b"-----BEGIN FIRST-----\r-----END FIRST-----\r" as &[u8],
             b"-----BEGIN SECOND-----\r-----END SECOND\r"]);
    // Split two certs, LF line terminators except at EOF.
    assert_eq!(PemBlock::new(b"-----BEGIN FIRST-----\n-----END FIRST-----\n\
        -----BEGIN SECOND-----\n-----END SECOND").collect::<Vec<&[u8]>>(),
        vec![b"-----BEGIN FIRST-----\n-----END FIRST-----\n" as &[u8],
             b"-----BEGIN SECOND-----\n-----END SECOND"]);
    // Split a single cert, LF line terminators.
    assert_eq!(PemBlock::new(b"-----BEGIN FIRST-----\n-----END FIRST-----\n").collect::<Vec<&[u8]>>(),
        vec![b"-----BEGIN FIRST-----\n-----END FIRST-----\n" as &[u8]]);
    // Split a single cert, LF line terminators except at EOF.
    assert_eq!(PemBlock::new(b"-----BEGIN FIRST-----\n-----END FIRST-----").collect::<Vec<&[u8]>>(),
        vec![b"-----BEGIN FIRST-----\n-----END FIRST-----" as &[u8]]);
    // (Don't) split garbage.
    assert_eq!(PemBlock::new(b"junk").collect::<Vec<&[u8]>>(),
        Vec::<&[u8]>::new());
    assert_eq!(PemBlock::new(b"junk-----BEGIN garbage").collect::<Vec<&[u8]>>(),
        vec![b"-----BEGIN garbage" as &[u8]]);
}
