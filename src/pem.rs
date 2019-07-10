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

/// Convert PEM to DER. If `guard` is specified (e.g. as PEM_CERTIFICATE), then the guardlines are
/// verified to match the expected string. Otherwise, the guardlines are verified to generally have
/// the correct form.
///
/// On failure (due to guardlines syntax or an illegal PEM character), returns None.
pub fn pem_to_der<T: ?Sized + AsRef<[u8]>>(pem: &T, guard: Option<&PemGuard>) -> Option<Vec<u8>> {
    let pem = match std::str::from_utf8(pem.as_ref()) {
        Err(_) => return None,
        Ok(p) => p,
    };
    let pem = match pem.find("-----") {
        Some(i) => pem.split_at(i).1,
        None => return None,
    };
    let mut lines = pem.lines();

    let begin = match lines.next() {
        Some(l) => l,
        None => return None,
    };
    let end = match lines.last() {
        Some(l) => l,
        None => return None,
    };

    if let Some(g) = guard {
        if begin != g.begin || end != g.end {
            return None;
        }
    } else {
        if !begin.starts_with("-----BEGIN ") || !begin.ends_with("-----") ||
                !end.starts_with("-----END") || !end.ends_with("-----") {
            return None;
        }
    }

    let body_start = pem.char_indices()
        .skip(begin.len())
        .skip_while(|t| t.1.is_whitespace())
        .next().unwrap().0;
    let body_end = pem.rmatch_indices(&end).next().unwrap().0;
    pem[body_start..body_end].from_base64().ok()
}

/// Convert DER to PEM. The guardlines use the identifying string chosen by `guard`
/// (e.g. PEM_CERTIFICATE).
pub fn der_to_pem<T: ?Sized + AsRef<[u8]>>(der: &T, guard: &PemGuard) -> String {
    let mut pem = String::new();

    pem.push_str(guard.begin);
    pem.push('\n');
    if der.as_ref().len() > 0 {
        pem.push_str(&der.as_ref().to_base64(*BASE64_PEM));
        pem.push('\n');
    }
    pem.push_str(guard.end);
    pem.push('\n');

    pem
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
fn test_pem() {
    assert!(pem_to_der("", None).is_none());
    assert!(pem_to_der("-----BEGIN CERTIFICATE-----\n-----END JUNK-----\n", Some(PEM_CERTIFICATE)).is_none());
    assert!(pem_to_der("-----BEGIN JUNK-----\n-----END CERTIFICATE-----\n", Some(PEM_CERTIFICATE)).is_none());
    assert_eq!(pem_to_der("-----BEGIN JUNK-----\n-----END GARBAGE-----\n", None).unwrap(), vec![]);
    assert_eq!(pem_to_der("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n", None).unwrap(), vec![]);
    assert!(pem_to_der("-----EGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n", None).is_none());
    assert!(pem_to_der("-----BEGIN CERTIFICATE-----\n-----ND CERTIFICATE-----\n", None).is_none());
    assert!(pem_to_der("-----BEGIN CERTIFICATE----\n-----END CERTIFICATE-----\n", None).is_none());
    assert!(pem_to_der("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE----\n", None).is_none());
    assert_eq!(pem_to_der("-----BEGIN JUNK-----\n\
                          AAECAwQFBgcICQoLDA0ODw==\n\
                          -----END GARBAGE-----\n", None).unwrap(),
               vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
    assert_eq!(pem_to_der("-----BEGIN CERTIFICATE-----\n\
                          AAECAwQFBgcICQoLDA0ODw==\n\
                          -----END CERTIFICATE-----\n", None).unwrap(),
               vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
}

#[test]
fn test_roundtrip_whole_line() {
    // Test the case where the PEM is a multiple of whole lines.
    let test_cert =
"-----BEGIN CERTIFICATE-----
MIIHBTCCBe2gAwIBAgIRAIFsdIAf8kR29DFR7K4znoIwDQYJKoZIhvcNAQELBQAw
-----END CERTIFICATE-----
";

    assert_eq!(der_to_pem(&pem_to_der(test_cert, Some(PEM_CERTIFICATE)).unwrap(), PEM_CERTIFICATE), test_cert);
}

#[test]
fn test_wrapping() {
    let mut v: Vec<u8> = vec![];
    let bytes_per_line = BASE64_PEM_WRAP * 3 / 4;
    for i in 0..2*bytes_per_line {
        let pem = der_to_pem(&v, PEM_CERTIFICATE);
        // Check that we can do a round trip, and that we got the expected number of lines.
        assert_eq!(pem_to_der(&pem, Some(PEM_CERTIFICATE)).unwrap(), v);
        assert_eq!(pem.matches("\n").count(), 2 + (i + bytes_per_line - 1) / bytes_per_line);
        v.push(0);
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
