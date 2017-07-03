extern crate native_tls;

pub use native_tls::*;


macro_rules! p {
    ($e:expr) => {
        match $e {
            Ok(r) => r,
            Err(e) => panic!("{:?}", e),
        }
    }
}
