use std::env;

fn main() {
    let no_ssl_mask = if let Ok(version) = env::var("DEP_OPENSSL_VERSION_NUMBER") {
        let version = u64::from_str_radix(&version, 16).unwrap();
        version < 0x1_00_02_00_0
    } else {
        true
    };

    if no_ssl_mask {
        println!("cargo:rustc-cfg=no_ssl_mask");
    }
}
