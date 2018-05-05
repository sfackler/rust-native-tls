use std::env;

fn main() {
    let openssl_version = env::var("DEP_OPENSSL_VERSION_NUMBER")
        .ok()
        .map(|s| u64::from_str_radix(&s, 16).unwrap());

    match openssl_version {
        Some(version) if version >= 0x1_00_02_00_0 => println!("cargo:rustc-cfg=have_no_ssl_mask"),
        _ => {}
    }
}
