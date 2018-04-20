use std::env;

fn main() {
    match env::var("DEP_OPENSSL_VERSION") {
        Ok(ref v) if v == "101" => println!("cargo:rustc-cfg=ossl101"),
        _ => {}
    }
}
