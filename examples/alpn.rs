
#[cfg(feature = "alpn")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use native_tls::Protocol;
    use native_tls::TlsConnector;
    use native_tls::ApplicationProtocol;

    let domain = "video.qq.com";
    let host = (domain, 443);
    let alpns = &["h2", "dot", "http/1.1"];
    
    println!("#1: tcp connect to {:?} ...", host);
    let tcp_stream = std::net::TcpStream::connect(host)?;

    let tls_connector = TlsConnector::builder()
        .use_sni(true)
        .min_protocol_version(Some(Protocol::Tlsv12))
        .max_protocol_version(Some(Protocol::Tlsv12))
        .alpn_protocols(alpns)
        // .add_root_certificate(root_ca)
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(false)
        .build()?;

    println!("#2: tls connect to {:?} with alpns {:?} ...", domain, alpns);
    let tls_stream = tls_connector.connect(domain, tcp_stream)?;

    println!("#3: alpn negotiating ...");
    let alpn: Option<ApplicationProtocol<Vec<u8>>> = tls_stream.negotiated_alpn()?;
    println!("negotiated alpn result: {:?}", alpn);
    
    Ok(())
}


#[cfg(not(feature = "alpn"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("ALPN feature not enabled.");
    println!("try run:\n\t$ cargo run --example alpn --features alpn");
    Ok(())
}