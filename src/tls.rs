pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}
