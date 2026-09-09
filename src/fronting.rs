//! Fronted egress: TCP to a connect IP + TLS with a benign SNI.
//!
//! The censor sees only the outer handshake (e.g. SNI=www.google.com).
//! Inside, normal HTTP with the REAL Host is exchanged, so the edge
//! routes to the true destination. No relay server, no worker, no key.

use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use tokio::net::TcpStream;
use tokio_rustls::{TlsConnector, TlsStream};

#[derive(Debug, thiserror::Error)]
pub enum FrontError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("tls: {0}")]
    Tls(#[from] rustls::Error),
    #[error("bad name: {0}")]
    Name(String),
    #[error("timeout")]
    Timeout,
}

#[derive(Debug)]
struct NoVerify;
impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end: &CertificateDer,
        _inter: &[CertificateDer],
        _name: &ServerName,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _m: &[u8],
        _c: &CertificateDer,
        _d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // "NoVerify": assert valid without checking.
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        let _ = (m, c, d);
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
        ]
    }
}

fn client_config(verify: bool) -> Result<ClientConfig, rustls::Error> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut b = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    b.alpn_protocols = vec![b"http/1.1".to_vec()];
    if !verify {
        b.dangerous().set_certificate_verifier(Arc::new(NoVerify));
    }
    Ok(b)
}

/// Open TCP to `connect_ip:443` then TLS-handshake with `sni`.
pub async fn connect_fronted(
    connect_ip: &str,
    sni: &str,
    verify: bool,
) -> Result<TlsStream<TcpStream>, FrontError> {
    let cfg = client_config(verify).map_err(FrontError::Tls)?;
    let tcp = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect((connect_ip, 443)))
        .await
        .map_err(|_| FrontError::Timeout)?
        .map_err(FrontError::Io)?;
    tcp.set_nodelay(true).ok();
    let name = ServerName::try_from(sni.to_string()).map_err(|e| FrontError::Name(e.to_string()))?;
    let conn = TlsConnector::from(Arc::new(cfg));
    let tls = tokio::time::timeout(Duration::from_secs(10), conn.connect(name, tcp))
        .await
        .map_err(|_| FrontError::Timeout)?
        .map_err(|e| FrontError::Tls(e))?;
    Ok(tls.into())
}

/// Probe: does `sni` handshake via `connect_ip`? Returns latency ms.
pub async fn probe_sni(connect_ip: &str, sni: &str) -> Result<u64, String> {
    let t0 = std::time::Instant::now();
    match connect_fronted(connect_ip, sni, true).await {
        Ok(_) => Ok(t0.elapsed().as_millis() as u64),
        Err(e) => Err(e.to_string()),
    }
}
