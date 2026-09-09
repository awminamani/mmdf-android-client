//! On-device CA + per-domain leaf issuance for the MITM leg.
//!
//! The user trusts ONE self-signed CA (installed once via Android
//! Settings). For every fronted host the proxy mints a short-lived leaf
//! for that exact name, so the browser sees a valid chain and hands us
//! plaintext. Leaves carry serverAuth EKU + digitalSignature /
//! keyEncipherment KU or modern browsers reject them.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;

#[derive(Debug, thiserror::Error)]
pub enum CaError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("rcgen: {0}")]
    Rcgen(#[from] rcgen::Error),
    #[error("tls: {0}")]
    Tls(#[from] rustls::Error),
    #[error("pem: {0}")]
    Pem(String),
    #[error("bad name: {0}")]
    Name(String),
}

pub const CA_DIR: &str = "mmdf-ca";
pub const CA_KEY: &str = "mmdf-ca/ca.key";
pub const CA_CRT: &str = "mmdf-ca/ca.crt";

fn data_base() -> PathBuf {
    #[cfg(target_os = "android")]
    {
        crate::android_jni::data_dir()
    }
    #[cfg(not(target_os = "android"))]
    {
        PathBuf::from(".")
    }
}

pub struct CaManager {
    ca_der: CertificateDer<'static>,
    ca_key: KeyPair,
    ca_cert: Certificate,
    cache: HashMap<String, Arc<ServerConfig>>,
}

impl CaManager {
    pub fn open() -> Result<Self, CaError> {
        Self::open_in(&data_base())
    }

    pub fn open_in(base: &Path) -> Result<Self, CaError> {
        let key_p = base.join(CA_KEY);
        let crt_p = base.join(CA_CRT);
        if key_p.exists() && crt_p.exists() {
            Self::load(&key_p, &crt_p)
        } else {
            if let Some(p) = key_p.parent() {
                std::fs::create_dir_all(p)?;
            }
            Self::create(&key_p, &crt_p)
        }
    }

    fn load(key_p: &Path, crt_p: &Path) -> Result<Self, CaError> {
        let key_pem = std::fs::read_to_string(key_p)?;
        let crt_pem = std::fs::read_to_string(crt_p)?;
        let key_pair = KeyPair::from_pem(&key_pem)?;
        let mut cur = crt_pem.as_bytes();
        let mut certs: Vec<CertificateDer<'static>> =
            rustls_pemfile::certs(&mut cur).collect::<Result<Vec<_>, _>>()?;
        if certs.is_empty() {
            return Err(CaError::Pem("ca.crt holds no certificate".into()));
        }
        let ca_der = certs.remove(0);
        let params = CertificateParams::from_ca_cert_der(&ca_der)?;
        let ca_cert = params.self_signed(&key_pair)?;
        tracing::info!("loaded MMDF CA from {}", crt_p.display());
        Ok(Self {
            ca_der,
            ca_key: key_pair,
            ca_cert,
            cache: HashMap::new(),
        })
    }

    fn create(key_p: &Path, crt_p: &Path) -> Result<Self, CaError> {
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "MMDF Local CA");
        dn.push(DnType::OrganizationName, "MMDF");
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::minutes(5);
        params.not_after = now + time::Duration::days(3650);
        let kp = KeyPair::generate()?;
        let cert = params.self_signed(&kp)?;
        std::fs::write(crt_p, cert.pem().as_bytes())?;
        std::fs::write(key_p, kp.serialize_pem().as_bytes())?;
        tracing::warn!(
            "generated new MMDF CA at {} — install it as a trusted CA",
            crt_p.display()
        );
        let ca_der = cert.der().clone();
        Ok(Self {
            ca_der,
            ca_key: kp,
            ca_cert: cert,
            cache: HashMap::new(),
        })
    }

    pub fn ca_crt_path() -> PathBuf {
        data_base().join(CA_CRT)
    }

    pub fn server_config(&mut self, domain: &str) -> Result<Arc<ServerConfig>, CaError> {
        if let Some(c) = self.cache.get(domain) {
            return Ok(c.clone());
        }
        let (leaf_der, leaf_key) = self.mint(domain)?;
        let chain = vec![leaf_der, self.ca_der.clone()];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key));
        let mut cfg = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, key)?;
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let arc = Arc::new(cfg);
        if self.cache.len() < 512 {
            self.cache.insert(domain.to_string(), arc.clone());
        }
        Ok(arc)
    }

    fn mint(&self, domain: &str) -> Result<(CertificateDer<'static>, Vec<u8>), CaError> {
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, domain);
        params.distinguished_name = dn;
        let dns_name = domain.try_into().map_err(|e: rcgen::Error| {
            CaError::Name(format!("bad dns name '{domain}': {e}"))
        })?;
        params.subject_alt_names.push(SanType::DnsName(dns_name));
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::minutes(5);
        params.not_after = now + time::Duration::days(90);
        let leaf_key = KeyPair::generate()?;
        let leaf = params.signed_by(&leaf_key, &self.ca_cert, &self.ca_key)?;
        Ok((leaf.der().clone(), leaf_key.serialize_der()))
    }
}
