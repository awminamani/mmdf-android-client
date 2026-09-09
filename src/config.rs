//! App-wide configuration for the MMDF client.
//!
//! The client implements the MITM + DomainFronting trick with no server:
//!  1. A local proxy accepts browser traffic.
//!  2. For selected hosts it terminates TLS locally (MITM) using an
//!     on-device CA the user trusts once.
//!  3. The now-plaintext request is re-sent inside a NEW TLS connection
//!     whose SNI is a benign, unfiltered name (e.g. www.google.com) while
//!     the HTTP Host / path still points at the real destination.
//! A censor watching the wire only sees "TLS to www.google.com".

use serde::{Deserialize, Serialize};

/// One fronting group: real target suffixes + which benign SNI/IP to hide behind.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrontGroup {
    pub name: String,
    pub sni: String,
    #[serde(default)]
    pub connect_ip: String,
    pub domains: Vec<String>,
}

impl FrontGroup {
    pub fn matches(&self, host: &str) -> bool {
        let h = host.trim_end_matches('.').to_ascii_lowercase();
        self.domains.iter().any(|d| {
            let d = d.to_ascii_lowercase();
            h == d || h.ends_with(&format!(".{d}"))
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MmdfConfig {
    #[serde(default = "d_host")]
    pub listen_host: String,
    #[serde(default = "d_http")]
    pub listen_port: u16,
    #[serde(default = "d_socks")]
    pub socks5_port: u16,

    /// Default egress: IP we TCP-connect to (Google edge / anycast).
    #[serde(default = "d_ip")]
    pub connect_ip: String,
    /// Default benign SNI presented on the egress TLS handshake.
    #[serde(default = "d_sni")]
    pub front_domain: String,

    #[serde(default = "d_true")]
    pub verify_ssl: bool,
    #[serde(default = "d_info")]
    pub log_level: String,

    #[serde(default = "d_groups")]
    pub groups: Vec<FrontGroup>,

    /// Hosts that must NEVER be MITM'd (banking, local, etc).
    #[serde(default)]
    pub passthrough: Vec<String>,
    /// Extra user domains forced through the default front leg.
    #[serde(default)]
    pub extra_domains: Vec<String>,
}

fn d_host() -> String {
    "127.0.0.1".into()
}
fn d_http() -> u16 {
    8080
}
fn d_socks() -> u16 {
    1081
}
fn d_ip() -> String {
    "142.251.36.68".into()
}
fn d_sni() -> String {
    "www.google.com".into()
}
fn d_true() -> bool {
    true
}
fn d_info() -> String {
    "info".into()
}

fn d_groups() -> Vec<FrontGroup> {
    vec![
        FrontGroup {
            name: "google".into(),
            sni: "www.google.com".into(),
            connect_ip: String::new(), // empty = use global connect_ip
            domains: vec![
                "google.com".into(),
                "youtube.com".into(),
                "youtu.be".into(),
                "googlevideo.com".into(),
                "ytimg.com".into(),
                "gstatic.com".into(),
                "googleapis.com".into(),
                "googleusercontent.com".into(),
                "ggpht.com".into(),
                "gvt1.com".into(),
                "gvt2.com".into(),
            ],
        },
        FrontGroup {
            name: "meta".into(),
            sni: "www.microsoft.com".into(),
            connect_ip: String::new(),
            domains: vec![
                "facebook.com".into(),
                "instagram.com".into(),
                "whatsapp.com".into(),
                "whatsapp.net".into(),
                "fb.com".into(),
                "fbcdn.net".into(),
                "meta.com".into(),
            ],
        },
        FrontGroup {
            name: "fastly".into(),
            sni: "github.githubassets.com".into(),
            connect_ip: String::new(),
            domains: vec![
                "reddit.com".into(),
                "fastly.net".into(),
                "githubassets.com".into(),
                "githubusercontent.com".into(),
            ],
        },
        FrontGroup {
            name: "dns".into(),
            sni: "www.microsoft.com".into(),
            connect_ip: String::new(),
            domains: vec![
                "dns.google".into(),
                "cloudflare-dns.com".into(),
                "dns.quad9.net".into(),
            ],
        },
    ]
}

impl Default for MmdfConfig {
    fn default() -> Self {
        Self {
            listen_host: d_host(),
            listen_port: d_http(),
            socks5_port: d_socks(),
            connect_ip: d_ip(),
            front_domain: d_sni(),
            verify_ssl: d_true(),
            log_level: d_info(),
            groups: d_groups(),
            passthrough: vec!["localhost".into(), "127.0.0.1".into()],
            extra_domains: vec![],
        }
    }
}

impl MmdfConfig {
    /// Accept JSON (Android JNI) or TOML (desktop file / pasted text).
    pub fn parse_mixed(s: &str) -> Result<Self, String> {
        if let Ok(c) = serde_json::from_str::<MmdfConfig>(s) {
            return Ok(c);
        }
        match toml::from_str::<MmdfConfig>(s) {
            Ok(c) => Ok(c),
            Err(e) => Err(format!("config parse failed: {e}")),
        }
    }

    pub fn is_passthrough(&self, host: &str) -> bool {
        let h = host.trim_end_matches('.').to_ascii_lowercase();
        self.passthrough.iter().any(|p| {
            let p = p.to_ascii_lowercase();
            h == p || h.ends_with(&format!(".{p}"))
        })
    }

    /// Returns (sni, connect_ip) for a host, or None if not frontable.
    pub fn front_for(&self, host: &str) -> Option<(String, String)> {
        if self.is_passthrough(host) {
            return None;
        }
        for g in &self.groups {
            if g.matches(host) {
                let ip = if g.connect_ip.is_empty() {
                    self.connect_ip.clone()
                } else {
                    g.connect_ip.clone()
                };
                return Some((g.sni.clone(), ip));
            }
        }
        // extra_domains ride the default leg
        let h = host.trim_end_matches('.').to_ascii_lowercase();
        for d in &self.extra_domains {
            let d = d.to_ascii_lowercase();
            if h == d || h.ends_with(&format!(".{d}")) {
                return Some((self.front_domain.clone(), self.connect_ip.clone()));
            }
        }
        None
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.listen_port == 0 || self.socks5_port == 0 {
            return Err("listen ports must be non-zero".into());
        }
        if self.listen_port == self.socks5_port {
            return Err("http and socks5 ports must differ".into());
        }
        if self.connect_ip.is_empty() || self.front_domain.is_empty() {
            return Err("connect_ip and front_domain are required".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn group_match() {
        let c = MmdfConfig::default();
        assert!(c.front_for("www.youtube.com").is_some());
        assert!(c.front_for("x.instagram.com").is_some());
        assert!(c.front_for("example.com").is_none());
        assert!(c.front_for("localhost").is_none());
    }
}
