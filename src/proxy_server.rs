//! Local proxy: HTTP + SOCKS5 in, fronted-TLS or direct out.
//!
//! Flow per connection:
//!   HTTP CONNECT host:443 / SOCKS5 CONNECT host:443 where host is frontable
//!     -> reply success, TLS-terminate locally with a minted leaf (MITM,
//!        needs the user-trusted CA), open a fronted egress
//!        (TCP to connect_ip:443 + TLS with benign SNI), byte-pipe.
//!   Anything else -> plain TCP to the real target, byte-pipe.
//!   Plain HTTP (absolute-URI) -> forward one request/response over a
//!        fronted or direct connection, keep-alive loop.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio_rustls::{LazyConfigAcceptor, TlsAcceptor};

use crate::config::MmdfConfig;
use crate::fronting::connect_fronted;
use crate::mitm::CaManager;

#[derive(Debug, Default)]
pub struct Stats {
    pub conns: AtomicU64,
    pub fronted: AtomicU64,
    pub direct: AtomicU64,
    pub bytes_up: AtomicU64,
    pub bytes_down: AtomicU64,
}

impl Stats {
    pub fn snapshot(&self) -> serde_json::Value {
        serde_json::json!({
            "conns": self.conns.load(Ordering::Relaxed),
            "fronted": self.fronted.load(Ordering::Relaxed),
            "direct": self.direct.load(Ordering::Relaxed),
            "bytes_up": self.bytes_up.load(Ordering::Relaxed),
            "bytes_down": self.bytes_down.load(Ordering::Relaxed),
        })
    }
}

pub struct ProxyServer {
    pub config: MmdfConfig,
    pub stats: Arc<Stats>,
}

impl ProxyServer {
    pub fn new(config: MmdfConfig) -> Self {
        Self {
            config,
            stats: Arc::new(Stats::default()),
        }
    }

    pub async fn run(self: Arc<Self>, mut stop: oneshot::Receiver<()>) -> anyhow_mod::Result<()> {
        let http_addr: SocketAddr =
            format!("{}:{}", self.config.listen_host, self.config.listen_port)
                .parse()
                .map_err(|e| anyhow_mod::anyhow(format!("bad http addr: {e}")))?;
        let socks_addr: SocketAddr =
            format!("{}:{}", self.config.listen_host, self.config.socks5_port)
                .parse()
                .map_err(|e| anyhow_mod::anyhow(format!("bad socks addr: {e}")))?;
        let http = TcpListener::bind(http_addr).await?;
        let socks = TcpListener::bind(socks_addr).await?;
        tracing::info!("mmdf http  on {http_addr}");
        tracing::info!("mmdf socks on {socks_addr}");
        loop {
            tokio::select! {
                _ = &mut stop => { tracing::info!("proxy stopping"); break; }
                r = http.accept() => {
                    if let Ok((s, _)) = r {
                        let me = self.clone();
                        tokio::spawn(async move { me.handle_http(s).await; });
                    }
                }
                r = socks.accept() => {
                    if let Ok((s, _)) = r {
                        let me = self.clone();
                        tokio::spawn(async move { me.handle_socks(s).await; });
                    }
                }
            }
        }
        Ok(())
    }
}

// tiny anyhow shim to avoid a new dep
pub(crate) mod anyhow {
    #[derive(Debug)]
    pub struct Error(String);
    impl std::fmt::Display for Error {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(&self.0)
        }
    }
    impl std::error::Error for Error {}
    pub type Result<T> = std::result::Result<T, Error>;
    pub fn anyhow(s: String) -> Error {
        Error(s)
    }
}
pub use anyhow as anyhow_mod;

// ---------------- HTTP ----------------

async fn read_head(stream: &mut TcpStream, buf: &mut Vec<u8>) -> std::io::Result<Vec<u8>> {
    buf.clear();
    let mut tmp = [0u8; 4096];
    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "closed",
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > 65536 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "head too big",
            ));
        }
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            return Ok(buf.clone());
        }
    }
}

fn header_len(raw: &[u8]) -> usize {
    raw.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
        .unwrap_or(raw.len())
}

impl ProxyServer {
    async fn handle_http(self: Arc<Self>, mut down: TcpStream) {
        self.stats.conns.fetch_add(1, Ordering::Relaxed);
        let mut buf = Vec::with_capacity(8192);
        loop {
            let raw = match read_head(&mut down, &mut buf).await {
                Ok(r) => r,
                Err(_) => return,
            };
            let hlen = header_len(&raw);
            let mut hdrs = [httparse::EMPTY_HEADER; 64];
            let mut req = httparse::Request::new(&mut hdrs);
            let method;
            let path;
            let host_hdr: Option<String>;
            match req.parse(&raw) {
                Ok(httparse::Status::Complete(_)) => {
                    method = req.method.unwrap_or("").to_string();
                    path = req.path.unwrap_or("").to_string();
                    host_hdr = req
                        .headers
                        .iter()
                        .find(|h| h.name.eq_ignore_ascii_case("host"))
                        .and_then(|h| std::str::from_utf8(h.value).ok())
                        .map(|s| s.to_string());
                }
                _ => return,
            }
            if method.eq_ignore_ascii_case("CONNECT") {
                self.handle_connect(down, &path).await;
                return;
            }
            // plain HTTP with absolute URI
            let (host, port, origin_path) = match split_absolute(&path, host_hdr.as_deref()) {
                Some(t) => t,
                None => return,
            };
            let extra = raw[hlen..].to_vec();
            match self.serve_plain_http(&mut down, &method, &host, port, &origin_path, &raw[..hlen], &extra).await {
                Ok(keep) => {
                    if !keep {
                        return;
                    }
                }
                Err(_) => return,
            }
        }
    }

    async fn handle_connect(self: Arc<Self>, mut down: TcpStream, authority: &str) {
        let (host, port) = match split_host_port(authority, 443) {
            Some(t) => t,
            None => return,
        };
        if port == 443 {
            if let Some((sni, ip)) = self.config.front_for(&host) {
                // MITM leg
                if down.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.is_err() {
                    return;
                }
                let acceptor = LazyConfigAcceptor::new(
                    tokio_rustls::rustls::server::Acceptor::default(),
                    down,
                );
                let start = acceptor.await;
                let Ok(start) = start else { return };
                let hello = start.client_hello();
                let name = hello.server_name().unwrap_or(host.as_str()).to_string();
                let cfg = {
                    let mut mgr = match CaManager::open() {
                        Ok(m) => m,
                        Err(e) => {
                            tracing::error!("ca open: {e}");
                            return;
                        }
                    };
                    match mgr.server_config(&name) {
                        Ok(c) => c,
                        Err(e) => {
                            tracing::error!("mint {name}: {e}");
                            return;
                        }
                    }
                };
                let tls_down = match start.into_stream(cfg).await {
                    Ok(s) => s,
                    Err(_) => return,
                };
                let tls_up = match connect_fronted(&ip, &sni, self.config.verify_ssl).await {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!("front {sni} via {ip}: {e}");
                        return;
                    }
                };
                self.stats.fronted.fetch_add(1, Ordering::Relaxed);
                pipe_counted(tls_down, tls_up, &self.stats).await;
                return;
            }
        }
        // direct
        match TcpStream::connect((host.as_str(), port)).await {
            Ok(mut up) => {
                if down.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.is_err() {
                    return;
                }
                self.stats.direct.fetch_add(1, Ordering::Relaxed);
                pipe_counted(down, up, &self.stats).await;
            }
            Err(_) => {
                let _ = down.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
            }
        }
    }

    /// Forward one plain-HTTP request, return keep-alive flag.
    async fn serve_plain_http(
        self: &Arc<Self>,
        down: &mut TcpStream,
        method: &str,
        host: &str,
        port: u16,
        origin_path: &str,
        head: &[u8],
        extra: &[u8],
    ) -> std::io::Result<bool> {
        let fronted = self.config.front_for(host).is_some();
        let mut up: UpStream = if fronted {
            let (sni, ip) = self.config.front_for(host).unwrap();
            match connect_fronted(&ip, &sni, self.config.verify_ssl).await {
                Ok(t) => {
                    self.stats.fronted.fetch_add(1, Ordering::Relaxed);
                    UpStream::Tls(t)
                }
                Err(e) => {
                    tracing::warn!("front {sni}: {e}");
                    let _ = down.write_all(b"HTTP/1.1 504 Gateway Timeout\r\n\r\n").await;
                    return Ok(false);
                }
            }
        } else {
            self.stats.direct.fetch_add(1, Ordering::Relaxed);
            match TcpStream::connect((host, port)).await {
                Ok(t) => UpStream::Tcp(t),
                Err(_) => {
                    let _ = down.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                    return Ok(false);
                }
            }
        };
        // rebuild origin-form request: swap absolute URI -> path, fix Host, force close-to-server? keep simple: connection: close
        let mut out = rebuild_origin(method, origin_path, head, host, port);
        out.extend_from_slice(extra);
        let keep = wants_keep_alive(head);
        up.write_all(&out).await?;
        up.flush().await?;
        // relay response back (single response; close-delimited or content-length/chunked aware-ish: read until server closes or full body)
        relay_one_response(up, down, &self.stats).await?;
        Ok(keep)
    }

    // ---------------- SOCKS5 ----------------

    async fn handle_socks(self: Arc<Self>, mut down: TcpStream) {
        self.stats.conns.fetch_add(1, Ordering::Relaxed);
        // greeting
        let mut b = [0u8; 2];
        if down.read_exact(&mut b).await.is_err() {
            return;
        }
        if b[0] != 5 {
            return;
        }
        let n = b[1] as usize;
        let mut methods = vec![0u8; n];
        if down.read_exact(&mut methods).await.is_err() {
            return;
        }
        if !methods.contains(&0) {
            let _ = down.write_all(&[5, 0xFF]).await;
            return;
        }
        if down.write_all(&[5, 0]).await.is_err() {
            return;
        }
        // request
        let mut h = [0u8; 4];
        if down.read_exact(&mut h).await.is_err() {
            return;
        }
        if h[0] != 5 || h[1] != 1 {
            let _ = down.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await;
            return; // only CONNECT
        }
        let host = match h[3] {
            1 => {
                let mut ip = [0u8; 4];
                if down.read_exact(&mut ip).await.is_err() {
                    return;
                }
                std::net::Ipv4Addr::from(ip).to_string()
            }
            3 => {
                let mut l = [0u8; 1];
                if down.read_exact(&mut l).await.is_err() {
                    return;
                }
                let mut d = vec![0u8; l[0] as usize];
                if down.read_exact(&mut d).await.is_err() {
                    return;
                }
                String::from_utf8_lossy(&d).to_string()
            }
            4 => {
                let mut ip = [0u8; 16];
                if down.read_exact(&mut ip).await.is_err() {
                    return;
                }
                std::net::Ipv6Addr::from(ip).to_string()
            }
            _ => return,
        };
        let mut pb = [0u8; 2];
        if down.read_exact(&mut pb).await.is_err() {
            return;
        }
        let port = u16::from_be_bytes(pb);

        if port == 443 {
            if let Some((sni, ip)) = self.config.front_for(&host) {
                if down
                    .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                    .await
                    .is_err()
                {
                    return;
                }
                // MITM: client now speaks TLS directly.
                let acceptor = LazyConfigAcceptor::new(
                    tokio_rustls::rustls::server::Acceptor::default(),
                    down,
                );
                let start = acceptor.await;
                let Ok(start) = start else { return };
                let hello = start.client_hello();
                let name = hello.server_name().unwrap_or(host.as_str()).to_string();
                let cfg = {
                    let mut mgr = match CaManager::open() {
                        Ok(m) => m,
                        Err(_) => return,
                    };
                    match mgr.server_config(&name) {
                        Ok(c) => c,
                        Err(_) => return,
                    }
                };
                let tls_down = match start.into_stream(cfg).await {
                    Ok(s) => s,
                    Err(_) => return,
                };
                let tls_up = match connect_fronted(&ip, &sni, self.config.verify_ssl).await {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!("front {sni}: {e}");
                        return;
                    }
                };
                self.stats.fronted.fetch_add(1, Ordering::Relaxed);
                pipe_counted(tls_down, tls_up, &self.stats).await;
                return;
            }
        }
        match TcpStream::connect((host.as_str(), port)).await {
            Ok(up) => {
                if down
                    .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                    .await
                    .is_err()
                {
                    return;
                }
                self.stats.direct.fetch_add(1, Ordering::Relaxed);
                pipe_counted(down, up, &self.stats).await;
            }
            Err(_) => {
                let _ = down.write_all(&[5, 4, 0, 1, 0, 0, 0, 0, 0, 0]).await;
            }
        }
    }
}

enum UpStream {
    Tcp(TcpStream),
    Tls(tokio_rustls::client::TlsStream<TcpStream>),
}

impl UpStream {
    async fn write_all(&mut self, b: &[u8]) -> std::io::Result<()> {
        match self {
            UpStream::Tcp(s) => s.write_all(b).await,
            UpStream::Tls(s) => s.write_all(b).await,
        }
    }
    async fn flush(&mut self) -> std::io::Result<()> {
        match self {
            UpStream::Tcp(s) => s.flush().await,
            UpStream::Tls(s) => s.flush().await,
        }
    }
}

async fn relay_one_response(up: UpStream, down: &mut TcpStream, stats: &Stats) -> std::io::Result<()> {
    // read response head from upstream
    async fn read_head_up(up: &mut UpStream, buf: &mut Vec<u8>) -> std::io::Result<usize> {
        buf.clear();
        let mut tmp = [0u8; 8192];
        loop {
            let n = match up {
                UpStream::Tcp(s) => s.read(&mut tmp).await?,
                UpStream::Tls(s) => s.read(&mut tmp).await?,
            };
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "upstream closed",
                ));
            }
            buf.extend_from_slice(&tmp[..n]);
            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                return Ok(i + 4);
            }
            if buf.len() > 128 * 1024 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "resp head too big",
                ));
            }
        }
    }
    let mut up = up;
    let mut hbuf = Vec::with_capacity(8192);
    let hlen = read_head_up(&mut up, &mut hbuf).await?;
    // parse content-length / chunked / close
    let mut hdrs = [httparse::EMPTY_HEADER; 64];
    let mut resp = httparse::Response::new(&mut hdrs);
    let mut body_mode = BodyMode::Close;
    if let Ok(httparse::Status::Complete(_)) = resp.parse(&hbuf) {
        let mut len: Option<u64> = None;
        let mut chunked = false;
        for h in resp.headers.iter() {
            if h.name.eq_ignore_ascii_case("content-length") {
                if let Ok(v) = std::str::from_utf8(h.value) {
                    len = v.trim().parse().ok();
                }
            }
            if h.name.eq_ignore_ascii_case("transfer-encoding") {
                if let Ok(v) = std::str::from_utf8(h.value) {
                    if v.to_ascii_lowercase().contains("chunked") {
                        chunked = true;
                    }
                }
            }
        }
        let code = resp.code.unwrap_or(0);
        if code == 204 || code == 304 || (100..200).contains(&code) {
            body_mode = BodyMode::None;
        } else if chunked {
            body_mode = BodyMode::Chunked(hbuf[hlen..].to_vec());
        } else if let Some(l) = len {
            body_mode = BodyMode::Length(l, hbuf[hlen..].to_vec());
        }
    }
    down.write_all(&hbuf[..hlen]).await?;
    stats
        .bytes_down
        .fetch_add(hlen as u64, Ordering::Relaxed);
    match body_mode {
        BodyMode::None => {}
        BodyMode::Close => {
            // stream until upstream closes
            let mut tmp = [0u8; 32768];
            loop {
                let n = match up {
                    UpStream::Tcp(ref mut s) => s.read(&mut tmp).await?,
                    UpStream::Tls(ref mut s) => s.read(&mut tmp).await?,
                };
                if n == 0 {
                    break;
                }
                stats.bytes_down.fetch_add(n as u64, Ordering::Relaxed);
                down.write_all(&tmp[..n]).await?;
            }
        }
        BodyMode::Length(mut left, buffered) => {
            if !buffered.is_empty() {
                let take = (buffered.len() as u64).min(left) as usize;
                down.write_all(&buffered[..take]).await?;
                stats.bytes_down.fetch_add(take as u64, Ordering::Relaxed);
                left -= take as u64;
            }
            let mut tmp = [0u8; 32768];
            while left > 0 {
                let n = match up {
                    UpStream::Tcp(ref mut s) => s.read(&mut tmp).await?,
                    UpStream::Tls(ref mut s) => s.read(&mut tmp).await?,
                };
                if n == 0 {
                    break;
                }
                let take = (n as u64).min(left) as usize;
                stats.bytes_down.fetch_add(take as u64, Ordering::Relaxed);
                down.write_all(&tmp[..take]).await?;
                left -= take as u64;
            }
        }
        BodyMode::Chunked(buffered) => {
            // simplest correct: pass through chunk framing until terminal 0-chunk
            let mut acc = buffered;
            let mut tmp = [0u8; 32768];
            loop {
                if let Some(end) = find_chunk_end(&acc) {
                    down.write_all(&acc[..end]).await?;
                    stats.bytes_down.fetch_add(end as u64, Ordering::Relaxed);
                    break;
                }
                // flush what we can safely? just write all and keep tail
                if acc.len() > 1024 * 1024 {
                    down.write_all(&acc).await?;
                    stats.bytes_down.fetch_add(acc.len() as u64, Ordering::Relaxed);
                    acc.clear();
                }
                let n = match up {
                    UpStream::Tcp(ref mut s) => s.read(&mut tmp).await?,
                    UpStream::Tls(ref mut s) => s.read(&mut tmp).await?,
                };
                if n == 0 {
                    if !acc.is_empty() {
                        down.write_all(&acc).await?;
                    }
                    break;
                }
                acc.extend_from_slice(&tmp[..n]);
            }
        }
    }
    down.flush().await?;
    Ok(())
}

enum BodyMode {
    None,
    Close,
    Length(u64, Vec<u8>),
    Chunked(Vec<u8>),
}

fn find_chunk_end(acc: &[u8]) -> Option<usize> {
    // terminal chunk "0\r\n\r\n" (ignore extensions/trailer edge: good enough)
    acc.windows(5)
        .position(|w| w == b"0\r\n\r\n")
        .map(|i| i + 5)
}

async fn pipe_counted<A, B>(a: A, b: B, stats: &Stats)
where
    A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut a = a;
    let mut b = b;
    match tokio::io::copy_bidirectional(&mut a, &mut b).await {
        Ok((up, dn)) => {
            stats.bytes_up.fetch_add(up, Ordering::Relaxed);
            stats.bytes_down.fetch_add(dn, Ordering::Relaxed);
        }
        Err(_) => {}
    }
}

fn split_host_port(auth: &str, def: u16) -> Option<(String, u16)> {
    let a = auth.trim();
    if a.is_empty() {
        return None;
    }
    if let Some(i) = a.rfind(':') {
        if let Ok(p) = a[i + 1..].parse::<u16>() {
            return Some((a[..i].trim_matches(|c| c == '[' || c == ']').to_string(), p));
        }
    }
    Some((a.to_string(), def))
}

fn split_absolute(path: &str, host_hdr: Option<&str>) -> Option<(String, u16, String)> {
    if let Ok(u) = url::Url::parse(path) {
        if u.scheme() != "http" {
            return None;
        }
        let host = u.host_str()?.to_string();
        let port = u.port().unwrap_or(80);
        let mut op = u.path().to_string();
        if let Some(q) = u.query() {
            op.push('?');
            op.push_str(q);
        }
        return Some((host, port, op));
    }
    // origin-form: need Host header
    let h = host_hdr?;
    let (host, port) = split_host_port(h, 80)?;
    Some((host, port, path.to_string()))
}

/// Rebuild request head with origin-form path + correct Host, connection: close to upstream.
fn rebuild_origin(method: &str, origin: &str, head: &[u8], host: &str, port: u16) -> Vec<u8> {
    let mut hdrs = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut hdrs);
    let _ = req.parse(head);
    let mut out = format!("{method} {origin} HTTP/1.1\r\n");
    let host_val = if port == 80 {
        host.to_string()
    } else {
        format!("{host}:{port}")
    };
    let mut wrote_host = false;
    for h in req.headers.iter() {
        let n = h.name;
        if n.eq_ignore_ascii_case("host") {
            out.push_str(&format!("Host: {host_val}\r\n"));
            wrote_host = true;
        } else if n.eq_ignore_ascii_case("proxy-connection")
            || n.eq_ignore_ascii_case("connection")
        {
            continue;
        } else if let Ok(v) = std::str::from_utf8(h.value) {
            out.push_str(&format!("{n}: {v}\r\n"));
        }
    }
    if !wrote_host {
        out.push_str(&format!("Host: {host_val}\r\n"));
    }
    out.push_str("Connection: close\r\n\r\n");
    out.into_bytes()
}

fn wants_keep_alive(head: &[u8]) -> bool {
    // HTTP/1.1 defaults keep-alive unless "connection: close"; HTTP/1.0 opposite.
    let mut hdrs = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut hdrs);
    let (ver, conn) = match req.parse(head) {
        Ok(httparse::Status::Complete(_)) => {
            let c = req
                .headers
                .iter()
                .find(|h| h.name.eq_ignore_ascii_case("connection"))
                .and_then(|h| std::str::from_utf8(h.value).ok())
                .unwrap_or("")
                .to_ascii_lowercase();
            (req.version.unwrap_or(1), c)
        }
        _ => return false,
    };
    if conn.contains("close") {
        return false;
    }
    if ver == 1 {
        return true;
    }
    conn.contains("keep-alive")
}

/// Allow graceful shutdown handle sharing.
pub async fn run_with_shutdown(
    server: Arc<ProxyServer>,
    stop: oneshot::Receiver<()>,
) -> Result<(), String> {
    ProxyServer::run(server, stop)
        .await
        .map_err(|e| e.to_string())
}

pub fn _tls_acceptor_typecheck(_: &TlsAcceptor) {}
