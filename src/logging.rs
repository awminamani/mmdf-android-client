use tracing_subscriber::EnvFilter;

/// Install a compact log subscriber once (idempotent).
pub fn init(level: &str) {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let f = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
        let _ = tracing_subscriber::fmt()
            .with_env_filter(f)
            .with_target(false)
            .with_ansi(false)
            .try_init();
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}
