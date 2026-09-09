//! JNI entry points for the Android app (`com.awminamani.mmdf.Native`).
//!
//! Kotlin calls `setDataDir()` once, then `startProxy(configJson)` and gets
//! back a numeric handle. The proxy runs on its own tokio runtime; `stopProxy`
//! / `statsJson` / `exportCa` / `testSni` / `drainLogs` round it out.
//!
//! Every entry point catches panics so nothing unwinds across JNI (UB).

#![cfg(target_os = "android")]

use std::collections::VecDeque;
use std::panic::AssertUnwindSafe;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use jni::objects::{JClass, JString};
use jni::sys::{jint, jlong, jstring};
use jni::JNIEnv;
use tokio::runtime::Runtime;
use tokio::sync::oneshot;

use crate::config::MmdfConfig;
use crate::mitm::CaManager;
use crate::proxy_server::ProxyServer;

struct Running {
    shutdown: Option<oneshot::Sender<()>>,
    rt: Option<Runtime>,
    stats: Option<Arc<crate::proxy_server::Stats>>,
}

static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);

fn slots() -> &'static Mutex<std::collections::HashMap<u64, Running>> {
    static S: OnceLock<Mutex<std::collections::HashMap<u64, Running>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

fn data_dir_cell() -> &'static Mutex<PathBuf> {
    static D: OnceLock<Mutex<PathBuf>> = OnceLock::new();
    D.get_or_init(|| Mutex::new(PathBuf::from(".")))
}

pub fn data_dir() -> PathBuf {
    data_dir_cell()
        .lock()
        .map(|g| (*g).clone())
        .unwrap_or_else(|_| PathBuf::from("."))
}

extern "C" {
    fn __android_log_write(prio: i32, tag: *const std::os::raw::c_char, text: *const std::os::raw::c_char) -> i32;
}
const LOG_INFO: i32 = 4;
const RING_CAP: usize = 500;

fn ring() -> &'static Mutex<VecDeque<String>> {
    static R: OnceLock<Mutex<VecDeque<String>>> = OnceLock::new();
    R.get_or_init(|| Mutex::new(VecDeque::with_capacity(RING_CAP)))
}

struct LogcatWriter;
impl std::io::Write for LogcatWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let t = if buf.ends_with(b"\n") { &buf[..buf.len() - 1] } else { buf };
        let mut c = Vec::with_capacity(t.len() + 1);
        c.extend_from_slice(t);
        c.push(0);
        static TAG: &[u8] = b"mmdf\0";
        unsafe {
            __android_log_write(
                LOG_INFO,
                TAG.as_ptr() as *const std::os::raw::c_char,
                c.as_ptr() as *const std::os::raw::c_char,
            );
        }
        if let Ok(mut g) = ring().lock() {
            if g.len() >= RING_CAP {
                g.pop_front();
            }
            g.push_back(String::from_utf8_lossy(t).into_owned());
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogcatWriter {
    type Writer = LogcatWriter;
    fn make_writer(&'a self) -> LogcatWriter {
        LogcatWriter
    }
}

fn init_logging() {
    use std::sync::Once;
    static O: Once = Once::new();
    O.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_target(false)
            .with_ansi(false)
            .with_writer(LogcatWriter)
            .try_init();
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn js(env: &mut JNIEnv, s: &JString) -> String {
    env.get_string(s).map(|v| v.into()).unwrap_or_default()
}

fn safe<F: FnOnce() -> R + std::panic::UnwindSafe, R>(dflt: R, f: F) -> R {
    std::panic::catch_unwind(f).unwrap_or(dflt)
}

#[no_mangle]
pub extern "system" fn Java_com_awminamani_mmdf_Native_setDataDir(
    mut env: JNIEnv,
    _c: JClass,
    path: JString,
) {
    let _ = safe((), AssertUnwindSafe(|| {
        init_logging();
        let p = js(&mut env, &path);
        if !p.is_empty() {
            if let Ok(mut g) = data_dir_cell().lock() {
                *g = PathBuf::from(p);
            }
        }
    }));
}

#[no_mangle]
pub extern "system" fn Java_com_awminamani_mmdf_Native_startProxy(
    mut env: JNIEnv,
    _c: JClass,
    cfg: JString,
) -> jlong {
    safe(0i64, AssertUnwindSafe(|| {
        init_logging();
        let raw = js(&mut env, &cfg);
        let config = match MmdfConfig::parse_mixed(&raw) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("android: bad config: {e}");
                return 0;
            }
        };
        if let Err(e) = config.validate() {
            tracing::error!("android: invalid config: {e}");
            return 0;
        }
        crate::logging::init("info");
        let server = Arc::new(ProxyServer::new(config));
        let stats = server.stats.clone();
        let rt = match tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
        {
            Ok(r) => r,
            Err(e) => {
                tracing::error!("android: runtime: {e}");
                return 0;
            }
        };
        let (tx, rx) = oneshot::channel::<()>();
        let srv = server.clone();
        rt.spawn(async move {
            let _ = srv.run(rx).await;
        });
        // give the listeners a moment to bind; then sanity-check the handle
        std::thread::sleep(std::time::Duration::from_millis(400));
        let h = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut m) = slots().lock() {
            m.insert(
                h,
                Running {
                    shutdown: Some(tx),
                    rt: Some(rt),
                    stats: Some(stats),
                },
            );
        }
        tracing::info!("android: proxy started handle={h}");
        h as jlong
    }))
}

#[no_mangle]
pub extern "system" fn Java_com_awminamani_mmdf_Native_stopProxy(
    _env: JNIEnv,
    _c: JClass,
    handle: jlong,
) -> bool {
    safe(false, AssertUnwindSafe(|| {
        let rec = slots().lock().ok().and_then(|mut m| m.remove(&(handle as u64)));
        match rec {
            Some(Running { shutdown, rt, .. }) => {
                if let Some(tx) = shutdown {
                    let _ = tx.send(());
                }
                if let Some(rt) = rt {
                    rt.shutdown_timeout(std::time::Duration::from_secs(5));
                }
                tracing::info!("android: proxy stopped handle={handle}");
                true
            }
            None => false,
        }
    }))
}

#[no_mangle]
pub extern "system" fn Java_com_awminamani_mmdf_Native_exportCa<'a>(
    env: JNIEnv,
    _c: JClass,
    dest: JString,
) -> bool {
    let mut env = env;
    safe(false, AssertUnwindSafe(|| {
        init_logging();
        let d: String = js(&mut env, &dest);
        if d.is_empty() {
            return false;
        }
        // ensure CA exists, then copy
        if CaManager::open().is_err() {
            return false;
        }
        let src = CaManager::ca_crt_path();
        match std::fs::copy(&src, &d) {
            Ok(n) => n > 0,
            Err(e) => {
                tracing::error!("exportCa: {e}");
                false
            }
        }
    }))
}

#[no_mangle]
pub extern "system" fn Java_com_awminamani_mmdf_Native_version<'a>(env: JNIEnv, _c: JClass) -> jstring {
    let s = format!("mmdf-client {}", env!("CARGO_PKG_VERSION"));
    env.new_string(s).map(|v| v.into_raw()).unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub extern "system" fn Java_com_awminamani_mmdf_Native_drainLogs<'a>(env: JNIEnv, _c: JClass) -> jstring {
    let blob = safe(String::new(), AssertUnwindSafe(|| {
        let mut out = Vec::new();
        if let Ok(mut g) = ring().lock() {
            while let Some(l) = g.pop_front() {
                out.push(l);
            }
        }
        out.join("\n")
    }));
    env.new_string(blob).map(|v| v.into_raw()).unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub extern "system" fn Java_com_awminamani_mmdf_Native_testSni<'a>(
    mut env: JNIEnv<'a>,
    _c: JClass,
    ip: JString,
    sni: JString,
) -> jstring {
    let out = safe(r#"{"ok":false,"error":"panic"}"#.to_string(), AssertUnwindSafe(|| {
        init_logging();
        let ip = js(&mut env, &ip);
        let sni = js(&mut env, &sni);
        if ip.is_empty() || sni.is_empty() {
            return r#"{"ok":false,"error":"empty ip or sni"}"#.to_string();
        }
        let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
            Ok(r) => r,
            Err(_) => return r#"{"ok":false,"error":"tokio init failed"}"#.to_string(),
        };
        match rt.block_on(crate::fronting::probe_sni(&ip, &sni)) {
            Ok(ms) => format!(r#"{{"ok":true,"latencyMs":{ms}}}"#),
            Err(e) => {
                let c = e.replace('\\', "\\\\").replace('"', "\\\"");
                format!(r#"{{"ok":false,"error":"{c}"}}"#)
            }
        }
    }));
    env.new_string(out).map(|v| v.into_raw()).unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub extern "system" fn Java_com_awminamani_mmdf_Native_statsJson<'a>(
    mut env: JNIEnv<'a>,
    _c: JClass,
    handle: jlong,
) -> jstring {
    let out = safe(String::new(), AssertUnwindSafe(|| {
        let guard = match slots().lock() {
            Ok(g) => g,
            Err(_) => return String::new(),
        };
        let rec = match guard.get(&(handle as u64)) {
            Some(r) => r,
            None => return String::new(),
        };
        match rec.stats.as_ref() {
            Some(s) => s.snapshot().to_string(),
            None => String::new(),
        }
    }));
    env.new_string(out).map(|v| v.into_raw()).unwrap_or(std::ptr::null_mut())
}

/// Start tun2proxy via its C API (`tun2proxy_run_with_cli_args`, dlsym'd
/// from libtun2proxy.so). BLOCKS until the TUN tears down.
#[no_mangle]
pub extern "system" fn Java_com_awminamani_mmdf_Native_runTun2proxy(
    mut env: JNIEnv,
    _c: JClass,
    cli: JString,
    mtu: jint,
) -> jint {
    safe(-1, AssertUnwindSafe(|| {
        let args = js(&mut env, &cli);
        tracing::info!("runTun2proxy: {args}");
        unsafe {
            use std::ffi::{CStr, CString};
            let lib = CString::new("libtun2proxy.so").unwrap();
            let h = libc::dlopen(lib.as_ptr(), libc::RTLD_NOW);
            if h.is_null() {
                let e = CStr::from_ptr(libc::dlerror());
                tracing::error!("dlopen libtun2proxy.so: {e:?}");
                return -10;
            }
            let sym = CString::new("tun2proxy_run_with_cli_args").unwrap();
            let f = libc::dlsym(h, sym.as_ptr());
            if f.is_null() {
                let e = CStr::from_ptr(libc::dlerror());
                tracing::error!("dlsym: {e:?}");
                libc::dlclose(h);
                return -11;
            }
            type Run = unsafe extern "C" fn(*const std::ffi::c_char, u16, bool) -> i32;
            let run: Run = std::mem::transmute(f);
            let c_args = CString::new(args).unwrap();
            let rc = run(c_args.as_ptr(), mtu as u16, false);
            libc::dlclose(h);
            rc
        }
    }))
}
