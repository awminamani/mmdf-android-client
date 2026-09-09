package com.awminamani.mmdf

/**
 * JNI bindings for the mmdf_client Rust crate (libmmdf_client.so).
 * The proxy runs on a Rust-side tokio runtime, not on the JVM thread.
 */
object Native {

    init {
        System.loadLibrary("mmdf_client")
    }

    /** Must be called once before any other call (pass filesDir path). */
    external fun setDataDir(path: String)

    /** Spin up the proxy. Returns handle (>0) or 0 on failure. */
    external fun startProxy(configJson: String): Long

    /** Stop a running proxy. Idempotent. */
    external fun stopProxy(handle: Long): Boolean

    /** Copy the MITM CA cert to destPath. Used for the install flow. */
    external fun exportCa(destPath: String): Boolean

    /** Crate version. Smoke test for JNI linkage. */
    external fun version(): String

    /** Drain the in-memory log ring buffer. */
    external fun drainLogs(): String

    /** Probe one SNI via one IP. JSON: {"ok":true,"latencyMs":N} or {"ok":false,"error":"..."}. BLOCKS. */
    external fun testSni(connectIp: String, sni: String): String

    /** Live counters JSON for a running handle, or "" if unknown. */
    external fun statsJson(handle: Long): String

    /** Start tun2proxy via its C API. BLOCKS until shutdown. */
    external fun runTun2proxy(cliArgs: String, tunMtu: Int): Int
}
