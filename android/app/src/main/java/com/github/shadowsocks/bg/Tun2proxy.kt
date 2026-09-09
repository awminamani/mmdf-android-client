package com.github.shadowsocks.bg

/**
 * JNI bridge to the tun2proxy crate's Android entry points.
 * Must live in this exact package — the Rust symbols are mangled as
 * Java_com_github_shadowsocks_bg_Tun2proxy_run / _stop.
 * The .so is libtun2proxy.so (shipped alongside libmmdf_client.so).
 */
object Tun2proxy {

    init {
        System.loadLibrary("tun2proxy")
    }

    @JvmStatic
    external fun run(
        proxyUrl: String,
        tunFd: Int,
        closeFdOnDrop: Boolean,
        tunMtu: Char,
        verbosity: Int,
        dnsStrategy: Int,
    ): Int

    @JvmStatic
    external fun stop(): Int
}
