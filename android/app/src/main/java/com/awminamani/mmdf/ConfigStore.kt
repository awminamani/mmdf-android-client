package com.awminamani.mmdf

import android.content.Context
import org.json.JSONObject
import java.io.File

/**
 * Config I/O. Source of truth is config.json in the app files dir —
 * the Rust side parses the same JSON, so there is one schema.
 */
data class MmdfUiConfig(
    val frontDomain: String = "www.google.com",
    val connectIp: String = "142.251.36.68",
    val listenPort: Int = 8080,
    val socks5Port: Int = 1081,
    val verifySsl: Boolean = true,
    val logLevel: String = "info",
    val extraDomains: String = "",   // newline/comma separated
    val sniMeta: String = "www.microsoft.com",
    val sniFastly: String = "github.githubassets.com",
    val enabledGoogle: Boolean = true,
    val enabledMeta: Boolean = true,
    val enabledFastly: Boolean = true,
    val enabledDns: Boolean = true,
)

object ConfigStore {
    private const val NAME = "config.json"

    fun file(ctx: Context): File = File(ctx.filesDir, NAME)

    fun load(ctx: Context): MmdfUiConfig {
        val f = file(ctx)
        if (!f.exists()) return MmdfUiConfig()
        return try {
            val o = JSONObject(f.readText())
            MmdfUiConfig(
                frontDomain = o.optString("frontDomain", "www.google.com"),
                connectIp = o.optString("connectIp", "142.251.36.68"),
                listenPort = o.optInt("listenPort", 8080),
                socks5Port = o.optInt("socks5Port", 1081),
                verifySsl = o.optBoolean("verifySsl", true),
                logLevel = o.optString("logLevel", "info"),
                extraDomains = o.optString("extraDomains", ""),
                sniMeta = o.optString("sniMeta", "www.microsoft.com"),
                sniFastly = o.optString("sniFastly", "github.githubassets.com"),
                enabledGoogle = o.optBoolean("enabledGoogle", true),
                enabledMeta = o.optBoolean("enabledMeta", true),
                enabledFastly = o.optBoolean("enabledFastly", true),
                enabledDns = o.optBoolean("enabledDns", true),
            )
        } catch (_: Throwable) {
            MmdfUiConfig()
        }
    }

    fun save(ctx: Context, c: MmdfUiConfig) {
        val o = JSONObject()
        o.put("frontDomain", c.frontDomain)
        o.put("connectIp", c.connectIp)
        o.put("listenPort", c.listenPort)
        o.put("socks5Port", c.socks5Port)
        o.put("verifySsl", c.verifySsl)
        o.put("logLevel", c.logLevel)
        o.put("extraDomains", c.extraDomains)
        o.put("sniMeta", c.sniMeta)
        o.put("sniFastly", c.sniFastly)
        o.put("enabledGoogle", c.enabledGoogle)
        o.put("enabledMeta", c.enabledMeta)
        o.put("enabledFastly", c.enabledFastly)
        o.put("enabledDns", c.enabledDns)
        file(ctx).writeText(o.toString(2))
    }

    /** Build the JSON the Rust side parses (MmdfConfig shape). */
    fun toRustJson(c: MmdfUiConfig): String {
        fun grp(name: String, sni: String, domains: List<String>): JSONObject {
            val g = JSONObject()
            g.put("name", name)
            g.put("sni", sni)
            g.put("connect_ip", "")
            val arr = org.json.JSONArray()
            domains.forEach { arr.put(it) }
            g.put("domains", arr)
            return g
        }
        val groups = org.json.JSONArray()
        if (c.enabledGoogle) groups.put(grp("google", c.frontDomain, listOf(
            "google.com", "youtube.com", "youtu.be", "googlevideo.com",
            "ytimg.com", "gstatic.com", "googleapis.com",
            "googleusercontent.com", "ggpht.com", "gvt1.com", "gvt2.com",
        )))
        if (c.enabledMeta) groups.put(grp("meta", c.sniMeta, listOf(
            "facebook.com", "instagram.com", "whatsapp.com", "whatsapp.net",
            "fb.com", "fbcdn.net", "meta.com",
        )))
        if (c.enabledFastly) groups.put(grp("fastly", c.sniFastly, listOf(
            "reddit.com", "fastly.net", "githubassets.com", "githubusercontent.com",
        )))
        if (c.enabledDns) groups.put(grp("dns", c.sniMeta, listOf(
            "dns.google", "cloudflare-dns.com", "dns.quad9.net",
        )))
        val extra = c.extraDomains.split(',', '\n', ';', ' ', '\t')
            .map { it.trim().trimStart('.').lowercase() }
            .filter { it.isNotEmpty() && it.contains('.') }
            .distinct()
        val o = JSONObject()
        o.put("listen_host", "127.0.0.1")
        o.put("listen_port", c.listenPort)
        o.put("socks5_port", c.socks5Port)
        o.put("connect_ip", c.connectIp)
        o.put("front_domain", c.frontDomain)
        o.put("verify_ssl", c.verifySsl)
        o.put("log_level", c.logLevel)
        o.put("groups", groups)
        val pt = org.json.JSONArray()
        pt.put("localhost"); pt.put("127.0.0.1")
        o.put("passthrough", pt)
        val ex = org.json.JSONArray()
        extra.forEach { ex.put(it) }
        o.put("extra_domains", ex)
        return o.toString()
    }
}
