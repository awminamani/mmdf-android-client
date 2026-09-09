package com.awminamani.mmdf

import android.content.Context
import android.content.Intent
import android.provider.Settings
import java.io.File
import java.security.MessageDigest
import java.security.cert.CertificateFactory

/**
 * MITM CA install flow:
 *  1. export() — Native.exportCa to <filesDir>/mmdf-ca.crt
 *  2. saveToDownloads() — copy where the user can find it in Files
 *  3. buildSettingsIntent() — open Security Settings; user installs
 *     via "CA certificate" search result.
 *  4. isInstalled(fp) — fingerprint check in AndroidCAStore.
 */
object CaInstall {
    private const val CA_FILENAME = "mmdf-ca.crt"
    const val FRIENDLY_NAME = "MMDF Local CA"

    fun caFile(ctx: Context): File = File(ctx.filesDir, CA_FILENAME)

    fun export(ctx: Context): Boolean {
        val dest = caFile(ctx)
        if (!Native.exportCa(dest.absolutePath)) return false
        return dest.exists() && dest.length() > 0
    }

    fun saveToDownloads(ctx: Context): String? {
        return try {
            val src = caFile(ctx)
            if (!src.exists()) return null
            val dl = android.os.Environment.getExternalStoragePublicDirectory(
                android.os.Environment.DIRECTORY_DOWNLOADS,
            )
            dl.mkdirs()
            val out = File(dl, CA_FILENAME)
            src.copyTo(out, overwrite = true)
            "Downloads/${out.name}"
        } catch (_: Throwable) {
            null
        }
    }

    fun buildSettingsIntent(): Intent = Intent(Settings.ACTION_SECURITY_SETTINGS)

    fun readDer(ctx: Context): ByteArray? {
        val f = caFile(ctx)
        if (!f.exists()) return null
        val raw = try { f.readBytes() } catch (_: Throwable) { return null }
        return pemToDer(raw) ?: raw
    }

    fun fingerprint(ctx: Context): ByteArray? {
        val der = readDer(ctx) ?: return null
        return MessageDigest.getInstance("SHA-256").digest(der)
    }

    fun fingerprintHex(b: ByteArray): String = b.joinToString(":") { "%02X".format(it) }

    fun isInstalled(fp: ByteArray): Boolean {
        return try {
            val cf = CertificateFactory.getInstance("X.509")
            val ks = java.security.KeyStore.getInstance("AndroidCAStore")
            ks.load(null, null)
            val aliases = ks.aliases()
            while (aliases.hasMoreElements()) {
                val a = aliases.nextElement()
                val cert = ks.getCertificate(a) ?: continue
                val digest = MessageDigest.getInstance("SHA-256").digest(cert.encoded)
                if (digest.contentEquals(fp)) return true
            }
            false
        } catch (_: Throwable) {
            false
        }
    }

    private fun pemToDer(raw: ByteArray): ByteArray? {
        return try {
            val s = String(raw)
            if (!s.contains("BEGIN CERTIFICATE")) return null
            val b64 = s.lines()
                .filter { !it.startsWith("-----") }
                .joinToString("")
            android.util.Base64.decode(b64, android.util.Base64.DEFAULT)
        } catch (_: Throwable) {
            null
        }
    }
}
