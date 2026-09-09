package com.awminamani.mmdf

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import com.github.shadowsocks.bg.Tun2proxy
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Foreground VpnService:
 *  1. Boots the mmdf Rust proxy (HTTP + SOCKS5 on 127.0.0.1).
 *  2. Establishes a TUN capturing all device traffic.
 *  3. Runs tun2proxy on a worker thread (TUN <-> our SOCKS5 bridge).
 *
 * Loop-avoidance: our own UID is excluded via addDisallowedApplication
 * so the proxy's outbound to connect_ip doesn't re-enter the TUN.
 */
class MmdfVpnService : VpnService() {

    private var tun: ParcelFileDescriptor? = null
    private var proxyHandle: Long = 0L
    private var tunThread: Thread? = null
    private val tunRunning = AtomicBoolean(false)
    private val tornDown = AtomicBoolean(false)

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        return when (intent?.action) {
            ACTION_STOP -> {
                try { stopForeground(STOP_FOREGROUND_REMOVE) } catch (_: Throwable) {}
                Thread({
                    teardown()
                    stopSelf()
                }, "mmdf-teardown").start()
                START_NOT_STICKY
            }
            else -> {
                startEverything()
                START_STICKY
            }
        }
    }

    private fun startEverything() {
        Native.setDataDir(filesDir.absolutePath)
        val cfg = ConfigStore.load(this)
        val socks5Port = cfg.socks5Port
        startForeground(NOTIF_ID, buildNotif(cfg.listenPort, socks5Port))

        if (proxyHandle != 0L) {
            try { Native.stopProxy(proxyHandle) } catch (_: Throwable) {}
            proxyHandle = 0L
        }

        proxyHandle = Native.startProxy(ConfigStore.toRustJson(cfg))
        if (proxyHandle == 0L) {
            Log.e(TAG, "Native.startProxy returned 0 — see logcat tag mmdf")
            try { stopForeground(STOP_FOREGROUND_REMOVE) } catch (_: Throwable) {}
            stopSelf()
            return
        }

        val builder = Builder()
            .setSession("mmdf")
            .setMtu(MTU)
            .addAddress("10.0.0.2", 32)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("1.1.1.1")
            .setBlocking(false)
        try {
            builder.addDisallowedApplication(packageName)
        } catch (e: Throwable) {
            Log.w(TAG, "self-exclude failed: ${e.message}")
        }

        val pfd = try {
            builder.establish()
        } catch (t: Throwable) {
            Log.e(TAG, "establish() failed: ${t.message}")
            null
        }
        if (pfd == null) {
            Native.stopProxy(proxyHandle)
            proxyHandle = 0L
            try { stopForeground(STOP_FOREGROUND_REMOVE) } catch (_: Throwable) {}
            stopSelf()
            return
        }
        tun = pfd

        val fd = pfd.detachFd()
        tunRunning.set(true)
        val worker = Thread({
            try {
                val rc = Tun2proxy.run(
                    "socks5://127.0.0.1:$socks5Port",
                    fd,
                    true,
                    MTU.toChar(),
                    3,
                    0, // Virtual DNS: fake 198.18.x.y so we keep hostnames
                )
                Log.i(TAG, "tun2proxy exited rc=$rc")
            } catch (t: Throwable) {
                Log.e(TAG, "tun2proxy crashed: ${t.message}", t)
            } finally {
                tunRunning.set(false)
            }
        }, "tun2proxy")
        try {
            worker.start()
            tunThread = worker
        } catch (t: Throwable) {
            Log.e(TAG, "tun2proxy thread failed: ${t.message}", t)
            tunRunning.set(false)
            try { ParcelFileDescriptor.adoptFd(fd).close() } catch (_: Throwable) {}
            Native.stopProxy(proxyHandle)
            proxyHandle = 0L
            try { stopForeground(STOP_FOREGROUND_REMOVE) } catch (_: Throwable) {}
            stopSelf()
            return
        }

        VpnState.setProxyHandle(proxyHandle)
        VpnState.setRunning(true)
    }

    private fun teardown() {
        if (!tornDown.compareAndSet(false, true)) return
        try { Tun2proxy.stop() } catch (_: Throwable) {}
        try { tunThread?.join(3000) } catch (_: Throwable) {}
        try { tun?.close() } catch (_: Throwable) {}
        tun = null
        if (proxyHandle != 0L) {
            try { Native.stopProxy(proxyHandle) } catch (_: Throwable) {}
            proxyHandle = 0L
        }
        VpnState.setProxyHandle(0L)
        VpnState.setRunning(false)
        tornDown.set(false)
    }

    override fun onDestroy() {
        teardown()
        super.onDestroy()
    }

    private fun buildNotif(httpPort: Int, socksPort: Int): Notification {
        val mgr = getSystemService(NotificationManager::class.java)
        try {
            mgr?.createNotificationChannel(
                NotificationChannel(CHANNEL, "MMDF", NotificationManager.IMPORTANCE_LOW),
            )
        } catch (_: Throwable) {}
        val pi = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        return NotificationCompat.Builder(this, CHANNEL)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle("MMDF running")
            .setContentText("HTTP 127.0.0.1:$httpPort · SOCKS5 127.0.0.1:$socksPort")
            .setContentIntent(pi)
            .setOngoing(true)
            .build()
    }

    companion object {
        const val ACTION_STOP = "com.awminamani.mmdf.STOP"
        private const val TAG = "MmdfVpn"
        private const val CHANNEL = "mmdf"
        private const val NOTIF_ID = 41
        private const val MTU = 1500
    }
}
