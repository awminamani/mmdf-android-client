package com.awminamani.mmdf

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import com.awminamani.mmdf.ui.HomeScreen
import com.awminamani.mmdf.ui.theme.MmdfTheme

class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Native.setDataDir(filesDir.absolutePath)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED
            ) {
                ActivityCompat.requestPermissions(
                    this, arrayOf(Manifest.permission.POST_NOTIFICATIONS), 42,
                )
            }
        }

        setContent {
            MmdfTheme {
                AppRoot()
            }
        }
    }

    @Composable
    private fun AppRoot() {
        val vpnLauncher = rememberLauncherForActivityResult(
            ActivityResultContracts.StartActivityForResult(),
        ) { result ->
            if (result.resultCode == Activity.RESULT_OK) {
                startVpnService()
            }
        }

        var pendingFp by remember { mutableStateOf<ByteArray?>(null) }
        var caMsg by remember { mutableStateOf<String?>(null) }

        val caLauncher = rememberLauncherForActivityResult(
            ActivityResultContracts.StartActivityForResult(),
        ) { _ ->
            val fp = pendingFp
            caMsg = when {
                fp == null -> "Internal error: no fingerprint"
                CaInstall.isInstalled(fp) -> "Certificate installed ✓"
                else -> "Not installed yet — finish it in Settings (CA certificate), then reconnect."
            }
            pendingFp = null
        }

        HomeScreen(
            onStart = {
                val prep = VpnService.prepare(this)
                if (prep == null) startVpnService()
                else vpnLauncher.launch(prep)
            },
            onStop = {
                startService(
                    Intent(this, MmdfVpnService::class.java)
                        .setAction(MmdfVpnService.ACTION_STOP),
                )
            },
            onInstallCa = {
                // Ensure a CA exists (startProxy creates it, but a bare
                // export attempt works too once native is seeded).
                if (!CaInstall.export(this)) {
                    caMsg = "Couldn't create the CA. Tap Connect once, then retry."
                } else {
                    pendingFp = CaInstall.fingerprint(this)
                    CaInstall.saveToDownloads(this)
                    try {
                        caLauncher.launch(CaInstall.buildSettingsIntent())
                    } catch (_: Throwable) {
                        caMsg = "Couldn't open Settings — install Downloads/mmdf-ca.crt manually as a CA certificate."
                    }
                }
            },
            caMsg = caMsg,
            onCaMsgConsumed = { caMsg = null },
        )
    }

    private fun startVpnService() {
        startService(Intent(this, MmdfVpnService::class.java))
    }
}
