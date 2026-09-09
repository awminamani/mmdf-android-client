package com.awminamani.mmdf.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.awminamani.mmdf.CaInstall
import com.awminamani.mmdf.ConfigStore
import com.awminamani.mmdf.MmdfUiConfig
import com.awminamani.mmdf.Native
import com.awminamani.mmdf.VpnState
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject

@Composable
fun HomeScreen(
    onStart: () -> Unit,
    onStop: () -> Unit,
    onInstallCa: () -> Unit,
    caMsg: String?,
    onCaMsgConsumed: () -> Unit,
) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val snack = remember { SnackbarHostState() }
    val running by VpnState.isRunning.collectAsState()
    val handle by VpnState.proxyHandle.collectAsState()

    var cfg by remember { mutableStateOf(ConfigStore.load(ctx)) }
    var stats by remember { mutableStateOf("") }
    var logs by remember { mutableStateOf("") }
    var testing by remember { mutableStateOf(false) }
    var testRes by remember { mutableStateOf("") }
    var version by remember { mutableStateOf("") }

    fun persist(next: MmdfUiConfig) {
        cfg = next
        ConfigStore.save(ctx, next)
    }

    LaunchedEffect(caMsg) {
        if (caMsg != null) {
            snack.showSnackbar(caMsg)
            onCaMsgConsumed()
        }
    }
    LaunchedEffect(running, handle) {
        if (!running) {
            stats = ""
            return@LaunchedEffect
        }
        while (VpnState.isRunning.value) {
                kotlinx.coroutines.delay(2000)
                try {
                    val h = VpnState.proxyHandle.value
                    if (h != 0L) {
                        val s = withContext(Dispatchers.IO) { Native.statsJson(h) }
                        if (s.isNotEmpty()) {
                            val o = JSONObject(s)
                            stats = "conns ${o.optLong("conns")} · fronted ${o.optLong("fronted")} · direct ${o.optLong("direct")}\n" +
                                "↑ ${o.optLong("bytes_up")} B · ↓ ${o.optLong("bytes_down")} B"
                        }
                    }
                    val l = withContext(Dispatchers.IO) { Native.drainLogs() }
                    if (l.isNotEmpty()) {
                        logs = ((logs + "\n" + l).split("\n").takeLast(80)).joinToString("\n")
                    }
                } catch (_: Throwable) {}
            }
        }
    }
    LaunchedEffect(Unit) {
        version = try {
            withContext(Dispatchers.IO) {
                Native.setDataDir(ctx.filesDir.absolutePath)
                Native.version()
            }
        } catch (_: Throwable) { "" }
    }

    Scaffold(snackbarHost = { SnackbarHost(snack) }) { pad ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(pad)
                .padding(16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("MMDF Client", style = MaterialTheme.typography.headlineSmall, modifier = Modifier.weight(1f))
                if (version.isNotEmpty()) Text(version, style = MaterialTheme.typography.labelSmall)
            }
            Text(
                if (running) "● Running" else "○ Stopped",
                color = if (running) Color(0xFF1B8A3D) else Color.Gray,
            )

            Button(
                onClick = { if (running) onStop() else onStart() },
                colors = ButtonDefaults.buttonColors(
                    containerColor = if (running) Color(0xFFB3261E) else Color(0xFF1B8A3D),
                ),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(if (running) "Disconnect" else "Connect")
            }

            OutlinedButton(onClick = onInstallCa, modifier = Modifier.fillMaxWidth()) {
                Text("Install MITM certificate")
            }
            Text(
                "1. Tap Install, confirm in Settings → install mmdf-ca.crt as a CA certificate.\n" +
                    "2. Set connect IP + front SNI below, tap Connect, accept the VPN prompt.\n" +
                    "3. The CA is yours alone — never share it.",
                style = MaterialTheme.typography.bodySmall,
            )

            Card(modifier = Modifier.fillMaxWidth()) {
                Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Network", style = MaterialTheme.typography.titleSmall)
                    OutlinedTextField(
                        value = cfg.connectIp, onValueChange = { persist(cfg.copy(connectIp = it.trim())) },
                        label = { Text("connect_ip (Google edge)") }, modifier = Modifier.fillMaxWidth(),
                    )
                    OutlinedTextField(
                        value = cfg.frontDomain, onValueChange = { persist(cfg.copy(frontDomain = it.trim())) },
                        label = { Text("front SNI (Google group)") }, modifier = Modifier.fillMaxWidth(),
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedTextField(
                            value = cfg.listenPort.toString(),
                            onValueChange = { v -> v.toIntOrNull()?.let { persist(cfg.copy(listenPort = it)) } },
                            label = { Text("HTTP") }, modifier = Modifier.weight(1f),
                        )
                        OutlinedTextField(
                            value = cfg.socks5Port.toString(),
                            onValueChange = { v -> v.toIntOrNull()?.let { persist(cfg.copy(socks5Port = it)) } },
                            label = { Text("SOCKS5") }, modifier = Modifier.weight(1f),
                        )
                    }
                    OutlinedTextField(
                        value = cfg.extraDomains, onValueChange = { persist(cfg.copy(extraDomains = it)) },
                        label = { Text("extra domains (comma/newline)") }, modifier = Modifier.fillMaxWidth(),
                    )
                }
            }

            Card(modifier = Modifier.fillMaxWidth()) {
                Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text("Front groups", style = MaterialTheme.typography.titleSmall)
                    CheckRow("Google / YouTube", cfg.enabledGoogle) { persist(cfg.copy(enabledGoogle = it)) }
                    CheckRow("Meta / Instagram / WhatsApp", cfg.enabledMeta) { persist(cfg.copy(enabledMeta = it)) }
                    CheckRow("Fastly / Reddit / GitHub assets", cfg.enabledFastly) { persist(cfg.copy(enabledFastly = it)) }
                    CheckRow("DNS providers", cfg.enabledDns) { persist(cfg.copy(enabledDns = it)) }
                    OutlinedTextField(
                        value = cfg.sniMeta, onValueChange = { persist(cfg.copy(sniMeta = it.trim())) },
                        label = { Text("SNI for Meta + DNS") }, modifier = Modifier.fillMaxWidth(),
                    )
                    OutlinedTextField(
                        value = cfg.sniFastly, onValueChange = { persist(cfg.copy(sniFastly = it.trim())) },
                        label = { Text("SNI for Fastly") }, modifier = Modifier.fillMaxWidth(),
                    )
                }
            }

            Card(modifier = Modifier.fillMaxWidth()) {
                Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("SNI tester", style = MaterialTheme.typography.titleSmall)
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                        Button(onClick = {
                            testing = true
                            testRes = ""
                            scope.launch(Dispatchers.IO) {
                                val pairs = listOf(
                                    cfg.frontDomain, cfg.sniMeta, cfg.sniFastly,
                                ).filter { it.isNotBlank() }.distinct()
                                val sb = StringBuilder()
                                for (s in pairs) {
                                    val r = try { Native.testSni(cfg.connectIp, s) } catch (t: Throwable) { "{\"ok\":false,\"error\":\"$t\"}" }
                                    sb.append(s).append(" → ").append(r).append("\n")
                                }
                                withContext(Dispatchers.Main) {
                                    testRes = sb.toString().trim()
                                    testing = false
                                }
                            }
                        }) { Text("Test all") }
                        if (testing) CircularProgressIndicator()
                    }
                    if (testRes.isNotEmpty()) Text(testRes, style = MaterialTheme.typography.bodySmall)
                }
            }

            if (stats.isNotEmpty()) {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(12.dp)) {
                        Text("Live stats", style = MaterialTheme.typography.titleSmall)
                        Text(stats, style = MaterialTheme.typography.bodySmall)
                    }
                }
            }

            if (logs.isNotEmpty()) {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(12.dp)) {
                        Text("Logs", style = MaterialTheme.typography.titleSmall)
                        Spacer(Modifier.height(4.dp))
                        Text(logs, style = MaterialTheme.typography.bodySmall)
                    }
                }
            }

            Text(
                "Fingerprint: " + try {
                    CaInstall.fingerprint(ctx)?.let { CaInstall.fingerprintHex(it) } ?: "(start once to create CA)"
                } catch (_: Throwable) { "(unavailable)" },
                style = MaterialTheme.typography.labelSmall,
            )
        }
    }
}

@Composable
private fun CheckRow(label: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
        Checkbox(checked = checked, onCheckedChange = onChange)
        Text(label, style = MaterialTheme.typography.bodyMedium)
    }
}
