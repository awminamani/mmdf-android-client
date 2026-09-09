package com.awminamani.mmdf

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/** Process-wide "is the VPN/proxy up?" flag + native handle for stats. */
object VpnState {
    private val _isRunning = MutableStateFlow(false)
    val isRunning: StateFlow<Boolean> = _isRunning.asStateFlow()

    private val _proxyHandle = MutableStateFlow(0L)
    val proxyHandle: StateFlow<Long> = _proxyHandle.asStateFlow()

    fun setRunning(r: Boolean) { _isRunning.value = r }
    fun setProxyHandle(h: Long) { _proxyHandle.value = h }
}
