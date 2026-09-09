package com.awminamani.mmdf

import android.app.Application
import android.util.Log

class MmdfApp : Application() {
    override fun onCreate() {
        super.onCreate()
        val prev = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { t, e ->
            try {
                Log.e("mmdf-crash", "uncaught on ${t.name}: ${e.message}", e)
            } catch (_: Throwable) { }
            prev?.uncaughtException(t, e)
        }
    }
}
