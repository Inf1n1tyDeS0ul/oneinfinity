package com.oneinfinity.companion.utils

import android.util.Log
import java.io.File

/**
 * Root Detection Utility
 *
 * Checks if device is rooted (required for Frida integration)
 */
object RootChecker {
    private const val TAG = "RootChecker"

    fun isRooted(): Boolean {
        return checkSuBinary() || checkRootFiles() || checkSuExec()
    }

    private fun checkSuBinary(): Boolean {
        val paths = arrayOf(
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/su",
            "/su/bin/su"
        )

        for (path in paths) {
            if (File(path).exists()) {
                Log.d(TAG, "Found su binary at: $path")
                return true
            }
        }
        return false
    }

    private fun checkRootFiles(): Boolean {
        val files = arrayOf(
            "/system/app/Superuser.apk",
            "/system/xbin/daemonsu",
            "/system/etc/init.d/99SuperSUDaemon"
        )

        for (file in files) {
            if (File(file).exists()) {
                Log.d(TAG, "Found root file: $file")
                return true
            }
        }
        return false
    }

    private fun checkSuExec(): Boolean {
        return try {
            val process = Runtime.getRuntime().exec("su -c exit")
            val exitValue = process.waitFor()
            exitValue == 0
        } catch (e: Exception) {
            false
        }
    }
}
