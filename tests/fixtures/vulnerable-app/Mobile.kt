// INTENTIONALLY VULNERABLE — SecAudit test fixture. Not real code. Do not deploy.
package com.example.app

import android.content.Context
import android.webkit.WebView

class Screen(private val context: Context) {

    // V55 — WebView JavaScript bridge (CWE-749): remote content can call into the app's own
    // Kotlin objects, which is remote code execution against the app's permissions.
    fun setup(web: WebView) {
        web.addJavascriptInterface(Bridge(), "android")
        // V56 — JavaScript enabled for untrusted content (CWE-749).
        web.settings.setJavaScriptEnabled(true)
    }

    // V57 — World-readable file mode (CWE-732): any app on the device can read the token.
    fun save(token: String) {
        context.openFileOutput("session", Context.MODE_WORLD_READABLE).use {
            it.write(token.toByteArray())
        }
    }

    class Bridge
}
