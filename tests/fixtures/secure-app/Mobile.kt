// SECURE COUNTERPART — SecAudit negative-control fixture. Not real code.
package com.example.app

import android.content.Context
import android.webkit.WebView

class Screen(private val context: Context) {

    // S55 — No JavaScript bridge (CWE-749 fixed): nothing is exposed to page script, so
    // remote content has no handle on the app's own objects.
    // S56 — Scripting off (CWE-749 fixed): the view renders trusted, bundled content only.
    fun setup(web: WebView) {
        web.settings.javaScriptEnabled = false
        web.loadUrl("file:///android_asset/help.html")
    }

    // S57 — Private file mode (CWE-732 fixed): readable only by this app's uid. Sharing, when
    // it is needed, goes through a FileProvider with a grant per recipient.
    fun save(token: String) {
        context.openFileOutput("session", Context.MODE_PRIVATE).use {
            it.write(token.toByteArray())
        }
    }
}
