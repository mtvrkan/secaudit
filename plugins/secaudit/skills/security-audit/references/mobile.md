# P8 — Mobile application security (OWASP MASVS / Mobile Top 10 2024)

Applies to Android (Kotlin/Java), iOS (Swift/Obj-C), and cross-platform (Flutter/Dart,
React Native). Source review is always safe; dynamic testing needs a device/emulator you
own and authorization.

## OWASP Mobile Top 10 (2024) checklist

| # | Risk | Check |
|---|---|---|
| M1 | Improper Credential Usage | hardcoded creds/keys, credentials in shared prefs/plists |
| M2 | Inadequate Supply Chain Security | vulnerable SDKs/pods/gradle deps (feed P3) |
| M3 | Insecure Authentication/Authorization | client-side-only authz, weak biometric/session handling |
| M4 | Insufficient Input/Output Validation | injection into WebViews, deep links, IPC |
| M5 | Insecure Communication | no TLS, no cert pinning, cleartext traffic allowed |
| M6 | Inadequate Privacy Controls | excessive PII collection/logging, over-broad permissions |
| M7 | Insufficient Binary Protections | no obfuscation/anti-tamper for high-value apps (context-dependent) |
| M8 | Security Misconfiguration | debuggable builds, exported components, backup allowed |
| M9 | Insecure Data Storage | secrets in plaintext DB/prefs/files instead of Keystore/Keychain |
| M10 | Insufficient Cryptography | weak algorithms, hardcoded keys, ECB, weak randomness |

## Platform hotspots

**Android:**
- `AndroidManifest.xml`: `android:debuggable="true"`, `allowBackup="true"`,
  `usesCleartextTraffic="true"`, `exported="true"` components without permission,
  overbroad `<uses-permission>`, exported `content://` providers.
- Secrets in `strings.xml`/`BuildConfig`/`gradle.properties`; use Android Keystore.
- `WebView`: `setJavaScriptEnabled(true)` + `addJavascriptInterface` with untrusted
  content; `loadUrl` with user input.
- Deep links / intent filters without validation; implicit intents leaking data.
- Network Security Config: cleartext permitted, no cert pinning.

**iOS:**
- `Info.plist`: `NSAllowsArbitraryLoads` (ATS disabled), URL schemes without validation.
- Secrets in plist/`UserDefaults` instead of Keychain; `kSecAttrAccessible` too broad.
- `WKWebView` loading untrusted content / JS bridges.
- Pasteboard leakage, screenshot caching of sensitive screens.

**Flutter/Dart & RN:** secrets in Dart/JS bundle (easily extracted), missing cert
pinning, insecure `shared_preferences`/`AsyncStorage` for sensitive data, platform-channel
injection.

## IPC & inter-app attack surface

- **Exported components (Android):** `Activity`/`Service`/`BroadcastReceiver`/`ContentProvider`
  with `exported="true"` (or an intent-filter, which implies exported) callable by any app —
  test for privileged actions, SQL injection into a provider, or path traversal via
  `openFile`. `PendingIntent` without `FLAG_IMMUTABLE` → intent hijacking.
- **Deep-link / universal-link takeover:** unverified custom URL scheme (`myapp://`) any app
  can register; App Links / Universal Links without a valid `assetlinks.json` / AASA and
  domain verification → link hijack, OAuth-redirect theft. Validate host + path server-side.
- **Insecure IPC data:** trusting data received over intents/URL params without validation
  (feeds M4 injection into WebViews).

## Runtime hardening (context-dependent, M7)

- Root/jailbreak detection, anti-hooking, and cert-pinning that are trivially bypassed with
  **Frida/objection** — note whether high-value apps (banking/health) have layered, not
  single-point, defenses. Absence isn't always a finding; call it by app sensitivity.

## Dynamic testing (device/emulator you own + authorization)

- **Static triage:** `MobSF` (automated APK/IPA scan) as a first pass — treat output as leads.
- **Runtime:** `Frida` / `objection` for pinning/root-check bypass and method tracing; `adb`
  for exported-component probing; a proxy (Burp/mitmproxy) to confirm TLS/pinning and inspect
  API traffic. Decompile with `apktool`/`jadx` (Android) to read secrets/logic in the bundle.

## Deliverable

Findings mapped to M1–M10 + CWE, with the file/manifest line and fix (move to Keystore/
Keychain, enable ATS/cleartext=false, cert pinning, remove exported flag, verify deep-link
domains, `FLAG_IMMUTABLE` on PendingIntents, etc.).
