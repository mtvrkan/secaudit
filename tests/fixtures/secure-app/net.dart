// SECURE COUNTERPART — SecAudit negative-control fixture. Not real code.
import 'dart:io';

// S58 — Certificate validation left to the platform (CWE-295 fixed): no override, so the
// system trust store decides, which is the only party that can.
HttpClient buildClient() {
  final client = HttpClient();
  client.connectionTimeout = const Duration(seconds: 10);
  return client;
}
