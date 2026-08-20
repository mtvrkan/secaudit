// INTENTIONALLY VULNERABLE — SecAudit test fixture. Not real code. Do not deploy.
import 'dart:io';

// V58 — Every TLS certificate accepted (CWE-295): the callback returns true unconditionally,
// which turns HTTPS into transport with no authentication.
HttpClient buildClient() {
  final client = HttpClient();
  client.badCertificateCallback = (cert, host, port) => true;
  return client;
}
