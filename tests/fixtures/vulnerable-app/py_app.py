# INTENTIONALLY VULNERABLE — SecAudit test fixture. Not real code. Do not deploy.
# Python-idiom vulnerability classes, planted for the golden-set eval so the fixture
# proves cross-language (not just JS) static coverage. Each block is a distinct, labeled
# sink, detectable by static review — the module is never executed by the self-test.
import base64
import pickle
import subprocess

import requests
from lxml import etree


# V17 — XXE / XML external entities (CWE-611): parser resolves external entities on
# untrusted XML → SSRF / local-file read via `file://` or a remote DTD.
def parse_xml(xml_data):
    parser = etree.XMLParser(resolve_entities=True, no_network=False)  # UNSAFE
    return etree.fromstring(xml_data, parser)


# V18 — Disabled TLS certificate verification (CWE-295): turns off cert validation, so a
# network MITM can intercept/alter the "secure" fetch and steal anything sent with it.
def fetch_secure(url):
    return requests.get(url, verify=False, timeout=5)  # UNSAFE: verify=False


# V19 — OS command injection (CWE-78): user input concatenated into a shell command.
# The Python-idiom sibling of the JS `/ping` sink (V2).
def run_ping(host):
    return subprocess.call('ping -c 1 ' + host, shell=True)  # UNSAFE: shell=True + concat


# V20 — Insecure deserialization (CWE-502): `pickle.loads` on attacker-controlled bytes
# runs arbitrary code via `__reduce__`. The Python-idiom sibling of the JS `eval` sink (V15).
def load_session(cookie):
    return pickle.loads(base64.b64decode(cookie))  # UNSAFE: never unpickle untrusted data
