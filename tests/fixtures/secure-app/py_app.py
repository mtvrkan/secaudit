# SECURE COUNTERPART — negative-control fixture. Safe implementations of the Python
# vulnerability classes planted (vulnerably) in vulnerable-app/py_app.py (S17–S20 ↔ V17–V20).
# A correct audit reports nothing critical here. Never executed by the self-test.
import json
import re
import subprocess

import requests
from flask import request
from lxml import etree


# S17 — XXE fixed (CWE-611): external-entity resolution, network access, and DTD loading are
# all disabled, so untrusted XML cannot read local files or trigger SSRF.
def parse_xml(xml_data):
    parser = etree.XMLParser(resolve_entities=False, no_network=True,
                             load_dtd=False, dtd_validation=False)
    return etree.fromstring(xml_data, parser)


# S18 — TLS verification kept ON (CWE-295 fixed): certificates are validated (the default),
# stated explicitly for clarity.
def fetch_secure(url):
    return requests.get(url, verify=True, timeout=5)


# S19 — OS command injection fixed (CWE-78): no shell, an argument list, and validated input.
_HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")


def run_ping(host):
    if not _HOST_RE.match(host):
        raise ValueError("invalid host")
    return subprocess.call(["ping", "-c", "1", "--", host])  # arg list, shell defaults off


# S20 — Safe deserialization (CWE-502 fixed): JSON, never pickle — only data comes out.
def load_session(cookie):
    return json.loads(cookie)


# S21 — SQL injection across a function boundary fixed (CWE-89): the untrusted value still
# crosses from the handler into the helper, so a reachability analysis must still follow it —
# it simply arrives as a BOUND PARAMETER rather than as part of the query string. This is the
# trap for an analysis that reports any tainted value reaching `execute()`.
def list_users(cursor):
    return find_by_name(cursor, request.args["name"])


def find_by_name(cursor, name):
    return cursor.execute("SELECT * FROM users WHERE name = ?", (name,))
