#!/usr/bin/env python3
"""Fetch the npm package versions SecBench.js labels, straight from the registry.

SecBench.js ships the *exploits* and the sink locations; the vulnerable code itself is the npm
package, at the pinned version, which the benchmark expects you to install. This script does that
without npm: the registry serves a tarball at a URL derived from the name and version, and the
standard library can fetch and unpack one. That keeps the reproduction step usable on a machine
with Python and nothing else — the same property `secaudit_core` itself holds.

    python3 eval/secbenchjs/fetch_packages.py --benchmark ../SecBench.js --out ../secbench-pkgs

Every extracted tree is `<out>/<class>/<name>_<version>/`, which is the directory the sink path
in `package.json` is relative to, so the scorer can join them without a second convention.

Tarball members are checked before extraction. A package is an archive from the internet, and
`tarfile` will happily write outside the destination if a member says to — the same containment
rule `diff.py` applies to its baselines, applied here for the same reason.
"""
from __future__ import annotations

import argparse
import io
import json
import os
import socket
import sys
import tarfile
import urllib.error
import urllib.request

REGISTRY = "https://registry.npmjs.org"
CLASSES = ("command-injection", "path-traversal", "prototype-pollution", "redos",
           "code-injection")
TIMEOUT = 60


def prefer_working_family(host: str, port: int = 443, probe_timeout: float = 3.0) -> str:
    """If the host resolves to an IPv6 address this machine cannot reach, stop offering it.

    Found the slow way, and worth the twenty lines because it is invisible otherwise: on a host
    that advertises AAAA records with no working IPv6 route, one 2.3 MB download took **181
    seconds** through `urllib` and **2.8 seconds** through `curl`. Nothing failed — `urllib` was
    waiting out a TCP timeout on the v6 address before falling back, once per connection, while
    curl was racing the two families the way browsers do. Six hundred packages at that rate is
    thirty hours instead of ten minutes.

    Rather than hard-coding IPv4 (which would be wrong on every machine where v6 works), probe
    once and only disable what is actually broken. Says which it chose, because a network
    decision made silently is one nobody can check.
    """
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    v6 = [i for i in infos if i[0] == socket.AF_INET6]
    if not v6 or not any(i[0] == socket.AF_INET for i in infos):
        return "as resolved (single family)"
    # Probe the v6 address *specifically*. `create_connection` without a family falls back to
    # IPv4 on its own and would report success for a route that does not exist — which is the
    # bug this function exists to detect, reproduced inside the detector.
    probe = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    probe.settimeout(probe_timeout)
    try:
        probe.connect(v6[0][4])
        return "dual stack, IPv6 reachable"
    except OSError:
        pass
    finally:
        probe.close()
    original = socket.getaddrinfo

    def ipv4_only(host_, port_, family=0, type=0, proto=0, flags=0):  # noqa: A002
        return original(host_, port_, socket.AF_INET, type, proto, flags)

    socket.getaddrinfo = ipv4_only
    return "IPv6 advertised but unreachable — using IPv4 for this run"


def pick_dependency(directory: str, deps: dict) -> tuple[str | None, str | None]:
    """Which of an entry's dependencies is the vulnerable one, and at which exact version.

    Both halves were wrong in the first version and the fetch said so: seven of eleven failures
    were this function's fault rather than npm's. Some entries pin a second package to run the
    exploit — `jison_0.4.17` also depends on `install-package`, and taking "the first" out of a
    dict fetched the helper at the victim's version number. And some pin a *range* (`^6.3.0`),
    which is not a version a tarball URL can name.

    The directory is the ground truth for both: SecBench.js names it `<package>_<version>`, so
    the package is the part before the last underscore and the version is the part after. The
    dependency map is used only to confirm the name, never to choose it.
    """
    if "_" not in directory:
        return None, None
    name, _, version = directory.rpartition("_")
    name = name.replace("__", "/")           # `@scope/name` is written `@scope__name` on disk
    if deps and name not in deps:
        # A name that is not in the entry's own dependency list means the convention changed;
        # say nothing rather than fetch something arbitrary.
        for candidate in deps:
            if candidate.split("/")[-1] == name.split("/")[-1]:
                name = candidate
                break
        else:
            return None, None
    if not version or not version[0].isdigit():
        return None, None
    return name, version


def entries(benchmark: str) -> list[dict]:
    """Every labelled vulnerability, as {class, dir, package, version, sink}."""
    out = []
    for cls in CLASSES:
        root = os.path.join(benchmark, cls)
        if not os.path.isdir(root):
            continue
        for name in sorted(os.listdir(root)):
            meta = os.path.join(root, name, "package.json")
            if not os.path.exists(meta):
                continue
            with open(meta, encoding="utf-8") as fh:
                data = json.load(fh)
            deps = data.get("dependencies") or {}
            pkg, version = pick_dependency(name, deps)
            out.append({"class": cls, "dir": name, "package": pkg, "version": version,
                        "sink": (data.get("sink") or "").strip(),
                        "id": data.get("id") or ""})
    return out


def tarball_url(package: str, version: str) -> str:
    # Scoped packages (`@scope/name`) live under the scope but the file is named after the tail.
    tail = package.split("/")[-1]
    return f"{REGISTRY}/{package}/-/{tail}-{version}.tgz"


def safe_extract(tar: tarfile.TarFile, dest: str) -> int:
    """Extract, refusing any member that would land outside `dest`."""
    dest_real = os.path.realpath(dest)
    written = 0
    for member in tar.getmembers():
        if not (member.isfile() or member.isdir()):
            continue  # no symlinks, devices or hard links out of an untrusted archive
        # npm tarballs put everything under `package/`; strip it so the sink path joins cleanly.
        rel = member.name.split("/", 1)[1] if "/" in member.name else member.name
        if not rel:
            continue
        target = os.path.realpath(os.path.join(dest_real, rel))
        if target != dest_real and not target.startswith(dest_real + os.sep):
            raise ValueError(f"tar member escapes the destination: {member.name}")
        if member.isdir():
            os.makedirs(target, exist_ok=True)
            continue
        os.makedirs(os.path.dirname(target), exist_ok=True)
        src = tar.extractfile(member)
        if src is None:
            continue
        with open(target, "wb") as fh:
            fh.write(src.read())
        written += 1
    return written


def fetch(entry: dict, out_root: str) -> tuple[str, str]:
    """(status, detail). Status is one of ok / cached / skipped / failed."""
    dest = os.path.join(out_root, entry["class"], entry["dir"])
    if os.path.isdir(dest) and os.listdir(dest):
        return "cached", dest
    if not entry["package"] or not entry["version"]:
        return "skipped", "no package/version in the entry"
    url = tarball_url(entry["package"], entry["version"])
    try:
        with urllib.request.urlopen(url, timeout=TIMEOUT) as resp:
            blob = resp.read()
    except (urllib.error.URLError, OSError) as exc:
        return "failed", f"{url}: {exc}"
    os.makedirs(dest, exist_ok=True)
    try:
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tar:
            safe_extract(tar, dest)
    except (tarfile.TarError, ValueError) as exc:
        return "failed", f"{url}: {exc}"
    return "ok", dest


def main(argv: list[str]) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--benchmark", required=True, help="path to a SecBench.js checkout")
    ap.add_argument("--out", required=True, help="where to extract the packages")
    args = ap.parse_args(argv)

    print("Network: " + prefer_working_family("registry.npmjs.org"))
    found = entries(os.path.abspath(args.benchmark))
    if not found:
        print(f"No entries under {args.benchmark} — is that a SecBench.js checkout?")
        return 1
    out_root = os.path.abspath(args.out)
    counts = {"ok": 0, "cached": 0, "skipped": 0, "failed": 0}
    failures = []
    for i, entry in enumerate(found, 1):
        status, detail = fetch(entry, out_root)
        counts[status] += 1
        if status == "failed":
            failures.append((entry["dir"], detail))
        if i % 50 == 0 or i == len(found):
            print(f"  {i}/{len(found)} — " + ", ".join(f"{k} {v}" for k, v in counts.items()))

    manifest = os.path.join(out_root, "entries.json")
    os.makedirs(out_root, exist_ok=True)
    with open(manifest, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(found, fh, indent=1, ensure_ascii=False)
        fh.write("\n")
    print(f"\nWrote {manifest} — {len(found)} labelled entries.")
    if failures:
        print(f"{len(failures)} package(s) could not be fetched; the scorer counts their labels "
              f"as unreachable rather than as missed:")
        for name, detail in failures[:10]:
            print(f"  - {name}: {detail}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
