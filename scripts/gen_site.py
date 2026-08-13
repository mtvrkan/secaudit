#!/usr/bin/env python3
"""Render the landing page. Every number on it is computed from this repo, at build time.

    python3 scripts/gen_site.py            # write site/dist/
    python3 scripts/gen_site.py --check    # render, verify, discard (CI)

A marketing page is where a security tool is most tempted to round a number up, and the
temptation does not announce itself — someone edits prose six months after the measurement and
nobody notices the page now claims a recall the engine never had. So the template holds no
figures at all: it has `{{tokens}}`, and the values come from `eval/scorecard.json`, the
detector table, the compliance mapping and the gate list. `--check` fails if a token is
unsupplied, if a supplied token goes unused, or if a stat rendered onto the page disagrees with
its source.

Bilingual from one template rather than two files, because two files drift and the drift is
invisible until a Turkish reader is shown a number the English page corrected a year ago.
"""
from __future__ import annotations

import json
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SITE = os.path.join(REPO, "site")
DIST = os.path.join(SITE, "dist")
TEMPLATE = os.path.join(SITE, "template.html")

sys.path.insert(0, os.path.join(REPO, "kit"))
sys.path.insert(0, os.path.join(REPO, "scripts"))

ORIGIN = "https://secaudit.mtvrkan.com"
REPO_URL = "https://github.com/mtvrkan/secaudit"

_TOKEN = re.compile(r"\{\{(\w+)\}\}")


# --------------------------------------------------------------------------- facts

def facts() -> dict:
    """Everything the page is allowed to state, from the source of truth for each."""
    from check_consistency import derive_facts
    from secaudit_core import compliance
    from run_checks import GATES

    with open(os.path.join(REPO, "eval", "scorecard.json"), encoding="utf-8") as f:
        score = json.load(f)

    derived = derive_facts()
    overall = score["overall"]
    return {
        "recall": f"{overall['recall']:.0%}",
        "precision": f"{overall['precision']:.0%}",
        "f3": f"{overall['f3']:.3f}",
        "trap_fps": str(overall["fp"]),
        "traps_total": str(score["false_positive_traps"]),
        "golden": str(score["labelled_vulnerabilities"]),
        "misses": str(overall["fn"]),
        "detectors": str(derived["detectors"]),
        "references": str(derived["references"]),
        "commands": str(derived["commands"]),
        "gates": str(len(GATES)),
        "asvs_cwes": str(len(compliance.CWE_TO_ASVS)),
        "asvs_chapters": str(len(compliance.ASVS_CHAPTERS)),
        "cra_date": compliance.CRA_REPORTING_STARTS,
    }


# --------------------------------------------------------------------------- copy

# The capability comparison. Held here rather than in the template because each row is a
# factual claim about another product, and those belong somewhere a reviewer will look.
# Sourced from Anthropic's own documentation for the two official plugins; the "source code in
# your checkout, not a running site" limitation is quoted from it almost verbatim.
COMPARISON = [
    ("live_target", True, False),
    ("authorization", True, False),
    ("standalone", True, False),
    ("measured", True, False),
    ("compliance", True, False),
    ("mcp", True, False),
    ("in_session", False, True),
    ("patches", False, True),
]

COPY: dict[str, dict[str, str]] = {
    "en": {
        "lang": "en",
        "page_title": "SecAudit — the security audit you can hand to someone else",
        "page_description": "Open-source authorized security audit kit for Claude Code and CI. "
                            "Live-target and source audits, source-to-sink reachability, "
                            "OpenVEX dependency verdicts, EU CRA evidence packs, and a "
                            "published detection score you can reproduce.",
        "eyebrow": "Open source · MIT · Defensive use only",
        "headline": "The security audit you can hand to someone else.",
        "lede": "Claude Code's built-in tools secure the code Claude is writing. SecAudit "
                "answers a different question: is this product secure, can I prove it, and "
                "what do I owe a regulator? For a running target as well as a repository, "
                "with or without Claude Code, against a detection score anyone can reproduce.",
        "cta_repo": "View on GitHub",
        "cta_scorecard": "Read the scorecard",
        "cta_roadmap": "Read the roadmap",

        "measured_title": "Measured, not asserted",
        "measured_sub": "Tier 0 only — no LLM, no external scanners, no network. Scored against "
                        "{golden} labelled vulnerabilities and {traps_total} false-positive "
                        "traps, where every trap is a safe implementation of the same feature "
                        "as its vulnerable twin.",
        "label_recall": "recall",
        "label_precision": "precision (upper bound)",
        "label_f3": "F3 (recall-weighted)",
        "label_traps": "false positives on traps",
        "measured_caveat": "These fixtures were written alongside the detectors, so this is a "
                           "regression floor, not a forecast for your code. The comparison "
                           "that means something is an external corpus nobody here labelled — "
                           "the RealVuln runner ships in the repository and its result will be "
                           "published verbatim, whatever it is. It has not been run yet.",

        "diff_title": "How this differs from Claude Code's built-in security tools",
        "diff_sub": "Anthropic ships two official security plugins and they are good. Install "
                    "them. This table is about what they deliberately do not cover — not about "
                    "being better at what they do.",
        "col_capability": "Capability",
        "col_official": "Official plugins",
        "diff_note": "The security-guidance plugin reviews code as Claude writes it, and the "
                     "Claude Security plugin runs a multi-agent scan of a repository. Both read "
                     "source in your checkout. Neither reaches a deployed service, models an "
                     "authorization boundary for testing something you must prove you own, or "
                     "produces an artefact for an auditor. Run SecAudit alongside them.",

        "how_title": "What it actually does",
        "how_sub": "Four things a pattern scanner cannot do, each with the evidence attached.",

        "install_title": "Install",
        "install_sub": "As a Claude Code plugin:",
        "standalone_sub": "Or standalone — no Claude Code, no API key, no plan, zero runtime "
                          "dependencies. Runs in CI, in cron, on an air-gapped box:",

        "inside_title": "What is in the box",
        "inside_sub": "Every figure on this page is recomputed from the repository when the "
                      "page is built. A number typed into the template fails the build.",
        "label_detectors": "deterministic detectors",
        "label_golden": "labelled fixture flaws",
        "label_gates": "CI gates",
        "label_asvs": "CWEs mapped to ASVS 5.0",

        "footer_ethics": "Defensive use only. Audit what you own or are explicitly authorized "
                         "to test. SecAudit will not produce weaponized exploits, malware, DoS "
                         "payloads or detection-evasion tooling, and its active-testing gate is "
                         "a deterministic hook rather than model discretion.",
        "footer_meta": "MIT licensed. Not affiliated with Anthropic or OWASP.",
    },
    "tr": {
        "lang": "tr",
        "page_title": "SecAudit — başkasına teslim edebileceğin güvenlik denetimi",
        "page_description": "Claude Code ve CI için açık kaynak yetkili güvenlik denetim kiti. "
                            "Canlı hedef ve kaynak kodu denetimi, kaynak→sink erişilebilirlik "
                            "analizi, OpenVEX bağımlılık kararları, AB CRA kanıt paketleri ve "
                            "tekrar üretebileceğiniz yayınlanmış bir tespit skoru.",
        "eyebrow": "Açık kaynak · MIT · Yalnızca savunma amaçlı",
        "headline": "Başkasına teslim edebileceğin güvenlik denetimi.",
        "lede": "Claude Code'un yerleşik araçları, Claude'un yazdığı kodu güvence altına alır. "
                "SecAudit başka bir soruyu cevaplar: bu ürün güvenli mi, kanıtlayabilir miyim "
                "ve düzenleyiciye ne borçluyum? Repo kadar çalışan hedef için de, Claude Code "
                "ile veya onsuz, herkesin tekrar üretebileceği bir tespit skoruna karşı.",
        "cta_repo": "GitHub'da görüntüle",
        "cta_scorecard": "Skor kartını oku",
        "cta_roadmap": "Yol haritasını oku",

        "measured_title": "İddia değil, ölçüm",
        "measured_sub": "Yalnızca Tier 0 — LLM yok, dış tarayıcı yok, ağ yok. {golden} etiketli "
                        "açık ve {traps_total} yanlış-pozitif tuzağına karşı ölçüldü; her tuzak, "
                        "zafiyetli ikizinin aynı özelliğinin güvenli uygulaması.",
        "label_recall": "recall",
        "label_precision": "precision (üst sınır)",
        "label_f3": "F3 (recall ağırlıklı)",
        "label_traps": "tuzaklarda yanlış pozitif",
        "measured_caveat": "Bu fixture'lar detector'larla birlikte yazıldı; yani bu bir "
                           "regresyon tabanıdır, senin kodun için bir tahmin değil. Anlamlı "
                           "kıyas, buradan kimsenin etiketlemediği bir dış korpus — RealVuln "
                           "koşucusu repoda hazır ve sonucu ne çıkarsa olduğu gibi "
                           "yayınlanacak. Henüz çalıştırılmadı.",

        "diff_title": "Claude Code'un yerleşik güvenlik araçlarından farkı",
        "diff_sub": "Anthropic iki resmî güvenlik eklentisi yayınlıyor ve ikisi de iyi. Onları "
                    "kurun. Bu tablo, bilinçli olarak kapsamadıkları şeyler hakkında — "
                    "yaptıkları işi daha iyi yapmak hakkında değil.",
        "col_capability": "Yetenek",
        "col_official": "Resmî eklentiler",
        "diff_note": "security-guidance eklentisi Claude kod yazarken inceler; Claude Security "
                     "eklentisi bir repoda çok-ajanlı tarama yapar. İkisi de checkout'unuzdaki "
                     "kaynağı okur. Hiçbiri çalışan bir servise ulaşmaz, sahipliğini "
                     "kanıtlamanız gereken bir hedef için yetkilendirme sınırı modellemez, ya "
                     "da bir denetçiye sunulacak belge üretmez. SecAudit'i onların yanında "
                     "çalıştırın.",

        "how_title": "Gerçekte ne yapıyor",
        "how_sub": "Desen tarayıcısının yapamayacağı dört şey, her biri kanıtıyla birlikte.",

        "install_title": "Kurulum",
        "install_sub": "Claude Code eklentisi olarak:",
        "standalone_sub": "Ya da bağımsız — Claude Code yok, API anahtarı yok, plan yok, sıfır "
                          "çalışma zamanı bağımlılığı. CI'da, cron'da, ağdan yalıtılmış bir "
                          "makinede çalışır:",

        "inside_title": "Kutunun içinde ne var",
        "inside_sub": "Bu sayfadaki her rakam, sayfa derlenirken repodan yeniden hesaplanır. "
                      "Şablona elle yazılan bir sayı build'i kırar.",
        "label_detectors": "deterministik detector",
        "label_golden": "etiketli fixture açığı",
        "label_gates": "CI kapısı",
        "label_asvs": "ASVS 5.0'a eşlenmiş CWE",

        "footer_ethics": "Yalnızca savunma amaçlı. Sadece sahip olduğunuz veya test etmek için "
                         "açıkça yetkilendirildiğiniz sistemleri denetleyin. SecAudit "
                         "silahlandırılmış exploit, zararlı yazılım, DoS yükü veya tespit "
                         "atlatma aracı üretmez; aktif test kapısı model takdirine değil "
                         "deterministik bir hook'a dayanır.",
        "footer_meta": "MIT lisanslı. Anthropic veya OWASP ile bağlantılı değildir.",
    },
}

COMPARISON_LABELS = {
    "en": {
        "live_target": "Audit a running site or API",
        "authorization": "Authorization gate + scope file for active testing",
        "standalone": "Runs without Claude Code, without a paid plan, offline",
        "measured": "Published, reproducible detection score",
        "compliance": "SBOM, OpenVEX and EU CRA evidence pack",
        "mcp": "Same engine from Codex, Cursor, OpenCode (MCP server)",
        "in_session": "Reviews code as Claude writes it",
        "patches": "Generates reviewed patches",
    },
    "tr": {
        "live_target": "Çalışan bir siteyi veya API'yi denetleme",
        "authorization": "Aktif test için yetkilendirme kapısı + kapsam dosyası",
        "standalone": "Claude Code olmadan, ücretli plan olmadan, çevrimdışı çalışma",
        "measured": "Yayınlanmış, tekrar üretilebilir tespit skoru",
        "compliance": "SBOM, OpenVEX ve AB CRA kanıt paketi",
        "mcp": "Codex, Cursor, OpenCode'dan aynı motor (MCP sunucusu)",
        "in_session": "Claude kod yazarken inceleme",
        "patches": "İncelenmiş yama üretimi",
    },
}

FEATURES = {
    "en": [
        ("Reachability, not pattern matching",
         "A taint engine traces untrusted input from source to sink — across lines, and across "
         "function calls within a file. <code>db.query(sql)</code> is reported when "
         "<code>sql</code> was built from the request, and not when the value is bound as a "
         "query parameter. Every finding ships the path you can follow and refute."),
        ("Dependency advisories get a verdict",
         "Each CVE is classified by whether your code actually imports the package, into an "
         "OpenVEX status with the evidence for the call. Nothing is deleted — a filtered "
         "register is not evidence — but an advisory for a package you never load stops "
         "outranking one you do."),
        ("Compliance artefacts from the same scan",
         "A CycloneDX SBOM, an OpenVEX document, and a CRA evidence pack mapping each finding "
         "to the clause it bears on. Input to a compliance process, not a certificate, and the "
         "pack says so itself."),
        ("Safe by default, deterministically",
         "Passive recon needs no authorization. Active testing is blocked by a PreToolUse hook "
         "— a harness-level gate, not model discipline — until you assert ownership."),
    ],
    "tr": [
        ("Desen eşleme değil, erişilebilirlik",
         "Taint motoru güvenilmez girdiyi kaynaktan sink'e izler — satırlar arasında ve dosya "
         "içinde fonksiyon çağrıları boyunca. <code>db.query(sql)</code> ancak "
         "<code>sql</code> istekten üretildiyse raporlanır; değer bağlı parametre olarak "
         "geçtiğinde raporlanmaz. Her bulgu, takip edip çürütebileceğin yolu taşır."),
        ("Bağımlılık advisory'leri karar alır",
         "Her CVE, kodunuzun paketi gerçekten import edip etmediğine göre bir OpenVEX "
         "durumuna ve kararın gerekçesine bağlanır. Hiçbir şey silinmez — filtrelenmiş bir "
         "kayıt kanıt değildir — ama hiç yüklemediğiniz bir paketin advisory'si artık "
         "yüklediğinizinkinin önüne geçmez."),
        ("Aynı taramadan uyumluluk belgeleri",
         "CycloneDX SBOM, OpenVEX belgesi ve her bulguyu ilgili maddeye bağlayan CRA kanıt "
         "paketi. Uyumluluk sürecine girdidir, sertifika değildir — ve paket bunu kendisi "
         "söyler."),
        ("Varsayılan güvenli, deterministik olarak",
         "Pasif keşif yetkilendirme gerektirmez. Aktif test, siz sahipliği beyan edene kadar "
         "bir PreToolUse hook'u tarafından engellenir — model disiplini değil, harness "
         "seviyesinde bir kapı."),
    ],
}

INSTALL_PLUGIN = ("/plugin marketplace add mtvrkan/secaudit\n"
                  "/plugin install secaudit@secaudit-kit")
INSTALL_CLI = ("python3 -m secaudit_core.cli ./repo --min high\n"
               "python3 -m secaudit_core.cli ./repo --format sarif   # GitHub code scanning\n"
               "python3 -m secaudit_core.cli ./repo --format cra     # EU CRA evidence pack")


# --------------------------------------------------------------------------- render

def escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


# The site mark, inlined as a data URI so the page stays a single self-contained file — the
# property the whole template is built around, and one a separate favicon.ico would break for
# the sake of 500 bytes. URL-quoted at build time rather than hand-encoded, because a
# hand-encoded data URI is unreadable and therefore uneditable.
FAVICON_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">'
    '<path d="M16 2 4 7v9c0 7.5 5.1 12.6 12 14 6.9-1.4 12-6.5 12-14V7z" fill="#b34a1f"/>'
    '<path d="m10.5 16 4 4 7-8" fill="none" stroke="#fff" stroke-width="3.2" '
    'stroke-linecap="round" stroke-linejoin="round"/></svg>')


def favicon_href() -> str:
    from urllib.parse import quote
    return "data:image/svg+xml," + quote(FAVICON_SVG, safe="")


def build(lang: str, data: dict) -> str:
    copy = dict(COPY[lang])
    labels = COMPARISON_LABELS[lang]
    other = "tr" if lang == "en" else "en"

    rows = []
    for key, ours, theirs in COMPARISON:
        mark_ours = '<td class="yes">yes</td>' if ours else '<td class="no">—</td>'
        mark_them = '<td class="yes">yes</td>' if theirs else '<td class="no">—</td>'
        rows.append(f"<tr><td>{escape(labels[key])}</td>{mark_them}{mark_ours}</tr>")

    cards = "".join(
        f'<li class="card"><h3>{escape(title)}</h3><p>{body}</p></li>'
        for title, body in FEATURES[lang])

    canonical = f"{ORIGIN}/" if lang == "en" else f"{ORIGIN}/{lang}/"
    hreflang = (f'<link rel="alternate" hreflang="en" href="{ORIGIN}/">\n'
                f'<link rel="alternate" hreflang="tr" href="{ORIGIN}/tr/">\n'
                f'<link rel="alternate" hreflang="x-default" href="{ORIGIN}/">')
    other_href = f"{ORIGIN}/" if other == "en" else f"{ORIGIN}/{other}/"

    values = {
        **data,
        **copy,
        "canonical": canonical,
        # Absolute, because a relative `og:image` is ignored by every scraper. The template
        # declared `summary_large_image` and supplied no image at all, which asks for a big
        # preview card and gives it nothing to put in — a blank card, not an absent one.
        "og_image": f"{ORIGIN}/og.png",
        "og_alt": (f"SecAudit — {data['recall']} recall, F3 {data['f3']}, "
                   f"{data['gates']} CI gates"),
        "hreflang": hreflang,
        "lang_switch": f'<a href="{other_href}">{other.upper()}</a>',
        "repo": REPO_URL,
        "diff_rows": "".join(rows),
        "feature_cards": cards,
        "install_plugin": escape(INSTALL_PLUGIN),
        "install_cli": escape(INSTALL_CLI),
        "favicon": favicon_href(),
    }
    # Copy strings may themselves interpolate facts (counts inside a sentence).
    for key, value in list(values.items()):
        if isinstance(value, str) and "{" in value:
            values[key] = value.format(**data)

    with open(TEMPLATE, encoding="utf-8") as f:
        template = f.read()

    missing = sorted(set(_TOKEN.findall(template)) - set(values))
    if missing:
        raise SystemExit(f"gen-site: template uses undefined token(s): {missing}")
    unused = sorted(set(values) - set(_TOKEN.findall(template)) - set(data))
    if unused:
        raise SystemExit(f"gen-site: value(s) supplied but never rendered: {unused}")

    return _TOKEN.sub(lambda m: values[m.group(1)], template)


def verify(page: str, data: dict) -> list[str]:
    """Assert the page states the facts it was given, and no leftover tokens survived.

    Cheap, and it catches the one failure that matters: a stat block that renders a number the
    scorecard does not support, because someone edited the template instead of the source."""
    problems = []
    leftover = _TOKEN.findall(page)
    if leftover:
        problems.append(f"unresolved token(s) in output: {sorted(set(leftover))}")
    for key in ("recall", "precision", "f3", "trap_fps", "detectors", "gates", "asvs_cwes"):
        if f"<b>{data[key]}</b>" not in page:
            problems.append(f"stat `{key}` ({data[key]}) is not on the page — the template "
                            f"stopped rendering it, or renders something else")
    return problems


def main(argv: list[str]) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass

    data = facts()
    problems: list[str] = []
    pages = {}
    for lang in COPY:
        page = build(lang, data)
        pages[lang] = page
        problems += [f"[{lang}] {p}" for p in verify(page, data)]

    if problems:
        print("SITE CHECK FAILED:")
        print("\n".join("  - " + p for p in problems))
        return 1

    if "--check" in argv:
        print(f"Site renders cleanly in {len(pages)} language(s) — recall {data['recall']}, "
              f"F3 {data['f3']}, {data['detectors']} detectors, {data['gates']} gates, all "
              f"derived from the repo.")
        return 0

    os.makedirs(DIST, exist_ok=True)
    for lang, page in pages.items():
        out = os.path.join(DIST, "index.html") if lang == "en" else os.path.join(DIST, lang,
                                                                                "index.html")
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, "w", encoding="utf-8") as f:
            f.write(page)
    # A custom domain needs CNAME on the published branch, and it must agree with ORIGIN —
    # one produces the other, so they cannot disagree.
    with open(os.path.join(DIST, "CNAME"), "w", encoding="utf-8") as f:
        f.write(ORIGIN.split("//", 1)[1].rstrip("/") + "\n")
    # The card has to ship with the pages, or the meta tag points at a 404 — which renders as a
    # broken preview rather than as no preview at all.
    card = os.path.join(SITE, "og.png")
    if os.path.exists(card):
        with open(card, "rb") as src, open(os.path.join(DIST, "og.png"), "wb") as dst:
            dst.write(src.read())
    print(f"Wrote site/dist/ — {len(pages)} language(s), every figure derived from the repo.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
