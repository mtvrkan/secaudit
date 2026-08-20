"""The landing page's words, and the 404's.

Split out of `gen_site.py` when that file passed 2,700 lines and the roadmap still listed four
more pages, each worth roughly 350 lines of the same. The generator keeps the logic — the readers
that pull every figure out of the repository, the renderer and the verifier — and the words live
here. Nothing was rewritten in the move: `site/dist` is byte-identical before and after, which is
the only assertion that makes a refactor of a generator safe.
"""

# --------------------------------------------------------------------------- copy

COPY: dict[str, dict[str, str]] = {
    "en": {
        "lang": "en",
        "page_title": "SecAudit — authorized security audit for code and CI",
        "page_description": "Open-source security audit kit for Claude Code and CI: source and "
                            "live-target scans, reachability analysis, CRA evidence packs, "
                            "a published detection score.",
        "eyebrow": "Open source · MIT · Defensive use only",
        # Verb first, and the two shortest sentences on the site. The pair this replaced —
        # "The security audit / you can hand over." — named a property of the output and never
        # the thing itself, so a reader four seconds in knew it was security-adjacent and
        # nothing more.
        "headline_1": "Finds the flaw.",
        "headline_2": "Shows the proof.",
        "lede": "SecAudit audits a source repository, and a running target where ownership has "
                "been asserted. Every finding carries its file, its line, and the path from "
                "untrusted input to the dangerous call.",
        "cta_repo": "View on GitHub",
        "nav_label": "Sections",
        "lang_label": "Language",
        "totop_label": "Back to top",
        "skip_label": "Skip to content",
        "cta_secondary": "External measurement",
        "cta_docs": "Getting started",
        "cta_note": "Available as a Claude Code plugin or as a standalone tool. No API key, no "
                    "paid plan, no network access, zero runtime dependencies.",
        "cta_title": "Run the audit before it is requested.",
        "cta_body": "SecAudit scans a repository, or a running target under declared ownership. "
                    "The deterministic tier requires only Python, and it reports the limits of "
                    "its own coverage.",

        "demo_head": "one finding, in full",
        "chip_proof": "reachable · refutable",
        "demo_foot": "The CWE, the two lines the finding spans, and the argument that carried "
                     "the value, printed as the tool prints them. A pattern matcher flags line "
                     "13 on sight; this engine reports it because line 12 reaches it, and "
                     "publishes the path behind the verdict.",

        "numbers_kicker": "Detection rate",
        "numbers_title": "Detection rate, measured on two corpora.",
        "numbers_sub": "Recall is the share of existing vulnerabilities found. Precision is the "
                       "share of reported findings that are real. F3 combines the two and "
                       "weights recall nine times heavier, on the basis that a missed "
                       "vulnerability costs more than a false alarm. All figures are Tier 0: no "
                       "LLM, no external scanners, no network. The external result on the left "
                       "is the material one — a third-party corpus, third-party labels and a "
                       "third-party scorer.",
        "external_title": "RealVuln — external corpus, Python",
        "external_why": "{rv_repos} of {rv_repos_total} real vulnerable repositories, labelled "
                        "independently of this project and scored by the benchmark's own "
                        "scorer. {rv_sast_name}, the published rule-based baseline, scores "
                        "{rv_pct_sast_f3} on the same corpus. This corpus is Python; the "
                        "JavaScript side is measured separately against {sb_labels} labelled "
                        "sinks in real npm packages and finds {sb_pct_recall} of them.",
        "own_title": "Internal fixtures — regression floor",
        "own_why": "{golden} labelled flaws and {traps_total} false-positive traps, each trap a "
                   "safe implementation of the feature its vulnerable twin implements. These "
                   "figures establish that the engine still works. They are not a prediction "
                   "for any other codebase.",
        "label_rv_f3": "F3 (recall × 9)",
        "label_rv_recall": "recall",
        "label_rv_repos": "of {rv_repos_total} repos",
        "label_recall": "recall",
        "label_precision": "precision",
        "label_own_precision": "precision (upper bound)",
        "label_f3": "F3 (recall-weighted)",
        "label_traps": "false positives on traps",
        "numbers_caveat": "The same scorer reports a stricter reading of the same run at F3 "
                          "{rv_pct_strict_f3}. That is the figure to cite for any purpose other "
                          "than comparison against the benchmark's own baselines. Raw scorer "
                          "output is committed to the repository, and CI fails when a figure on "
                          "this page no longer matches it.",

        "runs_kicker": "Disclosure",
        "runs_tag": "read before citing the figure",
        "runs_title": "The score is no longer blind, and that qualifies it.",
        "runs_sub": "{rv_runs} runs on a single corpus. In the first, the engine had not seen "
                    "the corpus. In the runs since, the rules added were selected by reading "
                    "this benchmark's own false negatives.",
        "runs_caveat": "Every rule added is of a kind any SAST ships, so no rule is fitted to a "
                       "fixture. The selection, however, was corpus-informed: the gap between "
                       "{rv_blind_f3} and {rv_f3} is the size of that advantage. "
                       "{rv_blind_f3} is the conservative figure for an unseen codebase. The "
                       "honest successor to this measurement is a benchmark this repository has "
                       "not read.",
        "runs_more": "All {rv_runs} runs and the cost of each",
        "nx_bench_kicker": "External measurement",
        "nx_bench_meta": "{rv_runs} runs · {rv_repos} repositories · {rv_labels} labels",

        "gate_kicker": "Authorization",
        "gate_title": "Active testing requires an asserted authorization.",
        "gate_body": "SecAudit audits a running target as well as a checkout, and that "
                     "capability is gated. Passive reconnaissance requires no permission. "
                     "Active testing against a live target is refused by a deterministic "
                     "PreToolUse hook before the command executes, rather than by instructing a "
                     "model. Once ownership is asserted, the same command proceeds. A committed "
                     "scope file does not qualify: it arrives with the clone and is not an "
                     "assertion made by the operator.",
        "gate_head": "active-scan-guard",
        "gate_blocked": "active-scanning tool `nuclei`; no authorization has been asserted for "
                        "this session.",
        "gate_allowed": "SECAUDIT_ACTIVE=1, or an untracked scope.yaml written by the operator.",
        "gate_foot": "18 active patterns blocked and 12 passive patterns allowed, asserted by "
                     "the hook's own self-test on every build, on Linux and on Windows.",

        "lang_kicker": "Coverage",
        "lang_title": "Fifteen languages, with recall reported for each.",
        "lang_body": "Every language in the fixture corpus has a paired vulnerable and safe "
                     "implementation. The figures below are what the deterministic tier scores "
                     "on each, including the languages that fall short of full marks.",
        "lang_foot": "Recall on the shipped fixtures, which were written alongside the "
                     "detectors. Depth varies by language: Python and JS/TS receive taint "
                     "analysis and the structural passes; the remainder receive the pattern "
                     "pack. The per-language matrix in the repository is generated from the "
                     "code.",

        "comp_kicker": "Evidence",
        "comp_title": "The documents an auditor requests, produced by the same scan.",
        "comp_body": "A single run produces an inventory of shipped components, a verdict on "
                     "each dependency advisory, and a mapping from every finding to the clause "
                     "it bears on. Vulnerability-handling obligations under the EU Cyber "
                     "Resilience Act take effect on {cra_date}. Findings additionally carry an "
                     "OWASP ASVS 5.0 chapter and, where the requirement text supports it, a PCI "
                     "DSS 4.0.1 requirement.",
        "comp_foot": "The pack is an input to a compliance process, not a certificate, and "
                     "states this in its own disclaimer. Requirements that cannot be asserted "
                     "from a source scan are listed as refused, with the reason.",

        # The surfaces grid used to live here as its own section and is now the install page's
        # hero: a reader was shown the same six cards twice, once on the way to the page that
        # opens with them. `{surfaces}` rather than the word — this line said "six" while the
        # number of surfaces was a list in this file that nothing held it to.
        "where_more": "All {surfaces} deployment surfaces",
        "nx_install_kicker": "Installation",
        "nx_install_meta": "{commands} commands · {mcp_tools} MCP tools · {runtime_deps} dependencies",

        "miss_kicker": "Limitations",
        "miss_title": "What the engine misses, generated from the engine.",
        "miss_body": "A hand-maintained limitations page is accurate for one release and "
                     "understates thereafter. This one is produced from the detector table and "
                     "the measured misses, so it cannot fall behind the code.",
        "miss_foot": "A clean report is not an all-clear until the full limitations page has "
                     "been read. Every report the tool writes states its own bounds: a scan "
                     "that could not reach something records that rather than omitting it.",

        "what_kicker": "What it does",
        "what_title": "A single command scans the code and reports what it finds.",
        "what_sub": "Three stages, none of which requires an account, a network connection or a "
                    "model.",

        "install_kicker": "Installation",
        "install_title": "Two lines in Claude Code, or a single pip install.",
        "install_sub": "The two most commonly used. There are {surfaces} in total: the MCP "
                       "server, the GitHub Action, the container image and the pre-commit hooks "
                       "are the remaining four. All run the same engine, and none is a reduced "
                       "version of another.",
        "install_plugin_sub": "As a Claude Code plugin:",
        "standalone_sub": "Standalone — no Claude Code, no API key, no plan, zero runtime "
                          "dependencies. Runs in CI, under cron, and on an air-gapped host:",
        "label_detectors": "deterministic detectors",
        "label_golden": "labelled fixture flaws",
        "label_gates": "CI gates",
        "label_asvs": "CWEs mapped to ASVS 5.0",

    },
    "tr": {
        "lang": "tr",
        "page_title": "SecAudit — kod ve CI için yetkilendirmeli güvenlik denetimi",
        "page_description": "Claude Code ve CI için açık kaynak güvenlik denetim kiti: kaynak "
                            "ve canlı hedef taraması, erişilebilirlik analizi, CRA kanıt "
                            "paketi, yayımlanmış tespit skoru.",
        "eyebrow": "Açık kaynak · MIT · Yalnızca savunma amaçlı",
        # Türkçede niteleyici cümlecik başa, vurgu sona düşer, o yüzden İngilizcedeki bölünme
        # birebir taşınmıyor. İki kısa cümle olarak kuruldu; ikinci satır kod yüzünde diziliyor.
        "headline_1": "Açığı bulur.",
        "headline_2": "Kanıtını gösterir.",
        "lede": "SecAudit bir kaynak kodu deposunu, sahiplik beyan edilmişse çalışan bir hedefi "
                "de denetler. Her bulgu; dosyası, satırı ve güvenilmez girdiden tehlikeli "
                "çağrıya giden yolu ile birlikte raporlanır.",
        "cta_repo": "GitHub'da görüntüle",
        "nav_label": "Bölümler",
        "lang_label": "Dil",
        "totop_label": "Başa dön",
        "skip_label": "İçeriğe geç",
        "cta_secondary": "Dış ölçüm sonucu",
        "cta_docs": "Başlangıç kılavuzu",
        "cta_note": "Claude Code eklentisi olarak ya da bağımsız araç olarak kullanılır. API "
                    "anahtarı, ücretli plan ve ağ erişimi gerektirmez; çalışma zamanı "
                    "bağımlılığı bulunmaz.",
        "cta_title": "Denetimi, istenmeden önce tamamlayın.",
        "cta_body": "SecAudit bir depoyu ya da sahipliği beyan edilmiş çalışan bir hedefi "
                    "tarar. Deterministik katman yalnızca Python gerektirir ve kendi kapsam "
                    "sınırlarını raporlar.",

        "demo_head": "tek bir bulgu, tam hâliyle",
        "chip_proof": "erişilebilir · çürütülebilir",
        "demo_foot": "CWE, bulgunun kapsadığı iki satır ve değeri taşıyan argüman — aracın "
                     "yazdığı biçimiyle. Bir desen eşleyici 13. satırı görür görmez işaretler; "
                     "bu çekirdek onu 12. satır oraya ulaştığı için raporlar ve kararın arkasındaki "
                     "yolu da yayımlar.",

        "numbers_kicker": "Tespit oranı",
        "numbers_title": "Tespit oranı, iki ayrı veri kümesinde ölçüldü.",
        "numbers_sub": "Recall, var olan zafiyetlerin bulunan oranıdır. Precision, raporlanan "
                       "bulguların gerçek olan oranıdır. F3 ikisini birleştirir ve recall'a "
                       "dokuz kat ağırlık verir; kaçırılan bir zafiyetin maliyeti yanlış "
                       "alarmdan yüksektir. Tüm rakamlar Tier 0'dır: LLM, dış tarayıcı ve ağ "
                       "kullanılmaz. Esas alınması gereken, soldaki dış sonuçtur — üçüncü tarafa "
                       "ait veri kümesi, üçüncü tarafa ait etiketler, üçüncü tarafa ait puanlayıcı.",
        "external_title": "RealVuln — dış veri kümesi, Python",
        "external_why": "{rv_repos_total} gerçek zafiyetli deponun {rv_repos} tanesi. Etiketleme "
                        "bu projeden bağımsız yapıldı, puanlama kıyaslamanın kendi "
                        "puanlayıcısıyla gerçekleşti. Yayımlanmış kural tabanlı referans "
                        "{rv_sast_name}, aynı veri kümesinde {rv_pct_sast_f3} alıyor. Bu veri kümesi "
                        "Python; JavaScript tarafı ayrıca gerçek npm paketlerindeki "
                        "{sb_labels} etiketli sink üzerinde ölçülüyor ve bunların "
                        "{sb_pct_recall} kadarını buluyor.",
        "own_title": "İç fixture'lar — regresyon tabanı",
        "own_why": "{golden} etiketli açık ve {traps_total} yanlış pozitif tuzağı; her tuzak, "
                   "zafiyetli ikizindeki işlevin güvenli uygulamasıdır. Bu rakamlar çekirdeğin "
                   "çalışmaya devam ettiğini gösterir; başka bir kod tabanı için öngörü "
                   "niteliği taşımaz.",
        "label_rv_f3": "F3 (recall × 9)",
        "label_rv_recall": "recall",
        "label_rv_repos": "/ {rv_repos_total} depo",
        "label_recall": "recall",
        "label_precision": "precision",
        "label_own_precision": "precision (üst sınır)",
        "label_f3": "F3 (recall ağırlıklı)",
        "label_traps": "tuzaklarda yanlış pozitif",
        "numbers_caveat": "Aynı puanlayıcı, aynı koşunun daha katı okumasını F3 "
                          "{rv_pct_strict_f3} olarak raporlar. Kıyaslamanın kendi "
                          "referanslarıyla karşılaştırma "
                          "dışındaki her amaç için bu rakam kullanılmalıdır. Ham puanlayıcı "
                          "çıktısı depoda bulunur; bu sayfadaki bir rakam çıktıyla örtüşmeyi "
                          "bıraktığında CI başarısız olur.",

        "runs_kicker": "Açık beyan",
        "runs_tag": "rakamı aktarmadan önce okuyun",
        "runs_title": "Skor artık körlemesine alınmıyor; bu, rakamı niteler.",
        "runs_sub": "Tek veri kümesi üzerinde {rv_runs} koşu. İlk koşuda çekirdek bu veri kümesini görmemişti. "
                    "Sonraki koşularda eklenen kurallar, kıyaslamanın kendi kaçırdığı bulgular "
                    "okunarak seçildi.",
        "runs_caveat": "Eklenen kuralların tamamı, herhangi bir SAST aracının içerdiği "
                       "türdendir; hiçbiri tek bir fixture'a göre uyarlanmamıştır. Ancak seçim "
                       "veri kümesine bakılarak yapılmıştır: {rv_blind_f3} ile {rv_f3} arasındaki fark "
                       "bu avantajın büyüklüğüdür. Görülmemiş bir kod tabanı için temkinli rakam "
                       "{rv_blind_f3}'tir. Bu ölçümün dürüst devamı, bu deponun hiç okumadığı "
                       "yeni bir kıyaslamadır.",
        "runs_more": "{rv_runs} koşunun tamamı ve her birinin maliyeti",
        "nx_bench_kicker": "Dış ölçüm",
        "nx_bench_meta": "{rv_runs} koşu · {rv_repos} depo · {rv_labels} etiket",

        "gate_kicker": "Yetkilendirme",
        "gate_title": "Aktif test, beyan edilmiş bir yetkilendirme gerektirir.",
        "gate_body": "SecAudit bir checkout'un yanı sıra çalışan bir hedefi de denetler; kapı "
                     "altına alınan yetenek budur. Pasif keşif izin gerektirmez. Canlı bir "
                     "hedefe yönelik aktif test, komut çalıştırılmadan önce deterministik bir "
                     "PreToolUse hook'u tarafından reddedilir; bu, modele verilmiş bir talimat "
                     "değildir. Sahiplik beyan edildiğinde aynı komut çalışır. Depoya "
                     "commit'lenmiş bir kapsam dosyası geçerli sayılmaz: bu dosya clone ile "
                     "birlikte gelir ve operatörün yaptığı bir beyan değildir.",
        "gate_head": "active-scan-guard",
        "gate_blocked": "aktif tarama aracı `nuclei`; bu oturum için beyan edilmiş bir yetki "
                        "bulunmuyor.",
        "gate_allowed": "SECAUDIT_ACTIVE=1 ya da operatörün kendi yazdığı, sürüm kontrolüne "
                        "alınmamış bir scope.yaml.",
        "gate_foot": "18 aktif desen engellendi, 12 pasif desene izin verildi; bu, her build'de "
                     "hook'un kendi self-test'iyle doğrulanır — Linux ve Windows üzerinde.",

        "lang_kicker": "Kapsam",
        "lang_title": "On beş dil, her biri için raporlanan recall.",
        "lang_body": "Fixture veri kümesindeki her dilin eşleştirilmiş zafiyetli ve güvenli birer "
                     "uygulaması vardır. Aşağıdaki rakamlar, deterministik katmanın her dilde "
                     "aldığı skordur; tam not almayan diller de listededir.",
        "lang_foot": "Değerler, detector'larla birlikte yazılmış fixture'lar üzerinde "
                     "ölçülmüştür. Derinlik dile göre değişir: Python ve JS/TS taint analizi ile "
                     "yapısal geçişleri, diğerleri desen paketini alır. Depodaki dil matrisi "
                     "koddan üretilir.",

        "comp_kicker": "Kanıt",
        "comp_title": "Denetçinin talep ettiği belgeler, aynı taramadan üretilir.",
        "comp_body": "Tek bir koşu; dağıtılan bileşenlerin envanterini, her bağımlılık "
                     "advisory'si için bir kararı ve her bulgunun ilgili maddeye eşlenmesini "
                     "üretir. AB Siber Dayanıklılık Yasası'nın zafiyet yönetimi yükümlülükleri "
                     "{cra_date} tarihinde yürürlüğe girer. Bulgular ayrıca bir OWASP ASVS 5.0 "
                     "bölümü ve — gereksinim metni destekliyorsa — bir PCI DSS 4.0.1 maddesi "
                     "taşır.",
        "comp_foot": "Paket, uyumluluk sürecine girdidir; sertifika değildir ve bunu kendi "
                     "çekince notunda belirtir. Kaynak taramasından beyan edilemeyen "
                     "gereksinimler, gerekçesiyle birlikte reddedilmiş olarak listelenir.",

        "where_more": "{surfaces} dağıtım yüzeyinin tamamı",
        "nx_install_kicker": "Kurulum",
        "nx_install_meta": "{commands} komut · {mcp_tools} MCP aracı · {runtime_deps} bağımlılık",

        "miss_kicker": "Sınırlar",
        "miss_title": "Çekirdeğin neyi kaçırdığı, çekirdekten üretilir.",
        "miss_body": "Elle güncellenen bir sınırlılıklar sayfası tek bir sürüm boyunca doğrudur, "
                     "sonrasında eksik beyana dönüşür. Bu liste detector tablosundan ve "
                     "ölçülmüş kaçırmalardan üretilir; koddan geri kalamaz.",
        "miss_foot": "Temiz bir rapor, sınırların tamamı okunmadan sorunsuzluk anlamına gelmez. "
                     "Aracın ürettiği her rapor kendi sınırlarını da belirtir: ulaşılamayan bir "
                     "alan varsa rapora kaydedilir.",

        "what_kicker": "Ne yapıyor",
        "what_title": "Tek komut kodu tarar ve bulduğunu raporlar.",
        "what_sub": "Üç aşama; hiçbiri hesap, ağ bağlantısı ya da model gerektirmez.",

        "install_kicker": "Kurulum",
        "install_title": "Claude Code'da iki satır ya da tek bir pip install.",
        "install_sub": "En sık kullanılan iki yöntem. Toplam {surfaces} yüzey vardır: MCP "
                       "sunucusu, GitHub Action, konteyner imajı ve pre-commit hook'ları kalan "
                       "dördüdür. Hepsi aynı çekirdeği çalıştırır, hiçbiri diğerinin kısıtlanmış "
                       "sürümü değildir.",
        "install_plugin_sub": "Claude Code eklentisi olarak:",
        "standalone_sub": "Bağımsız kullanım — Claude Code, API anahtarı ve ücretli plan "
                          "gerekmez, çalışma zamanı bağımlılığı bulunmaz. CI'da, cron'da ve "
                          "ağdan yalıtılmış makinelerde çalışır:",
        "label_detectors": "deterministik detector",
        "label_golden": "etiketli fixture açığı",
        "label_gates": "CI kapısı",
        "label_asvs": "ASVS 5.0'a eşlenmiş CWE",

    },
}

SHELL_KEYS = ("cta_repo", "nav_label", "lang_label", "totop_label", "skip_label")

# The page that is not a page. GitHub Pages serves `404.html` for any address that does not
# exist, which has three consequences the template cannot express on its own: it renders at a URL
# the generator never chose, so every link on it is root-absolute; it has no canonical and no
# alternates, because it is not a document a crawler should hold; and it carries `noindex` for the
# same reason. One file for both languages, since the server cannot know which was wanted — so
# this copy is a single dict rather than one per language.
E404: dict[str, dict[str, str]] = {
    "en": {
        "lang": "en",
        "page_title": "Not found — SecAudit",
        "page_description": "This address does not match a page on secaudit.mtvrkan.com.",
        # One eyebrow per language rather than one carrying both. They are separate pills because
        # `.seg` sizes its ends with `:first-child`/`:last-child`, and a hidden segment still
        # matches those — hiding one inside a shared pill leaves the visible end unpadded.
        "e404_eyebrow_en": "404 · Not found",
        "e404_eyebrow_tr": "404 · Bulunamadı",
        "e404_h1": "That page is not here.",
        "e404_h2": "Bu sayfa burada değil.",
        "e404_en": "The address does not match any page on this site. Three exist: the "
                   "overview, the external measurement, and the installation guide.",
        "e404_tr": "Adres bu sitedeki hiçbir sayfayla eşleşmiyor. Üç sayfa mevcut: genel bakış, "
                   "dış ölçüm ve kurulum kılavuzu.",
        "e404_cta_en": "English",
        "e404_cta_tr": "Türkçe",
        "e404_note": "A link on this site cannot have brought you here: the build resolves every "
                     "internal link and fragment against the pages it just rendered, and fails "
                     "if one of them does not exist.",
        "e404_note_tr": "Bu sitedeki bir bağlantı sizi buraya getirmiş olamaz: derleme, her iç "
                        "bağlantıyı ve her parça adresini az önce ürettiği sayfalara karşı "
                        "çözümler ve biri yoksa derlemeyi düşürür.",
    },
}
E404["tr"] = E404["en"]
