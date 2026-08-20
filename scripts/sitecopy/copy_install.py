"""The install page's words.

Split out of `gen_site.py` when that file passed 2,700 lines and the roadmap still listed four
more pages, each worth roughly 350 lines of the same. The generator keeps the logic — the readers
that pull every figure out of the repository, the renderer and the verifier — and the words live
here. Nothing was rewritten in the move: `site/dist` is byte-identical before and after, which is
the only assertion that makes a refactor of a generator safe.
"""

# --------------------------------------------------------------------------- install page
#
# The landing page's `#install` section is two commands and the `#where` grid is six one-liners.
# Neither is an install page: a reader who has decided arrives needing the flags, the config
# entry for their own client, and the answer to "does this one work today". So this page is the
# six surfaces at full size, and the rule it is built under is stricter than the rest of the
# site's. A stale figure is embarrassing. A stale *command* is broken — it fails in the reader's
# terminal, and what they conclude from a security scanner whose install line does not work is
# not that the line is old.
#
# Nothing here is typed twice. The readers at the top of this file take every id, flag, input,
# hook and snippet out of the file that defines it, and the copy below is prose about them.
INSTALL_COPY: dict[str, dict[str, str]] = {
    "en": {
        "lang": "en",
        "page_title": "Install SecAudit — six surfaces, one engine",
        "page_description": "Every way to run SecAudit: the Claude Code plugin, the CLI, the "
                            "MCP server, the GitHub Action, the container image and the "
                            "pre-commit hooks.",

        "ins_eyebrow": "{surfaces} surfaces · one engine · {tag}",
        # No count in the headline. `{surfaces} ways in` derived correctly and read badly:
        # "One engine. 6 ways in." spells one number and sets the other as a numeral, in two
        # lines of the same sentence. The count belongs in the eyebrow and the stat row, where
        # a numeral is what a reader expects.
        "ins_h1_1": "One engine.",
        "ins_h1_2": "Every way in.",
        "ins_lede": "The plugin, the CLI, the MCP server, the Action, the image and the hooks "
                    "all run the same deterministic tier — the one carrying the external "
                    "number. None is a reduced version of another; the appropriate surface is "
                    "the one already present in the workflow. Every command on this page is "
                    "read at build time out of the file that defines it, so a renamed flag "
                    "breaks this build rather than a user's terminal.",
        "ins_cta_plugin": "Claude Code plugin",
        "ins_cta_cli": "Standalone CLI",
        "ins_note": "None of these paths requires an API key. The deterministic tier needs no "
                    "network and no account; the optional model tier remains off until it is "
                    "enabled.",
        "label_surfaces": "ways in",
        "label_commands": "slash commands",
        "label_tools": "MCP tools",
        "label_deps": "runtime dependencies",

        "choose_kicker": "Choose one",
        "choose_title": "Which surface, in one table.",
        "choose_sub": "Same engine, same findings, same report. What differs is who runs it, "
                      "when it runs, and what it is allowed to reach.",
        "col_situation": "Situation",
        "col_surface": "Surface",
        "col_cost": "What it costs",
        "choose_note": "The live target is the one real asymmetry. Probing a running system is "
                       "a human decision, so it exists only in the plugin and only behind the "
                       "authorization gate — nothing on any other row reaches a host. "
                       "Everything else is the same code: the detectors, the taint analysis, "
                       "the dependency reachability pass and the evidence pack.",

        "s1_kicker": "1 / {surfaces}",
        "s1_tag": "Claude Code",
        "s1_title": "The plugin: the whole methodology, live target included.",
        "s1_body": "Two lines in the Claude Code prompt. The marketplace id and the plugin id "
                   "come out of `.claude-plugin/marketplace.json` — the file Claude Code itself "
                   "reads — so this page cannot end up naming a marketplace that was renamed a "
                   "release ago. This is the only surface with the live-target track and the "
                   "only one that runs P1–P10 end to end; the others are the deterministic "
                   "engine underneath it.",
        "s1_foot": "Active testing remains blocked until ownership is declared in "
                   "`scope.yaml`. That is a PreToolUse hook rather than an instruction to a "
                   "model: the harness refuses the call, so no amount of persuasion in the "
                   "conversation reaches an unclaimed host.",
        "s1_verify": "Then type `/secaudit`. The command should appear with its argument hint — "
                     "if it does not, the marketplace was added but the plugin was not "
                     "installed.",
        "s1_cmd_head": "plugins/secaudit/commands/",

        "s2_kicker": "2 / {surfaces}",
        "s2_tag": "no key, no network",
        "s2_title": "The CLI: the same engine with nothing around it.",
        "s2_body": "`{package}` installs the `secaudit` command and nothing else: no account, "
                   "no key, no plan, and no runtime dependency to audit before it can be "
                   "trusted. It runs on a host with no network connection, which is the state a "
                   "great deal of code worth auditing lives in. Python {python_floor} or newer.",
        "s2_foot": "Until the first release is published, `pip install {package}` is a command "
                   "that can succeed with somebody else's package: a pending trusted publisher "
                   "does not reserve the name. The `git+…` line above needs no release and is "
                   "exact. And the zero-dependency claim is a build gate rather than a "
                   "sentence: `assert_no_runtime_deps.py` fails the build the moment one is "
                   "added, and the list rendered beside this paragraph is read out of "
                   "`kit/pyproject.toml`.",

        "s3_kicker": "3 / {surfaces}",
        "s3_tag": "stdio",
        "s3_title": "The MCP server: Codex, Cursor, OpenCode, and whatever is next.",
        "s3_body": "One process over stdio, {mcp_tools} tools, the same engine the plugin and "
                   "the CLI run. A second implementation per harness is how two clients end up "
                   "disagreeing about whether a file is safe, so there is not one — the "
                   "published number describes this server too.",
        "s3_foot": "No tool here accepts a URL, a host or an endpoint, and the test suite "
                   "asserts that no schema grows one. A `tools/call` carries no evidence that "
                   "anybody authorized a probe, and a tool that scans whatever it is handed is "
                   "a tool that scans whatever a prompt injection puts in front of it.",
        "s3_essentials_head": "what every client needs",
        "s3_clients_title": "Per client",

        "s4_kicker": "4 / {surfaces}",
        "s4_tag": "pull-request gate",
        "s4_title": "The Action: a gate on what the change introduced.",
        "s4_body": "It runs the code in the checkout rather than installing a release, so the "
                   "version audited is the commit under review and there is no window in which "
                   "a compromised release of a security scanner runs against an already "
                   "checked-out repository. On a pull request it compares against the base "
                   "branch by default, so the gate fires on what the change introduced and "
                   "stays quiet about the rest.",
        "s4_foot": "`comment` is off by default. A workflow should not acquire write access to "
                   "pull requests because an example in someone's documentation had the flag "
                   "set.",
        "s4_file": ".github/workflows/security.yml",

        "s5_kicker": "5 / {surfaces}",
        "s5_tag": "non-root",
        "s5_title": "The image: a fixed toolchain, built from this repository.",
        "s5_body": "There is no image to pull, by design: it is built from the Dockerfile in "
                   "the repository. The base is pinned by digest rather than by tag, so an "
                   "image built today is the image someone else built last month, and "
                   "everything that went into it is readable in one file.",
        "s5_foot": "It drops to an unprivileged uid, and the run above mounts the tree "
                   "read-only. A scanner does not require write access to what it scans, and "
                   "the one occasion on which that matters is the occasion on which the target "
                   "has been tampered with.",
        "s6_kicker": "6 / {surfaces}",
        "s6_tag": "staged files",
        "s6_title": "The hooks: before the branch rather than after it.",
        "s6_body": "Two hooks, both scoped to the files being committed. Budget matters more "
                   "than coverage here: a hook that takes ten seconds is bypassed with "
                   "`--no-verify` inside a week, and a bypassed hook catches nothing. So the "
                   "default is the deterministic pass with the dependency and external-scanner "
                   "tiers switched off, and the full audit stays in CI where it can afford to "
                   "be slow.",
        "s6_foot": "Where the full hook is too slow to survive on a given repository, the "
                   "narrower one applies. A secret is the least recoverable finding after the "
                   "fact — once committed it is in the history — so catching that alone is "
                   "worth considerably more than catching nothing.",

        "tools_kicker": "Optional, never required",
        "tools_title": "External scanners, used when present on PATH.",
        "tools_sub": "The engine's own findings do not depend on any of them. Where one is "
                     "installed its results are merged and attributed to it; where it is "
                     "absent the report says so rather than quietly narrowing what it "
                     "searched — a clean result has to mean the same thing on both machines.",
        "tools_note": "A scan with none of these installed still runs every detector, the "
                      "taint analysis and the dependency reachability pass. The live-mode "
                      "toolchain — `testssl.sh` and the rest — belongs to the plugin rather "
                      "than the engine, and `docs/tooling-setup.md` lists all of it.",

        "icta_title": "After installation.",
        "icta_body": "Getting started walks the first scan, the authorization gate and the "
                     "report formats. The benchmark page has the external number and "
                     "everything behind it.",
        "icta_docs": "Getting started",
        "icta_bench": "The external number",
    },
    "tr": {
        "lang": "tr",
        "page_title": "SecAudit kurulumu — altı yüzey, tek çekirdek",
        "page_description": "SecAudit'i çalıştırmanın her yolu: Claude Code eklentisi, CLI, MCP "
                            "sunucusu, GitHub Action, konteyner imajı ve pre-commit hook'ları.",
        "ins_eyebrow": "{surfaces} yüzey · tek çekirdek · {tag}",
        "ins_h1_1": "Tek çekirdek.",
        "ins_h1_2": "Her giriş yolu.",
        "ins_lede": "Eklenti, CLI, MCP sunucusu, Action, imaj ve hook'lar aynı deterministik "
                    "katmanı çalıştırır — dış sayıyı taşıyan katmanı. Hiçbiri diğerinin "
                    "kısıtlanmış sürümü değildir; uygun yüzey, iş akışında zaten bulunandır. Bu "
                    "sayfadaki her komut derleme anında onu tanımlayan dosyadan okunur; adı "
                    "değişen bir bayrak kullanıcının terminalini değil, bu derlemeyi kırar.",
        "ins_cta_plugin": "Claude Code eklentisi",
        "ins_cta_cli": "Bağımsız CLI",
        # Türkçe sürüme özel son cümle: bu sayfadaki komut, girdi ve araç açıklamaları
        # manifestlerden birebir okunuyor ve manifestler İngilizce, dolayısıyla sayfanın bir
        # kısmı İngilizce görünüyor. Bunu bir kez söylemek, okuyanın yarım çeviri sanmasına
        # engel oluyor.
        # Türkçe sürüme özel son cümle: bu sayfadaki komut, girdi ve araç açıklamaları
        # manifestlerden birebir okunuyor ve manifestler İngilizce, dolayısıyla sayfanın bir
        # kısmı İngilizce görünüyor. Bunu bir kez söylemek, okuyanın yarım çeviri sanmasını
        # önlüyor.
        "ins_note": "Bu yolların hiçbiri API anahtarı gerektirmez. Deterministik katman ağ ve "
                    "hesap istemez; isteğe bağlı model katmanı etkinleştirilene kadar kapalı "
                    "kalır. Manifestlerden birebir okunan açıklamalar İngilizcedir: çevrilmiş "
                    "bir kopya, kaynak dosya değiştiğinde sessizce yanlış hâle gelirdi.",
        "label_surfaces": "giriş yolu",
        "label_commands": "slash komutu",
        "label_tools": "MCP aracı",
        "label_deps": "çalışma zamanı bağımlılığı",

        "choose_kicker": "Yüzey seçimi",
        "choose_title": "Hangi yüzey — tek tabloda.",
        "choose_sub": "Aynı çekirdek, aynı bulgular, aynı rapor. Değişen şey: kimin çalıştırdığı, "
                      "ne zaman çalıştığı ve neye erişmesine izin verildiği.",
        "col_situation": "Durum",
        "col_surface": "Yüzey",
        "col_cost": "Maliyeti",
        "choose_note": "Tek gerçek asimetri canlı hedef. Çalışan bir sistemi yoklamak insan "
                       "kararıdır, o yüzden yalnızca eklentide ve yalnızca yetkilendirme "
                       "kapısının arkasında var — diğer satırlardan hiçbiri bir host'a "
                       "ulaşmaz. Geri kalan her şey aynı kod: detector'lar, taint analizi, "
                       "bağımlılık erişilebilirlik geçişi ve kanıt paketi.",

        "s1_kicker": "1 / {surfaces}",
        "s1_tag": "Claude Code",
        "s1_title": "Eklenti: canlı hedef dahil metodolojinin tamamı.",
        "s1_body": "Claude Code isteminde iki satır. Marketplace ve eklenti kimlikleri "
                   "`.claude-plugin/marketplace.json` dosyasından geliyor — Claude Code'un "
                   "kendisinin okuduğu dosya — böylece bu sayfa bir sürüm önce adı değişmiş bir "
                   "marketplace'i anamaz. Canlı hedef izine sahip tek yüzey ve P1–P10'u baştan "
                   "sona çalıştıran tek yüzey bu; diğerleri altındaki deterministik çekirdek.",
        "s1_foot": "Aktif test, `scope.yaml` içinde sahiplik beyan edilene kadar engellidir. "
                   "Bu bir PreToolUse hook'udur, modele verilmiş bir talimat değil: çağrıyı "
                   "harness reddeder, dolayısıyla konuşma içindeki hiçbir ikna, sahiplenilmemiş "
                   "bir host'a ulaşmaz.",
        "s1_verify": "Sonra `/secaudit` yazın. Komut, argüman ipucuyla birlikte görünmeli — "
                     "görünmüyorsa marketplace eklenmiş ama eklenti kurulmamıştır.",
        "s1_cmd_head": "plugins/secaudit/commands/",

        "s2_kicker": "2 / {surfaces}",
        "s2_tag": "anahtar yok, ağ yok",
        "s2_title": "CLI: etrafında hiçbir şey olmayan aynı çekirdek.",
        "s2_body": "`{package}` yalnızca `secaudit` komutunu kurar — hesap yok, anahtar yok, "
                   "plan yok ve güvenmeden önce denetlemeniz gereken bir çalışma zamanı "
                   "bağımlılığı yok. Ağ kablosu çıkarılmış bir makinede çalışır ki denetlenmeye "
                   "değer kodun çoğu tam olarak o durumda yaşar. Python {python_floor} veya "
                   "üzeri.",
        "s2_foot": "İlk sürüm yayımlanana kadar `pip install {package}` komutu, başka birinin "
                   "paketiyle başarılı olabilecek bir komuttur: bekleyen bir trusted publisher "
                   "ismi rezerve etmez. Yukarıdaki `git+…` satırı sürüm gerektirmez ve kesindir. "
                   "Sıfır bağımlılık iddiası ise bir cümle değil, bir derleme kapısı: "
                   "`assert_no_runtime_deps.py` bir bağımlılık eklendiği anda derlemeyi "
                   "kırar ve bu paragrafın yanındaki liste `kit/pyproject.toml`'dan okunur.",

        "s3_kicker": "3 / {surfaces}",
        "s3_tag": "stdio",
        "s3_title": "MCP sunucusu: Codex, Cursor, OpenCode ve sıradaki ne olursa.",
        "s3_body": "stdio üzerinden tek süreç, {mcp_tools} araç, eklentinin ve CLI'ın "
                   "çalıştırdığı çekirdeğin aynısı. Her harness için ayrı bir uygulama, iki "
                   "istemcinin bir dosyanın güvenli olup olmadığı konusunda anlaşmazlığa "
                   "düşmesinin yoludur — o yüzden yok: yayımlanan sayı bu sunucuyu da anlatır.",
        "s3_foot": "Buradaki hiçbir araç URL, host veya endpoint kabul etmez ve test paketi "
                   "hiçbir şemanın böyle bir alan kazanmadığını doğrular. Bir `tools/call`, "
                   "yoklamayı birinin yetkilendirdiğine dair kanıt taşımaz; kendisine verilen "
                   "her şeyi tarayan bir araç, prompt injection'ın önüne koyduğu her şeyi "
                   "tarayan bir araçtır.",
        "s3_essentials_head": "her istemcinin ihtiyacı",
        "s3_clients_title": "İstemci başına",

        "s4_kicker": "4 / {surfaces}",
        "s4_tag": "pull request kapısı",
        "s4_title": "Action: değişikliğin getirdiğine kurulan kapı.",
        "s4_body": "Bir sürüm kurmak yerine checkout'taki kodu çalıştırır; denetlenen sürüm, "
                   "incelenen commit olur ve bir güvenlik tarayıcısının ele geçirilmiş "
                   "sürümünün, depo zaten checkout edilmişken çalıştığı bir pencere oluşmaz. "
                   "Pull request'te varsayılan olarak base dalla karşılaştırır; kapı, "
                   "değişikliğin getirdiği bulgulara tepki verir, getirmediklerine sessiz "
                   "kalır.",
        "s4_foot": "`comment` varsayılan olarak kapalı. Bir workflow, birinin dokümanındaki "
                   "örnekte bayrak açık kaldı diye pull request'lerinize yazma yetkisi "
                   "kazanmamalı.",
        "s4_file": ".github/workflows/security.yml",

        "s5_kicker": "5 / {surfaces}",
        "s5_tag": "root değil",
        "s5_title": "İmaj: depodan derlenen sabit bir araç zinciri.",
        "s5_body": "Çekilecek bir imaj yoktur; bu tasarım gereğidir. İmaj, depodaki "
                   "Dockerfile'dan derlenir. Taban imaj etikete değil digest'e sabitlenmiştir, "
                   "dolayısıyla bugün derlenen imaj başkasının geçen ay derlediği imajın "
                   "aynısıdır ve içine giren her şey tek dosyada okunabilir.",
        "s5_foot": "Yetkisiz bir uid'ye düşer ve yukarıdaki çalıştırma, ağacı salt okunur "
                   "bağlar. Bir tarayıcının taradığı şeye yazma erişimine ihtiyacı yoktur; bunun "
                   "önem kazandığı tek durum, hedefin kurcalanmış olduğu durumdur.",
        "s6_kicker": "6 / {surfaces}",
        "s6_tag": "staged dosyalar",
        "s6_title": "Hook'lar: daldan önce, dal oluştuktan sonra değil.",
        "s6_body": "İki hook, ikisi de commit edilen dosyalarla sınırlı. Burada bütçe "
                   "kapsamdan önemlidir: on saniye süren bir hook bir hafta içinde "
                   "`--no-verify` ile atlanır ve atlanan hook hiçbir şey yakalamaz. Bu yüzden "
                   "varsayılan, bağımlılık ve dış tarayıcı katmanları kapalı hâldeki "
                   "deterministik geçiş; tam denetim yavaş olmayı kaldırabildiği yerde, "
                   "CI'da kalır.",
        "s6_foot": "Tam hook bir depoda hayatta kalamayacak kadar yavaşsa dar olanı uygulanır. "
                   "Bir sır, sonradan telafisi en zor bulgudur; commit'e girdiği anda "
                   "geçmiştedir. Dolayısıyla yalnızca sırların yakalanması, hiçbir şeyin "
                   "yakalanmamasından kat kat değerlidir.",

        "tools_kicker": "İsteğe bağlı, asla zorunlu değil",
        "tools_title": "PATH üzerinde bulunduklarında kullanılan dış tarayıcılar.",
        "tools_sub": "Çekirdeğin kendi bulguları bunların hiçbirine bağlı değildir. Kurulu olan "
                     "aracın sonuçları birleştirilir ve o araca atfedilir; kurulu olmayan için "
                     "rapor bunu belirtir ve neyi aradığını sessizce daraltmaz. Temiz bir "
                     "sonuç, iki makinede de aynı anlama gelmelidir.",
        "tools_note": "Bunların hiçbiri kurulu değilken yapılan bir tarama yine her detector'ı, "
                      "taint analizini ve bağımlılık erişilebilirlik geçişini çalıştırır. Canlı "
                      "mod araç zinciri — `testssl.sh` ve gerisi — çekirdeğe değil eklentiye "
                      "aittir ve tamamı `docs/tooling-setup.md` içinde listelidir.",

        "icta_title": "Kurulumdan sonra.",
        "icta_body": "Getting started ilk taramayı, yetkilendirme kapısını ve rapor "
                     "formatlarını adım adım anlatır. Kıyaslama sayfasında dış sayı ve "
                     "arkasındaki her şey var.",
        "icta_docs": "Başlangıç rehberi",
        "icta_bench": "Dış sayı",
    },
}

# The six surfaces in the order the page presents them, and the anchor each card scrolls to.
# The titles and one-liners are NOT here — they are `SURFACES` below, the same list the landing
# page's grid renders, because two lists of six surfaces is two lists that will one day hold
# five and six. This holds only what the landing page has no use for: where each one lives on
# this page. A length disagreement between the two fails the build.
SURFACE_ANCHORS = ("plugin", "cli", "mcp", "action", "docker", "precommit")

# The chooser. (surface index, situation, what it costs) — the middle column is an index into
# `SURFACES` rather than a name, so a surface that gets renamed is renamed in the table too.
CHOOSE = {
    "en": [
        (0, "An existing Claude Code workflow", "Two lines; the live-target track comes with it"),
        (3, "CI, gating pull requests", "Ten lines of workflow, no install step"),
        (2, "Codex, Cursor, OpenCode or another MCP client", "One config entry"),
        (1, "Local, scriptable and offline use", "One package, zero dependencies"),
        (4, "A fixed toolchain and a sandboxed scanner", "One build, non-root"),
        (5, "Before the commit rather than after it", "Staged files only, under a second"),
    ],
    "tr": [
        (0, "Mevcut bir Claude Code iş akışı", "İki satır; canlı hedef izi beraberinde"),
        (3, "CI, pull request'lere kapı", "On satır workflow, kurulum adımı yok"),
        (2, "Codex, Cursor, OpenCode ya da başka bir MCP istemcisi", "Tek config girdisi"),
        (1, "Yerel, betiklenebilir ve çevrimdışı kullanım", "Tek paket, sıfır bağımlılık"),
        (4, "Sabit araç zinciri, izole tarayıcı", "Tek derleme, root değil"),
        (5, "Commit'ten sonra değil, önce", "Yalnızca staged dosyalar, bir saniyenin altında"),
    ],
}
