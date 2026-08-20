"""The comparison page's words.

The one page on this site that makes factual claims about somebody else's product, which is why
it is built differently from the others. Three rules it holds and the rest of the site does not
have to:

1. **Install both.** The recommendation on this page is not "use this instead". Anthropic ships
   two security plugins, they are good, and one of them is free inside the product. A comparison
   page that pretended otherwise would be selling rather than informing, and a reader who
   installs on that basis finds out within a day.
2. **Quote, attribute and date.** Every claim about the official plugins is a quotation from
   their own documentation with the date it was read, because their product changes and this
   page cannot. A capability table that silently goes stale about a competitor is worse than no
   table: it is wrong about someone who cannot correct it here.
3. **The SecAudit column is derived where it can be.** "Published score" is not a tick, it is the
   figure; "MCP server" is the tool count the manifest declares. A tick a reader cannot check is
   a tick this project has no business drawing.
"""

# Rows are (capability, official, ours). `None` renders as the em dash; a string renders as
# itself, which is how the derived cells carry their figure instead of a tick.
CMP_ROWS = [
    ("cmp_row_writes", True, None),
    ("cmp_row_agents", True, None),
    ("cmp_row_live", None, True),
    ("cmp_row_gate", None, True),
    ("cmp_row_offline", None, True),
    ("cmp_row_score", None, "{rv_pct_f3} / {sb_pct_recall}"),
    ("cmp_row_evidence", None, True),
    ("cmp_row_mcp", None, "{mcp_tools}"),
]

COMPARE_COPY: dict[str, dict[str, str]] = {
    "en": {
        "lang": "en",
        "page_title": "SecAudit vs the official Claude security plugins",
        "page_description": "What Anthropic's two security plugins do, what SecAudit does, and "
                            "why the answer is to install both. Every claim quoted and dated.",
        "cmp_eyebrow": "Comparison · read 2026-08-12 · quoted, not paraphrased",
        "cmp_head_1": "Install both.",
        "cmp_head_2": "They answer different questions.",
        "cmp_lede": "Anthropic ships two security plugins and they are good. One reviews code "
                    "as Claude writes it; the other runs a multi-agent scan of a repository and "
                    "produces reviewed patches. Both read the source in your checkout. This page "
                    "is about the questions that start after that sentence.",
        "cmp_cta_official": "The official plugins",
        "cmp_cta_install": "Install SecAudit",
        "cmp_note": "Nothing here argues that the official plugins are worse. The in-session "
                    "plugin reduces what reaches your branch, and this tool answers the question "
                    "you get asked afterwards — usually by somebody outside the engineering team.",

        "ccta_title": "Install the official plugins. Then install this one.",
        "ccta_body": "They review what you are writing. This audits what you have shipped, "
                     "against a corpus somebody else labelled, and produces the document you "
                     "hand over afterwards.",
        "ccta_install": "Install",
        "ccta_home": "Overview",
        "tbl_kicker": "Capability",
        "tbl_title": "The row that matters is the one you are about to need.",
        "tbl_sub": "A tick in the SecAudit column is a claim this site can be held to. Where the "
                   "honest answer is a figure rather than a tick, the figure is shown — and it "
                   "is read from the same measurement the rest of the site publishes.",
        "col_capability": "Capability",
        "col_official": "Official plugins",
        "col_secaudit": "SecAudit",
        "cmp_row_writes": "Reviews code as Claude writes it",
        "cmp_row_agents": "Multi-agent repo scan → reviewed patches",
        "cmp_row_live": "Audit a running site or API",
        "cmp_row_gate": "Authorization gate + scope.yaml for active testing",
        "cmp_row_score": "Published, reproducible detection score",
        "cmp_row_offline": "Runs without Claude Code, without a paid plan, offline",
        "cmp_row_evidence": "SBOM, OpenVEX and EU CRA evidence pack",
        "cmp_row_mcp": "Tools exposed to Codex, Cursor, OpenCode over MCP",
        "tbl_note": "The two figures in the score row are recall on two external corpora — "
                    "{rv_pct_f3} F3 on Python and {sb_pct_recall} recall on JavaScript, both "
                    "scored by benchmarks this project does not own. Neither official plugin "
                    "publishes a number, and their documentation says scans are "
                    "nondeterministic, so the row is a difference in kind rather than in degree.",

        "q_kicker": "In their words",
        "q_title": "The limits below are quoted from Anthropic's own documentation.",
        "q_body": "Not paraphrased and not inferred. Each line is what the official docs say "
                  "about their own scope, read on the date in the eyebrow above. If they change "
                  "the product, this page is wrong until somebody updates it — which is the "
                  "honest liability of writing about someone else's software at all.",
        "q_foot": "Both quotations are from the Claude Code security documentation. Follow the "
                  "link in the hero and read them in context; that is the point of quoting "
                  "rather than summarising.",
        "q_panel_head": "code.claude.com/docs",
        "q_1": "the review reads the source code in your checkout, not a running site or "
               "deployed service",
        "q_2": "two scans of the same code can surface different findings",
        "q_1_gloss": "",
        "q_2_gloss": "",
        "q_1_note": "This is the opening for a live-target track, and it is why this project has "
                    "an authorization gate at all.",
        "q_2_note": "A deliberate property of an agentic scan, and the reason a deterministic "
                    "tier can publish a reproducible number and an agentic one cannot.",

        "not_kicker": "What this does not do",
        "not_title": "Four things SecAudit deliberately is not.",
        "not_sub": "A comparison page that only lists advantages is an advertisement. These are "
                   "the four places where the answer is to use something else.",
        "not_1": "An in-editor reviewer",
        "not_1_why": "It does not watch Claude write code. Install the official guidance plugin "
                     "for that; the two do not overlap.",
        "not_2": "A measured LLM tier",
        "not_2_why": "The optional model tier ships off by default and is not measured. A "
                     "general-purpose model scores above this engine on the same corpus with no "
                     "harness at all, and that is stated rather than hidden.",
        "not_3": "A finder of business-logic flaws",
        "not_3_why": "The rules being broken are your product's and are not written down "
                     "anywhere the analyser can read. Most of what this engine still misses is "
                     "this, and the benchmark pages say so per class.",
        "not_4": "A certificate",
        "not_4_why": "The compliance pack is input to a process, not proof of one, and the pack "
                     "says so in its own disclaimer. Standards whose control text cannot be "
                     "quoted are refused rather than mapped by number.",
        "not_note": "Each of these is stated somewhere else on this site too, with the "
                    "measurement behind it. A limit that only appears on the page nobody reads "
                    "is a limit that was not really disclosed.",
    },
    "tr": {
        "lang": "tr",
        "page_title": "SecAudit ve resmî Claude güvenlik eklentileri",
        "page_description": "Anthropic'in iki güvenlik eklentisi ne yapar, SecAudit ne yapar ve "
                            "neden ikisi birlikte kullanılır. Her iddia alıntılanmış ve "
                            "tarihlendirilmiştir.",
        "cmp_eyebrow": "Karşılaştırma · 2026-08-12 tarihinde okundu · özet değil, birebir alıntı",
        "cmp_head_1": "Her ikisi de kurulmalı.",
        "cmp_head_2": "Farklı sorulara yanıt veriyorlar.",
        "cmp_lede": "Anthropic iki güvenlik eklentisi sunuyor ve ikisi de nitelikli araçlar. "
                    "Biri, Claude kod yazarken incelemeyi üstleniyor; diğeri bir depoyu birden "
                    "çok ajanla tarayarak gözden geçirilmiş yamalar üretiyor. Her ikisi de "
                    "yerel kopyanızdaki kaynak kodu okuyor. Bu sayfa, bu noktadan sonra "
                    "başlayan soruları ele alıyor.",
        "cmp_cta_official": "Resmî eklentiler",
        "cmp_cta_install": "SecAudit'i kurun",
        "cmp_note": "Bu sayfa resmî eklentilerin daha zayıf olduğunu ileri sürmüyor. Oturum içi "
                    "eklenti, dalınıza ulaşan hata sayısını azaltır; SecAudit ise kod yayına "
                    "alındıktan sonra sorulan soruyu yanıtlar. Bu soruyu çoğu zaman mühendislik "
                    "ekibi dışındaki bir paydaş sorar.",

        "ccta_title": "Resmî eklentileri kurun. Ardından SecAudit'i kurun.",
        "ccta_body": "Resmî eklentiler yazmakta olduğunuz kodu inceler. SecAudit, yayına "
                     "aldığınız kodu bağımsız olarak etiketlenmiş bir veri kümesine karşı denetler ve "
                     "denetimin ardından teslim edeceğiniz belgeyi üretir.",
        "ccta_install": "Kurulum",
        "ccta_home": "Genel bakış",
        "tbl_kicker": "Yetenek",
        "tbl_title": "Karar, ihtiyaç duyduğunuz satırda veriliyor.",
        "tbl_sub": "SecAudit sütunundaki her onay işareti, bu sitenin hesabını verebileceği bir "
                   "iddiadır. Dürüst yanıtın onay işareti değil rakam olduğu satırlarda rakamın "
                   "kendisi yazılıdır; bu rakamlar sitenin geri kalanında yayımlanan "
                   "ölçümlerden okunur.",
        "col_capability": "Yetenek",
        "col_official": "Resmî eklentiler",
        "col_secaudit": "SecAudit",
        "cmp_row_writes": "Claude kod yazarken inceleme yapar",
        "cmp_row_agents": "Çok ajanlı depo taraması → gözden geçirilmiş yamalar",
        "cmp_row_live": "Çalışan bir siteyi veya API'yi denetler",
        "cmp_row_gate": "Yetkilendirme kapısı ve aktif test için scope.yaml",
        "cmp_row_score": "Yayımlanmış, yeniden üretilebilir tespit skoru",
        "cmp_row_offline": "Claude Code olmadan, ücretli plan olmadan, çevrimdışı çalışır",
        "cmp_row_evidence": "SBOM, OpenVEX ve AB CRA kanıt paketi",
        "cmp_row_mcp": "MCP üzerinden Codex, Cursor ve OpenCode'a sunulan araç",
        "tbl_note": "Skor satırındaki iki rakam iki dış veri kümesinden gelir: Python tarafında "
                    "{rv_pct_f3} F3, JavaScript tarafında {sb_pct_recall} recall. Her ikisi de "
                    "bu projeye ait olmayan kıyaslamaların kendi puanlayıcılarıyla "
                    "ölçülmüştür. Resmî eklentilerin hiçbiri bir tespit rakamı yayımlamıyor ve "
                    "belgeleri taramaların deterministik olmadığını belirtiyor. Bu nedenle söz "
                    "konusu satır bir derece farkı değil, tür farkıdır.",

        "q_kicker": "Kendi ifadeleriyle",
        "q_title": "Aşağıdaki sınırlar Anthropic'in kendi belgelerinden birebir alıntıdır.",
        "q_body": "Özetlenmedi, yorumlanmadı. Her satır, resmî belgelerin kendi kapsamları "
                  "hakkında yazdıklarıdır ve yukarıdaki tarihte okunmuştur. Alıntılar özgün "
                  "dilinde bırakılmıştır — çevrilmiş bir alıntı artık alıntı değildir — Türkçe "
                  "karşılıkları her satırın altında ayrıca verilmiştir. Ürün değiştiğinde bu "
                  "sayfa, güncellenene kadar yanlış kalır; başkasının yazılımı hakkında "
                  "yazmanın bedeli budur.",
        "q_foot": "Her iki alıntı da Claude Code güvenlik belgelerinden alınmıştır. Giriş "
                  "bölümündeki bağlantıyı izleyerek ikisini de bağlamı içinde okuyabilirsiniz; "
                  "özetlemek yerine alıntılamanın amacı budur.",
        "q_panel_head": "code.claude.com/docs",
        "q_1": "the review reads the source code in your checkout, not a running site or "
               "deployed service",
        "q_2": "two scans of the same code can surface different findings",
        "q_1_gloss": "Türkçe çevirisi: inceleme, çalışan bir siteyi ya da yayına alınmış bir "
                     "servisi değil, yerel kopyanızdaki kaynak kodu okur.",
        "q_2_gloss": "Türkçe çevirisi: aynı kodun iki taraması birbirinden farklı bulgular "
                     "ortaya çıkarabilir.",
        "q_1_note": "Canlı hedef denetiminin doğduğu boşluk budur; bu projenin neden bir "
                    "yetkilendirme kapısı taşıdığını da açıklar.",
        "q_2_note": "Ajanlı taramanın bilinçli bir özelliğidir. Deterministik bir katmanın "
                    "neden yeniden üretilebilir bir rakam yayımlayabildiğini, ajanlı katmanın "
                    "neden yayımlayamadığını açıklar.",

        "not_kicker": "Kapsam dışı",
        "not_title": "SecAudit'in kapsamı dışında kalan dört alan.",
        "not_sub": "Yalnızca üstünlükleri sıralayan bir karşılaştırma sayfası, karşılaştırma "
                   "değil reklamdır. Aşağıdakiler, yanıtın başka bir araç kullanmak olduğu "
                   "dört alandır.",
        "not_1": "Editör içi inceleme",
        "not_1_why": "SecAudit, Claude kod yazarken süreci izlemez. Bunun için resmî inceleme "
                     "eklentisi kullanılmalıdır; iki araç birbiriyle çakışmaz.",
        "not_2": "Ölçülmüş bir LLM katmanı",
        "not_2_why": "Opsiyonel model katmanı varsayılan olarak kapalıdır ve ölçülmemiştir. "
                     "Genel amaçlı bir model, herhangi bir düzenek olmadan aynı veri kümesinde bu "
                     "çekirdeğin üzerinde skor almaktadır; bu bulgu gizlenmemekte, "
                     "yayımlanmaktadır.",
        "not_3": "İş mantığı açıklarını bulan bir araç",
        "not_3_why": "İhlal edilen kurallar ürününüze aittir ve çözümleyicinin okuyabileceği "
                     "hiçbir yerde yazılı değildir. Çekirdeğin hâlâ kaçırdıklarının büyük bölümü "
                     "bu alandadır; kıyaslama sayfaları bunu sınıf bazında belirtir.",
        "not_4": "Sertifika",
        "not_4_why": "Uyumluluk paketi bir sürecin girdisidir, kanıtı değil; paket bunu kendi "
                     "sorumluluk reddi metninde belirtir. Kontrol metni alıntılanamayan "
                     "standartlar, numarayla eşlenmek yerine kapsam dışı bırakılır.",
        "not_note": "Bu maddelerin her biri, arkasındaki ölçümle birlikte sitenin başka "
                    "sayfalarında da yer alır. Yalnızca kimsenin okumadığı sayfada görünen bir "
                    "sınır, gerçekte açıklanmamış sayılır.",
    },
}
