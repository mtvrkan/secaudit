"""The benchmark page's words.

Split out of `gen_site.py` when that file passed 2,700 lines and the roadmap still listed four
more pages, each worth roughly 350 lines of the same. The generator keeps the logic — the readers
that pull every figure out of the repository, the renderer and the verifier — and the words live
here. Nothing was rewritten in the move: `site/dist` is byte-identical before and after, which is
the only assertion that makes a refactor of a generator safe.
"""

# --------------------------------------------------------------------------- benchmark page
#
# The landing page can only summarise this: two stat blocks and a row of bars. The measurement
# is the product's single differentiating claim, so it gets the page where every figure behind
# the summary is visible — the confusion matrix, all six runs with what each one cost, every
# family, every repository, the digests that tie the run to an engine, and the disclosure that
# the number is no longer blind. Nothing here is typed: it is `result.json` and the README that
# check 27 already holds against it.
BENCH_COPY: dict[str, dict[str, str]] = {
    "en": {
        "lang": "en",
        "page_title": "The external number — SecAudit on RealVuln",
        "page_description": "SecAudit's deterministic tier on Real-Vuln-Benchmark, scored by "
                            "the benchmark's own scorer: F3 {rv_f3} across {rv_repos} of "
                            "{rv_repos_total} repositories.",

        "bench_eyebrow": "RealVuln {rv_bench_version} · Tier 0 · run {rv_date}",
        "bench_h1_1": "Someone else's corpus,",
        "bench_h1_2": "someone else's scorer.",
        "bench_lede": "{rv_labels} labelled vulnerabilities across {rv_repos} real repositories, "
                      "none of them labelled here and none of them scored here. This page is the "
                      "whole result, including the parts that are unflattering — the four "
                      "families still near zero, the {rv_zero_repos} repositories where nothing "
                      "labelled was found, and the disclosure that the number stopped being "
                      "blind three rounds ago.",
        "bench_cta_bench": "The benchmark",
        "bench_cta_raw": "Raw scorer output",
        "bench_note": "{rv_scanner} · {rv_tier} — no network, no API key, no paid plan.",
        "bench_matrix_head": "result.json · overall (micro)",
        "bench_matrix_right": "{rv_labels} labels",
        "gap_blind": "blind — the engine had not read this corpus",
        "gap_now": "now, three corpus-informed rounds later",
        "bench_matrix_foot": "The same scorer reports a stricter reading of this identical run: "
                             "F3 {rv_strict_f3}, recall {rv_strict_recall}, counting "
                             "{rv_strict_extra} further labels as missed on the same "
                             "{rv_tp} true positives. The honest range for this run is "
                             "{rv_strict_f3} – {rv_f3}. `micro` is quoted because it is the "
                             "aggregate the benchmark's own baselines are quoted in; "
                             "{rv_strict_f3} is the figure for anything else.",
        "label_f3": "F3 (recall × 9)",
        "label_f2": "F2",
        "label_precision": "precision",
        "label_recall": "recall",
        "label_tp": "true positives",
        "label_fp": "false positives",
        "label_fn": "missed",
        "label_tn": "true negatives",

        "disc_kicker": "Disclosure",
        "disc_tag": "read this before quoting the number",
        "disc_title": "This number is not blind, and it has not been for three rounds.",
        "disc_sub": "The first two runs were blind: the engine had never seen this corpus, and "
                    "{rv_blind_f3} is what it scored on code it had not read. Every run after "
                    "that was measured once the benchmark's own false negatives had been read "
                    "and the missing rules written.",
        "disc_note": "Every rule added is of a kind any SAST ships — weak PRNG for tokens, "
                     "cookie flags, CSRF exemptions, a committed fallback signing key, open "
                     "redirect, credentials in logs — so no rule is fitted to a particular "
                     "fixture. The selection, however, was corpus-informed three times, and the "
                     "advantage compounds. The gap between {rv_blind_f3} and {rv_f3} is the size "
                     "of it. {rv_blind_f3} is the conservative figure for an unseen codebase, "
                     "and the honest successor to this measurement is a benchmark this "
                     "repository has not seen.",
        "runs2_kicker": "Run history",
        "runs2_tag": "{rv_runs} runs, one corpus",
        "runs2_title": "The cost of each round, alongside its score.",
        "runs2_sub": "Same corpus, same scorer, same clone. Each round re-scores the previous "
                     "engine on the current checkout first and reproduces its committed figures "
                     "digit for digit, which is what makes the movement attributable to the "
                     "engine rather than to the corpus.",
        "runs2_caveat": "Precision rises alongside recall in every round after the first. The "
                        "repository treats that as evidence of rules rather than curve fitting; "
                        "a round in which precision falls is treated as a signal to narrow the "
                        "rule rather than to keep it.",
        "col_round": "Round",
        "col_matrix": "TP / FP / FN",
        "runs_first_label": "the first run — blind, on a corpus the engine had not read",

        "base_kicker": "Baselines",
        "base_title": "Against what the benchmark itself publishes.",
        "base_sub": "RealVuln publishes a best-reported figure per category. Three of these four "
                    "rows are theirs; the bold one is this engine, measured by their scorer on "
                    "their corpus. Every figure on this page keeps the scorer's own units — F3 "
                    "on 0–100, precision and recall as fractions — so the rows stay comparable "
                    "to the published table. The landing page states the same measurements as "
                    "percentages throughout.",
        "base_note": "Above rule-based SAST on both metrics, and well below both a "
                     "general-purpose model and the purpose-built system — both of which were "
                     "measured the way this one no longer is. The supportable claim is “above "
                     "{rv_sast_name} on a corpus since read”, not “better than "
                     "{rv_sast_name}”.",
        "col_category": "Category",
        "col_system": "Best reported",

        "fam_kicker": "Where the recall goes",
        "fam_title": "Every family, largest labelled pool first.",
        "fam_sub": "The ordering carries more information than the bars: the four families at "
                   "the top hold more than half of every label in the corpus, and they are the "
                   "four this tier scores worst on. A score is determined by the large pools "
                   "rather than by the ones a scanner finds easy.",
        "fam_note": "The pattern classes are near their ceiling: command injection, open "
                    "redirect, code injection and XXE all exceed 80%. The pools that determine "
                    "the score are not pattern classes. Roughly 130 of the labels in "
                    "`sensitive_data_exposure` and `security_misconfiguration` sit on a function "
                    "definition, the same shape as `broken_access_control` and `missing_auth`. "
                    "Those require the business-logic pass rather than a further rule, and no "
                    "rule added here has reached them.",
        "repo_kicker": "Per repository",
        "repo_tag": "{rv_repos} of {rv_repos_total}",
        "repo_title": "All of them, best first — including the ones that scored nothing.",
        "repo_sub": "Ranked by F3. Published in full rather than as a top five, because the top "
                    "five on this project's own page was two rounds stale before anything "
                    "compared it to the scorer output, and a leaderboard nobody reconciles "
                    "flatters itself.",
        "repo_note": "{rv_zero_repos} of {rv_repos} repositories scored 0.0 — nothing labelled "
                     "was found in either. They are in the table, at the bottom.",
        "repo_missing_title": "What was not scored, and why it matters",
        "col_repo": "Repository",

        "sb_kicker": "The other language",
        "sb_tag": "two runs",
        "sb_title": "What the JavaScript side does, and what it did before it had read this.",
        "sb_sub": "Every figure above describes Python. This one describes JavaScript, and it "
                  "has been measured twice. The first run was blind — no rule in this engine had "
                  "been written or chosen by reading a label from this benchmark — and it scored "
                  "{sb_blind_recall}. That is the figure for unseen code and it does not improve. What the "
                  "blind run bought was a diagnosis; the number here is what the engine scores "
                  "after acting on it. The two corpora are not comparable in either direction "
                  "— that one is applications, this one is libraries, and a library has no "
                  "request handler for the reachability analysis to start from.",
        "sb_panel_head": "SecBench.js",
        "sb_panel_right": "{sb_date}",
        "sb_label_found": "sinks found",
        "sb_label_sinks": "sinks labelled",
        "sb_label_pkgs": "npm packages",
        "sb_panel_foot": "Recall is the sound metric here and it is the only one published. The "
                         "benchmark labels one vulnerability per package and says nothing about "
                         "the rest of it, so an unmatched-finding ratio would be a lower bound on "
                         "noise rather than a precision — putting it beside the figure above "
                         "would compare two different measurements that share a name.",
        "sb_note": "The blind run said three things and this is what each became. ReDoS scored "
                   "zero because that analysis was Python-only — stated in the roadmap before a "
                   "package was fetched, so it could not afterwards be presented as a discovery; "
                   "it reads JavaScript now, and 8 of 87 is the honest size of criteria that "
                   "describe exponential backtracking when most real reports are polynomial. "
                   "Prototype pollution is still the worst class, but the rule that scored the "
                   "nine has been retired for one that reports the write rather than the loop. "
                   "And 35 sinks under `dist/` or `build/` were called a scoping decision rather "
                   "than a detection failure — the engine reads those directories now when the "
                   "package publishes them, 29 became reachable, and two were found. That claim "
                   "was the flattering half and it was wrong.",
        "prov_kicker": "Provenance",
        "prov_title": "Two digests, so a published figure cannot outlive its engine.",
        "prov_body": "A figure is reproducible only when what produced it can be identified. "
                     "The ground-truth digest pins the corpus; the engine digest covers every "
                     "module that can change what the measured run emits. A published figure "
                     "outliving the code it came from is not hypothetical here: it occurred, "
                     "with every gate green, because nothing compared the result to the engine. "
                     "A gate does now.",
        "prov_foot": "Recomputing the ground-truth digest on Windows gives a different value for "
                     "an identical corpus — it hashes raw bytes and joins paths with the "
                     "platform separator, so CRLF and backslashes each change it. Normalise to "
                     "LF with forward slashes and it reproduces exactly.",
        "prov_gt": "Ground truth",
        "prov_engine": "Engine",
        "prov_bench": "Benchmark",
        "prov_tier": "Tier",
        "prov_reverified": "Re-verified",

        "repro_kicker": "Reproduce it",
        "repro_title": "About fifteen minutes, end to end.",
        "repro_body": "Nothing here is computed by this repository. `run.py` writes Semgrep-format "
                      "JSON and the benchmark's own scorer is the authority — a tool that grades "
                      "itself against someone else's corpus has reintroduced exactly the problem "
                      "the corpus was there to solve. The full 62-repository scan is 1.4 minutes; "
                      "the rest is cloning.",
        "repro_notes_title": "Four notes, so the next run does not rediscover them",
        "repro_foot": "Four of the {rv_repos_total} repositories cannot be cloned at all, so any "
                      "reproduction lands on {rv_repos} the same way this one did.",

        "cav_kicker": "What this does not say",
        "cav_title": "Three things this number is not.",
        "cav_foot": "None of these is a caveat added after the fact. Each one is a bound this "
                    "measurement has had from the first run, and the report the tool writes "
                    "states its own bounds the same way.",

        "bcta_title": "Read the code that produced it.",
        "bcta_body": "The scorer output is committed, the harness is one command, and the CI "
                     "gate fails the build if a figure on this page stops matching the raw "
                     "result.",
        "bcta_install": "Install it",
        "bcta_home": "Back to the overview",
    },
    "tr": {
        "lang": "tr",
        "page_title": "Dış sayı — SecAudit'in RealVuln sonucu",
        "page_description": "SecAudit'in deterministik katmanı, Real-Vuln-Benchmark üzerinde "
                            "kıyaslamanın kendi puanlayıcısıyla: F3 {rv_f3}, "
                            "{rv_repos_total} deponun {rv_repos} tanesinde.",

        "bench_eyebrow": "RealVuln {rv_bench_version} · Tier 0 · {rv_date} koşusu",
        "bench_h1_1": "Başkasının veri kümesi,",
        "bench_h1_2": "başkasının puanlayıcısı.",
        "bench_lede": "{rv_repos} gerçek depoda {rv_labels} etiketli zafiyet; hiçbiri burada "
                      "etiketlenmedi, hiçbiri burada puanlanmadı. Bu sayfa sonucun tamamı — "
                      "gurur verici olmayan kısımlar dahil: hâlâ sıfıra yakın duran dört aile, "
                      "etiketli hiçbir şeyin bulunamadığı {rv_zero_repos} depo ve bu sayının üç "
                      "tur önce kör olmaktan çıktığı açıklaması.",
        "bench_cta_bench": "Kıyaslama deposu",
        "bench_cta_raw": "Ham puanlayıcı çıktısı",
        "bench_note": "{rv_scanner} · {rv_tier} — ağ yok, API anahtarı yok, ücretli plan yok.",
        "bench_matrix_head": "result.json · genel (micro)",
        "bench_matrix_right": "{rv_labels} etiket",
        "gap_blind": "kör — çekirdek bu veri kümesini okumamıştı",
        "gap_now": "şimdi, veri kümesine bakılarak geçen üç turun ardından",
        "bench_matrix_foot": "Aynı puanlayıcı, aynı koşunun daha katı bir okumasını da veriyor: "
                             "F3 {rv_strict_f3}, recall {rv_strict_recall}; aynı {rv_tp} doğru "
                             "pozitif üzerinde {rv_strict_extra} etiketi daha kaçırılmış "
                             "sayarak. Bu koşunun dürüst aralığı {rv_strict_f3} – {rv_f3}. "
                             "`micro` alıntılanıyor çünkü kıyaslamanın kendi referans "
                             "değerleri bu agregada yayımlanmış; başka her amaç için "
                             "kullanılacak rakam {rv_strict_f3}.",
        "label_f3": "F3 (recall × 9)",
        "label_f2": "F2",
        "label_precision": "precision",
        "label_recall": "recall",
        "label_tp": "doğru pozitif",
        "label_fp": "yanlış pozitif",
        "label_fn": "kaçırılan",
        "label_tn": "doğru negatif",

        "disc_kicker": "Açık beyan",
        "disc_tag": "sayıyı aktarmadan önce okuyun",
        "disc_title": "Bu sayı kör değil ve üç turdur kör değil.",
        "disc_sub": "İlk iki koşu kördü: çekirdek bu veri kümesini hiç görmemişti ve okumadığı kod "
                    "üzerinde aldığı skor {rv_blind_f3} idi. Sonraki her koşu, kıyaslamanın "
                    "kendi yanlış negatifleri okunup eksik kurallar yazıldıktan sonra ölçüldü.",
        "disc_note": "Eklenen kuralların tamamı, herhangi bir SAST aracının zaten içerdiği "
                     "türdendir — token için zayıf PRNG, çerez bayrakları, CSRF muafiyetleri, "
                     "commit'lenmiş yedek imza anahtarı, açık yönlendirme, loglara düşen kimlik "
                     "bilgileri — yani hiçbiri belirli bir fixture'a göre şekillendirilmemiştir. "
                     "Ancak seçim üç kez veri kümesine bakılarak yapılmıştır ve avantaj birikmektedir. "
                     "{rv_blind_f3} ile {rv_f3} arasındaki fark bu avantajın büyüklüğüdür. "
                     "Görülmemiş bir kod tabanı için temkinli rakam {rv_blind_f3}'tir; bu "
                     "ölçümün dürüst devamı, bu deponun hiç görmediği bir kıyaslamadır.",
        "runs2_kicker": "Koşu geçmişi",
        "runs2_tag": "tek veri kümesi, {rv_runs} koşu",
        "runs2_title": "Her turun skoru ve o skorun maliyeti.",
        "runs2_sub": "Aynı veri kümesi, aynı puanlayıcı, aynı klon. Her tur önce bir önceki çekirdeği "
                     "güncel checkout üzerinde yeniden puanlıyor ve commit'lenmiş rakamlarını "
                     "hane hane yeniden üretiyor; hareketi veri kümesine değil çekirdeğe bağlayan şey bu.",
        "runs2_caveat": "İlkinden sonraki her turda precision, recall ile birlikte yükseliyor. "
                        "Depo bunu “bunlar kural, eğri uydurma değil” sinyali sayıyor; "
                        "precision'ın düştüğü bir tur ise kuralı korumak yerine durup daraltma "
                        "sinyalidir.",
        "col_round": "Tur",
        "col_matrix": "TP / FP / FN",
        "runs_first_label": "ilk koşu — kör; çekirdeğin okumadığı bir veri kümesi üzerinde",

        "base_kicker": "Referans değerler",
        "base_title": "Kıyaslamanın kendi yayımladığı rakamlara karşı.",
        "base_sub": "RealVuln her kategori için en iyi bildirilen rakamı yayımlar. Aşağıdaki "
                    "dört satırın üçü RealVuln'a aittir; kalın olan satır bu çekirdektir ve aynı "
                    "veri kümesinde, aynı puanlayıcıyla ölçülmüştür. Bu sayfadaki her rakam "
                    "puanlayıcının kendi biriminde bırakılmıştır — F3 0–100 aralığında, "
                    "precision ve recall kesir olarak — böylece satırlar yayımlanmış tabloyla "
                    "karşılaştırılabilir kalır. Ana sayfa aynı ölçümleri baştan sona yüzde "
                    "olarak verir.",
        "base_note": "Kural tabanlı SAST'ın üzerinde, her iki metrikte de; genel amaçlı bir "
                     "modelin ve amaca özel sistemin ise çok altında — ve o ikisi, bunun artık "
                     "ölçülmediği biçimde ölçülmüştü. Doğru iddia “{rv_sast_name}'ten iyi” "
                     "değil, “sonradan okuduğumuz bir veri kümesinde {rv_sast_name}'in üzerinde”.",
        "col_category": "Kategori",
        "col_system": "En iyi bildirilen",

        "fam_kicker": "Recall nereye gidiyor",
        "fam_title": "Her aile, en büyük etiket havuzu önce.",
        "fam_sub": "Sıralama, çubuklardan daha önemli: en üstteki dört aile veri kümesindeki bütün "
                   "etiketlerin yarısından fazlasını tutuyor ve bu katmanın en kötü olduğu dört "
                   "aile de onlar. Bir skoru büyük havuzlar belirler, tarayıcının kolay bulduğu "
                   "havuzlar değil.",
        "fam_note": "Desen sınıfları tavanına yakın — komut enjeksiyonu, açık yönlendirme, kod "
                    "enjeksiyonu ve XXE hepsi %80'in üzerinde. Skoru belirleyen havuzlar ise "
                    "desen sınıfı değil: `sensitive_data_exposure` ve "
                    "`security_misconfiguration` etiketlerinin yaklaşık 130'u bir fonksiyon "
                    "tanımının üzerinde duruyor — `broken_access_control` ve `missing_auth` ile "
                    "aynı biçim. Bunlar başka bir kural değil, iş mantığı geçişi istiyor ve "
                    "burada eklenen hiçbir kural onlara dokunmadı.",

        "repo_kicker": "Depo bazında",
        "repo_tag": "{rv_repos_total} deponun {rv_repos} tanesi",
        "repo_title": "Hepsi, en iyiden başlayarak — hiçbir şey bulunamayanlar dahil.",
        "repo_sub": "F3'e göre sıralı. İlk beş yerine tamamı yayımlanıyor; çünkü bu projenin "
                    "kendi sayfasındaki ilk beş, puanlayıcı çıktısıyla karşılaştırılana kadar "
                    "iki tur bayattı ve kimsenin denetlemediği bir sıralama kendini kayırır.",
        "repo_note": "{rv_repos} deponun {rv_zero_repos} tanesi 0.0 aldı; ikisinde de "
                     "etiketli hiçbir bulgu tespit edilmedi. Her ikisi de tablonun sonunda yer "
                     "alır. Aşağıdaki gerekçe kıyaslama deposundan birebir alındığı için "
                     "İngilizcedir: çevrilmiş bir kopya, kaynak değiştiğinde sessizce yanlış "
                     "hâle gelirdi.",
        "repo_missing_title": "Neyin puanlanmadığı ve bunun neden önemli olduğu",
        "col_repo": "Depo",

        "sb_kicker": "Diğer dil",
        "sb_tag": "iki koşu",
        "sb_title": "JavaScript tarafı ne yapıyor — ve bunu okumadan önce ne yapıyordu.",
        "sb_sub": "Yukarıdaki her rakam Python'ı anlatıyor. Bu rakam JavaScript'i anlatıyor ve "
                  "iki kez ölçüldü. İlk koşu kördü — bu çekirdekteki hiçbir kural o an bu "
                  "kıyaslamanın etiketleri okunarak yazılmamış ya da seçilmemişti — ve {sb_blind_recall} "
                  "aldı. Hiç görülmemiş kodun rakamı odur ve iyileşmez. Kör koşunun getirdiği şey "
                  "bir teşhis oldu; buradaki sayı ona göre hareket edildikten sonraki sayı. İki "
                  "veri kümesi hiçbir yönde kıyaslanamaz — o veri kümesi uygulamalardan, bu veri kümesi "
                  "kütüphanelerden oluşuyor ve bir kütüphanenin, erişilebilirlik analizinin "
                  "başlayabileceği bir istek işleyicisi yoktur.",
        "sb_panel_head": "SecBench.js",
        "sb_panel_right": "{sb_date}",
        "sb_label_found": "bulunan sink",
        "sb_label_sinks": "etiketli sink",
        "sb_label_pkgs": "npm paketi",
        "sb_panel_foot": "Burada sağlam olan metrik recall ve yayınlanan tek metrik o. Kıyaslama "
                         "paket başına tek bir açık etiketliyor ve paketin geri kalanı hakkında "
                         "hiçbir şey söylemiyor; dolayısıyla eşleşmeyen bulgu oranı bir precision "
                         "değil, gürültü için bir alt sınır olurdu — onu yukarıdaki rakamın yanına "
                         "koymak, adı aynı olan iki farklı ölçümü kıyaslamak olurdu.",
        "sb_note": "Kör koşu üç şey söyledi; her biri şuna dönüştü. ReDoS sıfır almıştı çünkü o "
                   "analiz yalnızca Python içindi — tek bir paket çekilmeden önce yol haritasına "
                   "yazıldı ki sonradan bir keşif gibi sunulamasın; artık JavaScript de okuyor ve "
                   "8/87, üstel geri izlemeyi tarif eden kriterlerin, gerçek raporların çoğunun "
                   "polinomiyal olduğu bir dünyadaki dürüst karşılığı. Prototype pollution hâlâ "
                   "en kötü sınıf, ama dokuzu bulan kural emekliye ayrıldı; yerine döngüyü değil "
                   "yazma işlemini raporlayan bir analiz geldi. Ve `dist/` ya da `build/` "
                   "altındaki 35 sink için \"tespit hatası değil, kapsam kararı\" denmişti — çekirdek "
                   "artık paketin kendi manifesti oraları yayınlıyorsa okuyor, 29'u erişilebilir "
                   "oldu ve ikisi bulundu. O iddia işin gurur okşayan yarısıydı ve yanlıştı.",
        "prov_kicker": "Köken",
        "prov_title": "İki digest, bir rakamın üretildiği çekirdekten uzun yaşamasını "
                      "engeller.",
        "prov_body": "Bir sayı, ancak onu neyin ürettiğini söyleyebiliyorsanız tekrar "
                     "üretilebilirdir. Ground-truth digest'i veri kümesini sabitler; engine digest'i "
                     "ölçülen koşunun çıktısını değiştirebilecek her modülü kapsar. "
                     "Yayımlanmış bir rakamın onu üreten koddan uzun yaşaması burada varsayım "
                     "değil — bütün kapılar yeşilken gerçekten oldu, çünkü hiçbir şey sonucu "
                     "çekirdekle karşılaştırmıyordu. Artık bir kapı karşılaştırıyor.",
        "prov_foot": "Ground-truth digest'inin Windows'ta yeniden hesaplanması, birebir aynı "
                     "veri kümesi için farklı bir değer üretir: ham baytlar hash'lenir ve yollar "
                     "platform ayracıyla birleştirilir, yani hem CRLF hem de ters bölü sonucu "
                     "değiştirir. LF'ye normalleştirme ve düz bölü kullanımıyla değer birebir "
                     "yeniden üretilir.",
        "prov_gt": "Ground truth",
        "prov_engine": "Çekirdek",
        "prov_bench": "Kıyaslama",
        "prov_tier": "Katman",
        "prov_reverified": "Yeniden doğrulandı",

        "repro_kicker": "Tekrarlama",
        "repro_title": "Baştan sona yaklaşık on beş dakika.",
        "repro_body": "Buradaki hiçbir şeyi bu depo hesaplamıyor. `run.py` Semgrep formatında "
                      "JSON yazar ve otorite kıyaslamanın kendi puanlayıcısıdır — kendini "
                      "başkasının veri kümesine göre notlandıran bir araç, o veri kümesinin çözmek için "
                      "var olduğu problemi geri getirmiş olur. 62 deponun tam taraması 1,4 "
                      "dakika; gerisi klonlama.",
        "repro_notes_title": "Bir sonraki koşunun yeniden keşfetmemesi için dört not",
        "repro_foot": "{rv_repos_total} deponun dördü hiç klonlanamıyor; dolayısıyla her tekrar "
                      "üretim, bunun indiği yere — {rv_repos} depoya — iner.",

        "cav_kicker": "Bu sayının söylemedikleri",
        "cav_title": "Bu rakamın olmadığı üç şey.",
        "cav_foot": "Bunların hiçbiri sonradan eklenmiş bir çekince değil. Her biri bu ölçümün "
                    "ilk koşudan beri taşıdığı bir sınır — ve aracın yazdığı rapor da kendi "
                    "sınırlarını aynı şekilde belirtir.",

        "bcta_title": "Rakamı üreten kodu inceleyin.",
        "bcta_body": "Puanlayıcı çıktısı depoda commit'lidir, koşum tek komuttur ve bu "
                     "sayfadaki bir rakam ham sonuçla uyuşmadığında CI kapısı derlemeyi "
                     "durdurur.",
        "bcta_install": "Nasıl kurulur",
        "bcta_home": "Genel bakışa dön",
    },
}

# The three bounds, quoted from `eval/realvuln/README.md` § "Three things this does not say".
BENCH_CAVEATS = {
    "en": [
        ("It is not a measurement of the LLM tier",
         "Tier 1 is the tier meant to reach the classes the deterministic one structurally "
         "cannot. Measuring it needs paid inference across every repository here, and it is a "
         "stated non-goal rather than backlog. The tier ships off by default and the claim was "
         "narrowed instead."),
        ("It is not a measurement of the JavaScript engine",
         "RealVuln v1 is Python-only. The structural analyses grew a JavaScript/TypeScript front "
         "end, so the same four questions are now asked of both languages and only one of the "
         "two answers has ever been scored by someone else. The JS side ships as a regression "
         "floor, not as a score."),
        ("Not a claim about any other repository",
         "The families holding most of the labels are the ones still near zero, and no pattern "
         "added here touches them. A corpus of deliberately vulnerable applications is not the "
         "shape of a production codebase either — in both directions."),
    ],
    "tr": [
        ("LLM katmanının ölçümü değil",
         "Tier 1, deterministik katmanın yapısal olarak ulaşamadığı sınıflara ulaşması beklenen "
         "katman. Ölçmek buradaki her depo için ücretli çıkarım gerektiriyor ve bu, backlog "
         "değil açıkça belirtilmiş bir hedef-dışı. Katman varsayılan kapalı geliyor; onun yerine "
         "iddia daraltıldı."),
        ("JavaScript çekirdeğinin ölçümü değil",
         "RealVuln v1 yalnızca Python. Yapısal analizler bir JavaScript/TypeScript ön ucu "
         "kazandı; artık aynı dört soru iki dile de soruluyor ama iki cevaptan yalnızca biri "
         "başkası tarafından puanlandı. JS tarafı skor olarak değil, regresyon tabanı olarak "
         "geliyor."),
        ("Başka bir depo hakkında bir iddia değil",
         "Etiketlerin çoğunu tutan aileler hâlâ sıfıra yakın olanlar ve burada eklenen hiçbir "
         "desen onlara dokunmuyor. Kasten zafiyetli uygulamalardan oluşan bir veri kümesi, üretim "
         "kod tabanının biçimi de değil — iki yönde birden."),
    ],
}

# The four reproduction gotchas, each one found by doing it rather than by reading the docs.
REPRO_NOTES = {
    "en": [
        "`score.py` takes `--repo` and scores one repository at a time. There is no "
        "`--all-repos` flag.",
        "Windows needs `PYTHONUTF8=1`, or the scorer aborts writing its own markdown report "
        "under a non-UTF-8 console codepage.",
        "Scoring a second scanner overwrites the per-repo scorecards for the same date. The "
        "previous set has to be captured before the next scanner is scored.",
        "`compute_gt_hash.py` disagrees with the published digest on Windows for an identical "
        "corpus. Normalise to LF with forward slashes and it matches — the first reading says "
        "the ground truth moved, which would mean no run is comparable to any other.",
    ],
    "tr": [
        "`score.py` `--repo` alır ve tek seferde tek depo puanlar. `--all-repos` diye bir "
        "bayrak yok.",
        "Windows'ta `PYTHONUTF8=1` gerekir; yoksa puanlayıcı UTF-8 olmayan konsol kod "
        "sayfasında kendi markdown raporunu yazarken durur.",
        "İkinci bir tarayıcıyı puanlamak, aynı tarihe ait depo bazlı skor kartlarının üzerine "
        "yazar. Önceki set, bir sonraki tarayıcı puanlanmadan önce alınmalıdır.",
        "`compute_gt_hash.py` Windows'ta, birebir aynı veri kümesi için yayımlanmış digest ile "
        "uyuşmaz. LF'ye normalleştirme ve düz bölü kullanımıyla uyuşur; ilk okuma ground truth'un "
        "değiştiğini söyler ki bu, hiçbir koşunun bir diğeriyle kıyaslanamayacağı anlamına "
        "gelirdi.",
    ],
}


# The run history is the one table on this site whose text comes out of `result.json` rather than
# out of this file, and `result.json` is written in English because it is the record a benchmark
# maintainer reads. That left the Turkish page rendering twenty-nine English sentences inside a
# translated table — the one place where the language switch stopped switching.
#
# Keyed on the English label, and **missing a key fails the build** (`gen_site.py` raises rather
# than falling back). A silent fallback is what produced the problem in the first place: it looks
# finished on the day it is written and rots one round later, in the language its author does not
# read. One line per round is the cost of the table being in the reader's language.
RUN_LABELS_TR = {
    "targeted at the first run's diagnosis, still blind to the rest of the corpus":
        "ilk koşunun teşhisine yönelik; veri kümesinin geri kalanına hâlâ kör",
    "the configuration and crypto-hygiene round, corpus-informed":
        "yapılandırma ve kripto hijyeni turu, veri kümesine bakılarak",
    "the first structural round — authorization and ReDoS":
        "ilk yapısal tur — yetkilendirme ve ReDoS",
    "structural analyses: rate limiting, uploads, mass assignment":
        "yapısal analizler: hız sınırı, yüklemeler, toplu atama",
    "rate-limit rule narrowed (F3 31.5)":
        "hız sınırı kuralı daraltıldı (F3 31.5)",
    "language families, vendored assets, template XSS, Python SQL":
        "dil aileleri, vendor'lanmış dosyalar, şablon XSS, Python SQL",
    "vendored-asset filter":
        "vendor'lanmış dosya filtresi",
    "JavaScript round: ReDoS front end, prototype-pollution rewrite, published build output":
        "JavaScript turu: ReDoS ön yüzü, prototype pollution yeniden yazımı, yayımlanan build "
        "çıktısı",
    "prototype pollution: only a key the caller chose":
        "prototype pollution: yalnızca çağıranın seçtiği bir anahtar",
    "pathlib: the sink library nothing modelled":
        "pathlib: hiçbir şeyin modellemediği sink kütüphanesi",
    "req.url: the Node source nothing modelled":
        "req.url: hiçbir şeyin modellemediği Node kaynağı",
    "the 2026-08-16 round, re-measured: 273 false positives, not 271":
        "2026-08-16 turu, yeniden ölçüldü: 271 değil 273 yanlış pozitif",
    "quadratic ReDoS, and the JavaScript pattern reported where it runs":
        "karesel ReDoS ve JavaScript deseninin çalıştığı yerde raporlanması",
    "prototype pollution: the functions nobody could delimit, the callback's key, and the walk":
        "prototype pollution: kimsenin sınırlayamadığı fonksiyonlar, callback'in anahtarı ve "
        "ağaç gezinmesi",
    "import-resolved shell and vm receivers":
        "import ile çözümlenen shell ve vm alıcıları",
    "Config + credentials":
        "Yapılandırma + kimlik bilgileri",
    "Nine rule families the corpus had none for":
        "Veri kümesinin hiç karşılığı olmayan dokuz kural ailesi",
    "Django views stop being public by default":
        "Django view'ları artık varsayılan olarak herkese açık sayılmıyor",
    "The Secure cookie flag the HttpOnly rule was hiding":
        "HttpOnly kuralının gizlediği Secure çerez bayrağı",
    "HTML built by concatenation, which is where the JavaScript XSS labels live":
        "Birleştirmeyle kurulan HTML — JavaScript XSS etiketlerinin yaşadığı yer",
    "PHP gets an instrument, and the instrument finds three broken rules":
        "PHP bir ölçüm aracı kazandı ve araç üç bozuk kural buldu",
    "PHP superglobal rules — the source is spelled in the sink":
        "PHP superglobal kuralları — kaynak, sink'in içinde yazılı",
    "A suppression that reads the line, not the file":
        "Dosyayı değil satırı okuyan bir susturma",
    "A vendored library does not arrive as one file":
        "Vendor'lanmış bir kütüphane tek dosya olarak gelmez",
    "PHP taint — one assignment hop, one file":
        "PHP taint — tek atama sıçraması, tek dosya",
    "Three structural questions JavaScript could not be asked":
        "JavaScript'e sorulamayan üç yapısal soru",
    "A real application in the noise floor, and two defects it found":
        "Gürültü tabanında gerçek bir uygulama ve bulduğu iki kusur",
    "SSRF reaches the ordinary HTTP surface; four spellings of the debug switch":
        "SSRF sıradan HTTP yüzeyine ulaşıyor; debug anahtarının dört yazımı",
    "The framework's own login: a route with no handler to read":
        "Framework'ün kendi login'i: okunacak handler'ı olmayan bir rota",
}
