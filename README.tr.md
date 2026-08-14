<div align="center">

# 🛡️ SecAudit — Yetkili Güvenlik Denetim Kiti

**Claude'u bir URL'ye ya da bir kod tabanına yöneltin. Önceliklendirilmiş, düzeltme odaklı bir
güvenlik raporu alın.**

Bilinen (CVE / bağımlılık) **ve** bilinmeyen (mantık / kod) zafiyetleri OWASP Web, API, LLM ve
Mobile Top 10 ile CWE Top 25 boyunca bulur — kurulu tarayıcıları varsa onları, yoksa Claude'un
analizini kullanarak.

**English:** [README.md](README.md)

</div>

---

> ⚠️ **Yalnızca savunma amaçlı.** SecAudit **sahibi olduğunuz veya test etmeye açıkça yetkili
> olduğunuz** sistemleri denetlemek içindir. Varsayılanı güvenli/pasif kontrollerdir; aktif test
> için yetkiyi beyan etmeniz gerekir. Silahlandırılmış exploit, zararlı yazılım, DoS yükü veya
> yetkisiz erişim aracı üretmez.

## 15 saniye

```bash
# Claude Code içinde — plugin, canlı hedef izi ve yetkilendirme kapısıyla:
/plugin marketplace add mtvrkan/secaudit && /plugin install secaudit
/secaudit .

# Ya da Claude Code olmadan — aynı motor; LLM yok, ağ yok, bağımlılık yok:
pip install secaudit-kit && secaudit .
```

## Bir cümlede farkı

> **SecAudit, başkasına verebileceğiniz denetimdir.**
> Anthropic'in kendi eklentisi Claude'un *yazdığı* kodu güvenli tutar. SecAudit şunu yanıtlar:
> *"bu ürün güvenli mi, kanıtlayabilir miyim, ve bir düzenleyiciye ne borçluyum?"* — çalışan bir
> hedef için de, bir depo için de; Claude Code ile ya da onsuz; ölçülmüş bir tespit tabanıyla ve
> sonunda teslim edilebilir bir belgeyle.

## İki sayı, ikisi de doğru

| | Ne ölçtüğü | Sonuç |
|---|---|---|
| **Kendi korpusu** | Regresyon tabanı — fixture'lar dedektörlerle birlikte yazıldı | Recall **%98** (61/62), 15 dil, F3 **0.986** |
| **RealVuln** (dış, Tier 0) | 66 reponun 62'si, kıyaslamanın kendi skorlayıcısı | F3 **31.5**, precision **0.542**, recall **0.301** |

RealVuln'da kural tabanlı SAST'ın yayınlanmış skoru **17.7**. SecAudit her iki metrikte de onun
üzerinde; genel amaçlı bir LLM'in **51.7**'sinin ve amaca özel sistemin **73.0**'ının ise
belirgin şekilde altında.

**Bunu aktarırken düşülmemesi gereken kayıt:** ilk iki ölçüm (12.5 ve 13.3) kördü — motor bu
korpusu hiç görmemişti. Sonraki turlar kıyaslamanın kendi false negative'leri okunduktan sonra
ölçüldü. Eklenen her kural herhangi bir SAST'ın gönderdiği ders kitabı kuralı, yani hiçbir şey bir
fixture'a uydurulmadı; ama *seçim* korpus bilgisiyle yapıldı. Dürüst devamı, bu deponun okumadığı
bir kıyaslamadır. Ayrıntı: [`eval/realvuln/README.md`](eval/realvuln/README.md).

## Ne alıyorsunuz

- 🎯 **Tek komut, iki kip** — canlı bir **URL** ya da bir **kaynak kod deposu** (ya da ikisi
  birden, çapraz doğrulamayla).
- 🔗 **Erişilebilirlik, sadece kalıp eşleme değil** — dahili taint motoru güvenilmeyen girdiyi
  kaynaktan sink'e kadar izler; `db.query(sql)` yalnızca `sql` gerçekten `req.query.name`'den
  kurulduysa raporlanır, sorgu parametresi olarak bağlandığında raporlanmaz. Her bulgu
  izleyebileceğiniz — ve çürütebileceğiniz — yolu taşır.
- 📦 **Bağımlılık uyarılarına karar, döküm değil** — her CVE import erişilebilirliğine göre bir
  [OpenVEX](https://github.com/openvex/spec) durumuna sınıflanır (`affected` / `not_affected` /
  `under_investigation`) ve kararın gerekçesi yazılır. Hiçbir şey silinmez: filtrelenmiş bir
  kayıt defteri kanıt değildir.
- 🇪🇺 **Aynı taramadan EU CRA kanıt paketi** — `--format cra`; CycloneDX 1.6 SBOM, VEX durumlu
  zafiyet kayıt defteri ve her bulgunun ilgili maddeye eşlenmesi. Zafiyet yönetimi yükümlülükleri
  **2026-09-11**'de başlıyor.
- ⏱️ **Sürekli izleme** — `--watch`: dünyayı son çalıştırmaya göre kıyaslar ve hâlihazırda sevk
  ettiğiniz bir bağımlılık **aktif olarak sömürülmeye** başladığında haber verir. CRA'nın 24 saatlik
  erken uyarı tetiği tam olarak budur. Beslemeye ulaşılamayan bir çalıştırma "değişiklik yok"
  demez; hiçbir şey saptayamadığını söyler ve hata koduyla döner.
- 📋 **Uyum eşlemesi** — OWASP ASVS 5.0 (bölüm), EU CRA (madde), PCI DSS 4.0.1 (dört gereksinim).
  SOC 2 ve ISO 27001 **bilerek eşlenmedi**: kontrol metinleri telif/ödeme duvarı arkasında, yani
  eşleme yalnızca kimsenin doğrulayamayacağı numaralara işaret ederdi.
- 🧪 **Doğrulanmış yama döngüsü** — `--suggest-patches`: model önerir, deterministik motor kefil
  olur (yama tek kullanımlık kopyaya uygulanır, kopya yeniden taranır), bağımsız bir gözden
  geçirici veto hakkına sahiptir. Hiçbir şey otomatik uygulanmaz.
- 🔌 **MCP sunucusu** — Codex, Cursor, OpenCode ve her MCP istemcisi aynı motora ulaşır.

## Yetkilendirme — pazarlık konusu değil

Canlı bir hedefe karşı **aktif** test, deterministik bir PreToolUse kancasının arkasındadır.
Temiz yol, hedef depoda bir `scope.yaml` oluşturmaktır: sahip, onay, kapsamdaki alan adları, test
hesapları, hariç tutulan yollar, hız sınırları. Dosya **izlenmemiş** bırakılır — kanca
commit'lenmiş bir `scope.yaml`'ı reddeder, çünkü bir clone ile gelen dosya bu operatörün yaptığı
bir beyan değildir.

Pasif kontroller (kaynak kod okuma, bağımlılık/SBOM/secret/SAST taraması, normal bir tarayıcının
yapacağı `GET` istekleri) yetki gerektirmez.

## Neyi kaçırdığı

[`docs/what-we-miss.md`](docs/what-we-miss.md) — motorun kendisinden üretilir, elle yazılmaz.
Temiz bir raporu her şeyin yolunda olduğunun kanıtı saymadan önce okuyun. Elle bakımı yapılan bir
sınırlılık sayfası bir sürüm boyunca doğrudur, sonra sessizce eksik beyana dönüşür.

## Belgeler

- 🌐 [secaudit.mtvrkan.com](https://secaudit.mtvrkan.com) — açılış sayfası (EN / TR)
- [Başlangıç](docs/getting-started.md) · [Yetkilendirme ve kapsam](docs/authorization.md)
- [Canlı URL kipi](docs/live-url-mode.md) · [Kaynak kod kipi](docs/source-code-mode.md)
- [Sürekli izleme](docs/continuous-mode.md) · [Uyum eşlemesi](docs/compliance.md)
- [CI'da çalıştırma](docs/ci.md) · [MCP sunucusu](docs/mcp.md)
- [Kurulumu doğrulama](docs/supply-chain.md) — her sürümde derleme kanıtı ve SBOM attestation'ı
- [Dil kapsamı](docs/language-coverage.md) · [Diff kipi](docs/diff-mode.md)

## Lisans

MIT. Ayrıntı: [LICENSE](LICENSE) ve [LICENSING.md](LICENSING.md).
