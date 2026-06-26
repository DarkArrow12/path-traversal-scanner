"""Auto-discover mode (demo): find file-ish query params on a page, scan each."""
import re

import requests

from scanner import scan, load_targets

FILEISH = ["file", "path", "page", "doc", "img", "image", "template", "lang", "download"]


def find_params(html: str, base_url: str) -> list:
    params = []
    for q in re.findall(r"[?&]([a-zA-Z0-9_]+)=", html):
        if q not in params:
            params.append(q)
    # rank: file-ish names first
    params.sort(key=lambda p: 0 if any(k in p.lower() for k in FILEISH) else 1)
    return params


def auto_discover(args) -> int:
    from traverse import build_session  # local import avoids circular import
    session = build_session(args.cookie, args.header)
    print(f"[*] Fetching {args.auto} to discover parameters...")
    resp = session.get(args.auto, timeout=15)
    params = find_params(resp.text, args.auto)
    if not params:
        print("[-] No candidate parameters found.")
        return 1
    print(f"[*] Candidate params: {', '.join(params)}")
    targets = load_targets("targets.json", args.os)
    for param in params:
        sep = "&" if "?" in args.auto else "?"
        template = f"{args.auto.split('?')[0]}{sep}{param}=FUZZ"
        print(f"\n[*] Testing param '{param}' -> {template}")
        hits = scan(session, template, depth=args.depth, delay=args.delay,
                    stop_on_first=True, os_filter=args.os, targets=targets)
        if hits:
            print(f"[+] HIT via '{param}': {hits[0]['payload']}")
            return 0
    print("[-] No traversal found on discovered params.")
    return 1
