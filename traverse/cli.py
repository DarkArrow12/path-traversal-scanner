"""traverse — path traversal, file inclusion, and LFI-to-RCE testing toolkit.

AUTHORIZED USE ONLY. Run this only against systems you own or are explicitly
permitted to test (PortSwigger/THM/HTB labs, CTFs, your own rigs).
"""
import argparse
import sys
from pathlib import Path

from .scanner import scan, load_targets, run_wrapper
from .transport import build_session  # noqa: F401 (re-export)
from . import report

BANNER = "traverse — path traversal & file inclusion toolkit | AUTHORIZED TARGETS ONLY"


def build_parser():
    p = argparse.ArgumentParser(
        description=BANNER,
        epilog="Use only against systems you are authorized to test.")
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("-u", "--url", help="Target URL with a FUZZ marker, e.g. ?filename=FUZZ")
    mode.add_argument("-a", "--auto", help="Auto-discover mode: crawl URL for file-ish params (demo)")
    p.add_argument("--param", help="Parameter to inject into (appends =FUZZ if URL has no marker)")
    p.add_argument("--data", help="POST body template with a FUZZ marker, e.g. 'file=FUZZ'")
    p.add_argument("--json", dest="json_body",
                   help="JSON body template with a FUZZ marker, e.g. '{\"path\":\"FUZZ\"}'")
    p.add_argument("--method", help="HTTP method (default: GET, or POST when --data/--json given)")
    p.add_argument("--target-file", help="Specific file to read (default: built-in library)")
    p.add_argument("--signature", help="Detection regex for --target-file (default: /etc/passwd marker)")
    p.add_argument("--wrapper", choices=["filter", "data", "expect", "input"],
                   help="File-inclusion wrapper mode (needs --resource or --cmd)")
    p.add_argument("--resource", help="File to read via --wrapper filter, e.g. index.php")
    p.add_argument("--cmd", help="Command to run via --wrapper data/expect/input, e.g. id")
    p.add_argument("--os", choices=["linux", "windows", "both"], default="both")
    p.add_argument("--categories", help="Comma-separated target categories: poc,secrets,config,cloud,source")
    p.add_argument("--depth", type=int, default=8)
    p.add_argument("--null-exts", help="Comma-separated null-byte extensions, e.g. '.md,.pdf'")
    p.add_argument("--cookie", help="Cookie header, e.g. 'session=abc123'")
    p.add_argument("--header", action="append", default=[], help="Extra header 'Name: value' (repeatable)")
    p.add_argument("--delay", type=float, default=0.3)
    p.add_argument("--threads", type=int, default=1, help="Concurrent requests (default 1; opsec)")
    p.add_argument("--all", action="store_true", help="Don't stop at first HIGH hit")
    p.add_argument("--output", choices=["console", "json"], default="console")
    p.add_argument("--outfile", help="Write output to this file instead of stdout")
    p.add_argument("--loot-dir", default="./loot")
    p.add_argument("-v", "--verbose", action="store_true")
    return p




def _normalize_url(url, param):
    if "FUZZ" in url:
        return url
    if param:
        sep = "&" if "?" in url else "?"
        return f"{url}{sep}{param}=FUZZ"
    raise SystemExit("[!] URL has no FUZZ marker and no --param given.")


def main(argv=None):
    args = build_parser().parse_args(argv)
    # Keep JSON-to-stdout clean; still print the banner when writing to a file.
    if args.output != "json" or args.outfile:
        print(BANNER)
    if args.auto:
        from .discover import auto_discover
        return auto_discover(args)

    body_mode = bool(args.data or args.json_body)
    url = args.url if body_mode else _normalize_url(args.url, args.param)
    session = build_session(args.cookie, args.header)

    if args.wrapper:
        if args.wrapper == "filter" and not args.resource:
            raise SystemExit("[!] --wrapper filter requires --resource")
        if args.wrapper in ("data", "expect", "input") and not args.cmd:
            raise SystemExit(f"[!] --wrapper {args.wrapper} requires --cmd")
        hits = run_wrapper(session, url, args.wrapper, resource=args.resource,
                           cmd=args.cmd, method=args.method,
                           data_template=args.data, json_template=args.json_body)
    else:
        categories = [c.strip() for c in args.categories.split(",")] if args.categories else None
        targets = load_targets(os_filter=args.os, categories=categories)
        if args.target_file:
            sig = args.signature or "root:[x*]:0:0:"
            targets = [{"path": args.target_file, "os": args.os, "category": "user",
                        "signature": sig, "note": "user-specified"}]
        null_exts = [e.strip() for e in args.null_exts.split(",")] if args.null_exts else None

        hits = scan(session, url, depth=args.depth, delay=args.delay,
                    stop_on_first=not args.all, os_filter=args.os, targets=targets,
                    method=args.method, data_template=args.data,
                    json_template=args.json_body, null_exts=null_exts,
                    threads=args.threads)

    for h in hits:
        report.save_loot(args.loot_dir, h["target"], h["snippet"])

    if args.output == "json":
        out = report.render_json(hits, {"target": url})
    else:
        out = report.render_console(hits)
        if hits:
            out += f"\n[+] Loot saved to {args.loot_dir}/"

    if args.outfile:
        Path(args.outfile).write_text(out, encoding="utf-8")
        print(f"[+] Wrote {args.output} output to {args.outfile}")
    else:
        print(out)

    return 0 if hits else 1


if __name__ == "__main__":
    sys.exit(main())
