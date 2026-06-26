# traverse.py — Path Traversal Scanner

Automates file path traversal against a web target. Point it at a URL, it tries
every known bypass family, confirms the leak, and saves the file.

Implements the bypass families for all **6 PortSwigger "File path traversal" labs**
(verified live against the leading-path-validation lab; the remaining families are
unit-tested and map 1:1 to their labs — see the table below). Stretch goal: exfiltrate
readable files from Linux/Windows targets in CTFs and rooms.

## ⚠️ Authorized use only

This is an offensive security tool. Use it ONLY against systems you own or are
explicitly authorized to test — PortSwigger / TryHackMe / HTB labs, CTFs, and your
own rigs. Unauthorized use against third-party systems is illegal. The tool defaults
to a request delay and prints an authorization reminder in `--help`.

## Install

```bash
pip install -r requirements.txt   # just `requests` (+ pytest for the tests)
```

## Usage

```bash
# Targeted mode — mark the injection point with FUZZ
python traverse.py -u "https://LAB-ID.web-security-academy.net/image?filename=FUZZ" \
                   --cookie "session=YOUR_SESSION_TOKEN"

# Or name the parameter and let the tool add the marker
python traverse.py -u "https://site/image" --param filename

# Auto-discover mode (demo) — crawl the page, find file-ish params, test each
python traverse.py -a "https://site/gallery" --cookie "session=..."

# Help + authorization notice
python traverse.py --help
```

Always **quote the URL** — a bare `?` / `&` gets mangled by the shell.

### Key flags

| Flag | Meaning | Default |
|------|---------|---------|
| `-u, --url` | Target URL with a `FUZZ` marker | — |
| `-a, --auto` | Auto-discover params (demo) | — |
| `--param` | Param to inject into (adds `=FUZZ`) | — |
| `--target-file` | Read one specific file | built-in library |
| `--os` | `linux` / `windows` / `both` | `both` |
| `--depth` | Max `../` depth tried | `8` |
| `--cookie` | Session cookie, e.g. `session=abc` | — |
| `--header` | Extra header `Name: value` (repeatable) | — |
| `--delay` | Seconds between requests (opsec) | `0.3` |
| `--all` | Don't stop at first HIGH hit | off |
| `--loot-dir` | Where leaked content is saved | `./loot` |

## How it works (the part worth understanding)

Three small, single-purpose modules do the real work; everything else is glue.

**1. The bypass engine — `payloads.py`.** Given a target file (`/etc/passwd`) it
expands it into ~140 payloads across bypass *families*, each defeating a specific
defense. Encodings are applied **deliberately** on the canonical segments — we never
blindly re-quote an already-encoded string, because that would triple-encode it
(`%252e` → `%25252e`) and no server decodes that back to `.`.

| Family | Example | Defeats / PortSwigger lab |
|--------|---------|---------------------------|
| Basic traversal | `../../../etc/passwd` | naive — Lab 1 |
| Absolute path | `/etc/passwd` | strips `../` only — Lab 2 |
| Non-recursive | `....//....//etc/passwd` | single-pass strip — Lab 3 |
| Encoded (single+double) | `%252e%252e%252f…` | decode-then-filter — Lab 4 |
| Leading-path prefix | `/var/www/images/../../etc/passwd` | "must start with base" — Lab 5 |
| Null-byte extension | `../../../etc/passwd%00.png` | extension allowlist — Lab 6 |
| CTF extras | `..;/`, `file://`, Windows `..\` | reverse-proxy / Java / Windows |

**2. The detector — `detector.py`.** How it *knows* it worked, in three tiers:
- **HIGH** — the file's signature regex matched (e.g. `/etc/passwd` → `root:[x*]:0:0:`).
  This is certainty: that line only exists in a real passwd file.
- **MEDIUM** — the response diverges sharply from a *baseline* (we first request a junk
  filename to learn what "failure" looks like, then flag anything 3× longer or with a
  changed status). Catches blind leaks with no known signature.
- **NONE** — looks like the failure baseline.

**3. The target library — `targets.json`.** File paths + detection signatures live in
data, not code. Add a new target file and signature without touching the engine.

**4. The scanner — `scanner.py`.** The only networked module. Uses a
`requests.Session` so cookies/headers persist (PortSwigger tracks you by session
cookie), fires each payload with `--delay`, runs the detector, stops at the first HIGH
hit unless `--all`.

## Tests

Pure logic (engine + detector) is unit-tested offline — no network needed:

```bash
python -m pytest -q     # 22 tests
```

Live acceptance = launch a PortSwigger lab and run the targeted command above; expect
a HIGH hit printing a `root:x:0:0:` snippet and loot saved to `./loot/etc_passwd.txt`.

## Layout

```
traverse.py    CLI, session auth, reporting, loot saving
payloads.py    bypass engine (the families above)
detector.py    signature + baseline-diff confidence
scanner.py     networked sweep (requests.Session)
discover.py    auto-discover demo
targets.json   file + signature library (data, extensible)
tests/         offline unit tests
```

## Roadmap / not yet built

Proxy/SOCKS chaining, threaded sweeps, WAF-evasion timing, mass-host scanning. The
engine and detector are isolated behind clean interfaces so these bolt on without a
rewrite.
