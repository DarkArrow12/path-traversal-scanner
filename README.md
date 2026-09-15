# traverse

[![tests](https://github.com/DarkArrow12/path-traversal-scanner/actions/workflows/tests.yml/badge.svg)](https://github.com/DarkArrow12/path-traversal-scanner/actions/workflows/tests.yml)

A path traversal and file inclusion testing tool. Point it at a parameter, it
tries the known traversal bypass families, confirms which one leaks a file, and
saves what it read. Built for lab work and authorized assessments.

## Authorized use only

Offensive tool. Use it only against systems you own or are explicitly authorized
to test — PortSwigger / TryHackMe / HTB labs, CTFs, and your own targets.
Unauthorized use against third-party systems is illegal. Requests are delayed by
default and `--help` carries the same notice.

## Install

```bash
pip install -e .          # exposes the `traverse` command
# or run without installing:
python -m traverse --help
```

Only runtime dependency is `requests`. Tests need `pytest` (`pip install -e ".[dev]"`).

## Usage

Mark the injection point with `FUZZ`:

```bash
# query parameter
traverse -u "https://LAB-ID.web-security-academy.net/image?filename=FUZZ" \
         --cookie "session=YOUR_TOKEN"

# path segment
traverse -u "http://target/ftp/FUZZ"

# name the parameter and let traverse add the marker
traverse -u "https://target/image" --param filename
```

Quote the URL — a bare `?`/`&` is mangled by the shell.

| Flag | Meaning | Default |
|------|---------|---------|
| `-u, --url` | Target URL with a `FUZZ` marker | — |
| `--param` | Parameter to inject into (adds `=FUZZ`) | — |
| `--target-file` | Read one specific file | built-in library |
| `--os` | `linux` / `windows` / `both` | `both` |
| `--depth` | Max `../` depth tried | `8` |
| `--cookie` / `--header` | Session cookie / extra header (repeatable) | — |
| `--delay` | Seconds between requests | `0.3` |
| `--all` | Don't stop at the first HIGH hit | off |
| `--loot-dir` | Where leaked content is saved | `./loot` |

## Bypass families

Each family defeats a specific server-side defense. Encodings are applied to the
canonical path segments, never by re-quoting an already-encoded string (which
would triple-encode and break the payload).

| Family | Example | Defeats |
|--------|---------|---------|
| Basic | `../../../etc/passwd` | no filtering |
| Absolute | `/etc/passwd` | strips `../` only |
| Non-recursive | `....//....//etc/passwd` | single-pass strip |
| Encoded (single/double) | `%252e%252e%252f…` | decode-then-filter |
| Leading path prefix | `/var/www/images/../../etc/passwd` | "must start with base" |
| Null byte | `…/etc/passwd%00.png` | extension allowlist |
| CTF extras | `..;/`, `file://`, Windows `..\` | reverse proxy / Java / Windows |

## How it works

The bypass engine (`traverse/payloads.py`) expands one target file into every
family above. The detector (`traverse/detector.py`) confirms a hit in three
tiers: **HIGH** when the file's signature regex matches (e.g. `root:x:0:0:` for
`/etc/passwd`), **MEDIUM** when the response diverges sharply from a failure
baseline learned by first requesting a junk filename, **NONE** otherwise. The
target library (`traverse/data/targets.json`) keeps file paths and signatures as
data, so new targets need no code changes. Only `scanner.py`/`cli.py` touch the
network.

## Tests

```bash
pytest -q      # offline unit tests — no network
```

Live acceptance: run the query-parameter command above against a PortSwigger lab
and expect a HIGH hit printing a `root:x:0:0:` snippet, loot saved to `./loot/`.

## Scope and limitations

Focused on file read via path traversal. Injection is via a `FUZZ` marker in the
URL/query/path. See `CHANGELOG.md` for what each release adds.

## License

See `LICENSE`.
