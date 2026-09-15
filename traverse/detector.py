"""Confirmation layer: decide whether a response leaked a target file."""
import base64
import re

# A response whose length differs from the failure baseline by more than this
# ratio is treated as anomalous (possible blind hit).
ANOMALY_RATIO = 3.0

# Candidate base64 runs (php://filter output). Long enough to avoid noise.
_B64_RUN = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
_PHP_TOKENS = ("<?php", "<?=")


def matches_signature(text: str, pattern: str) -> bool:
    return re.search(pattern, text, re.MULTILINE) is not None


def contains_canary(text: str, nonce: str) -> bool:
    """A unique command-output marker echoed back confirms code execution."""
    return bool(nonce) and nonce in text


def looks_like_php_source(text: str):
    """Detect a base64 blob (e.g. php://filter output) that decodes to PHP.

    Returns (True, decoded_source) on the first match, else (False, "")."""
    for m in _B64_RUN.finditer(text):
        blob = m.group(0)
        try:
            decoded = base64.b64decode(blob, validate=True).decode("utf-8", "replace")
        except Exception:
            continue
        if any(tok in decoded for tok in _PHP_TOKENS):
            return True, decoded
    return False, ""


def _snippet(text: str, pattern: str) -> str:
    m = re.search(pattern, text, re.MULTILINE)
    if not m:
        return text[:200]
    start = max(0, m.start() - 20)
    return text[start:m.end() + 180]


def classify(text: str, status: int, signature: str,
             baseline_len: int, baseline_status: int, nonce: str = None) -> dict:
    # HIGH: a unique RCE canary was echoed back (code execution confirmed).
    if nonce and contains_canary(text, nonce):
        start = max(0, text.find(nonce) - 40)
        return {"hit": True, "confidence": "HIGH", "snippet": text[start:start + 240]}
    # HIGH: the file's signature is present.
    if matches_signature(text, signature):
        return {"hit": True, "confidence": "HIGH", "snippet": _snippet(text, signature)}
    # HIGH: a base64 blob decodes to PHP source (php://filter disclosure).
    ok, decoded = looks_like_php_source(text)
    if ok:
        return {"hit": True, "confidence": "HIGH", "snippet": decoded[:400]}
    # MEDIUM: response diverges sharply from the known failure baseline.
    longer = baseline_len > 0 and len(text) > baseline_len * ANOMALY_RATIO
    status_changed = status != baseline_status and status < 500
    if longer or status_changed:
        return {"hit": True, "confidence": "MEDIUM", "snippet": text[:200]}
    return {"hit": False, "confidence": "NONE", "snippet": ""}
