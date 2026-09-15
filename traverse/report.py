"""Output rendering: console text, machine-readable JSON, and loot files."""
import json as _json
import time
from pathlib import Path

TOOL = "traverse"


def render_console(hits) -> str:
    if not hits:
        return "[-] No traversal confirmed."
    lines = []
    for h in hits:
        lines.append(f"\n[+] {h['confidence']} — {h['target']}")
        lines.append(f"    payload: {h['payload']}")
        lines.append(f"    snippet: {h['snippet'][:120].strip()}")
    lines.append(f"\n[+] {len(hits)} hit(s).")
    return "\n".join(lines)


def render_json(hits, meta=None) -> str:
    from . import __version__
    doc = {
        "tool": TOOL,
        "version": __version__,
        "target": (meta or {}).get("target"),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "hits": [
            {
                "target": h["target"],
                "category": h.get("category"),
                "confidence": h["confidence"],
                "payload": h["payload"],
                "method": h.get("method", "GET"),
                "snippet": h["snippet"][:500],
            }
            for h in hits
        ],
    }
    return _json.dumps(doc, indent=2)


def save_loot(loot_dir, target, snippet):
    d = Path(loot_dir)
    d.mkdir(parents=True, exist_ok=True)
    safe = target.strip("/").replace("/", "_")
    path = d / f"{safe}.txt"
    path.write_text(snippet, encoding="utf-8")
    return path
