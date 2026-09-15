"""Target library: file paths + detection signatures, loaded from data/targets.json.

Kept as data so new targets need no code change. Each entry has:
  id, os, path, signature (regex), note, category.
Categories: poc, secrets, config, cloud, source.
"""
import json
from pathlib import Path

DEFAULT_TARGETS = Path(__file__).resolve().parent / "data" / "targets.json"


def load(path=None, os_filter: str = "both", categories=None) -> list:
    """Load targets, optionally filtered by OS and/or category."""
    if path is None:
        path = DEFAULT_TARGETS
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if os_filter != "both":
        data = [t for t in data if t["os"] == os_filter]
    if categories:
        cats = set(categories)
        data = [t for t in data if t.get("category") in cats]
    return data
