import json, re
from pathlib import Path

TARGETS = Path(__file__).resolve().parent.parent / "traverse" / "data" / "targets.json"

def test_targets_load_and_have_required_fields():
    data = json.loads(TARGETS.read_text(encoding="utf-8"))
    assert len(data) >= 8
    for rec in data:
        assert set(rec) >= {"id", "os", "path", "signature", "note"}
        assert rec["os"] in ("linux", "windows")
        re.compile(rec["signature"])  # signature must be a valid regex

def test_passwd_signature_matches_real_content():
    data = {r["id"]: r for r in json.loads(TARGETS.read_text(encoding="utf-8"))}
    sample = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    assert re.search(data["linux-passwd"]["signature"], sample)


def test_targets_have_categories():
    from traverse.targets import load
    ts = load()
    assert all("category" in t for t in ts)
    assert {"secrets", "config", "cloud"} <= {t["category"] for t in ts}


def test_filter_by_category():
    from traverse.targets import load
    secrets = load(categories=["secrets"])
    assert secrets and all(t["category"] == "secrets" for t in secrets)
