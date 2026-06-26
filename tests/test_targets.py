import json, re
from pathlib import Path

TARGETS = Path(__file__).resolve().parent.parent / "targets.json"

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
