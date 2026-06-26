from scanner import inject, load_targets


def test_inject_replaces_fuzz():
    out = inject("http://x/image?filename=FUZZ", "../../etc/passwd")
    assert out == "http://x/image?filename=../../etc/passwd"


def test_inject_preserves_percent_payloads():
    out = inject("http://x/a?f=FUZZ", "%252e%252e%252fetc/passwd")
    assert out.endswith("%252e%252e%252fetc/passwd")


def test_load_targets_os_filter():
    linux = load_targets("targets.json", os_filter="linux")
    assert linux and all(t["os"] == "linux" for t in linux)
