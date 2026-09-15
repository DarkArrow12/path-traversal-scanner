from traverse.scanner import inject, load_targets


def test_inject_replaces_fuzz():
    out = inject("http://x/image?filename=FUZZ", "../../etc/passwd")
    assert out == "http://x/image?filename=../../etc/passwd"


def test_inject_preserves_percent_payloads():
    out = inject("http://x/a?f=FUZZ", "%252e%252e%252fetc/passwd")
    assert out.endswith("%252e%252e%252fetc/passwd")


def test_load_targets_os_filter():
    linux = load_targets(os_filter="linux")
    assert linux and all(t["os"] == "linux" for t in linux)


class _Resp:
    def __init__(self, text, status=200):
        self.text = text
        self.status_code = status


class _FakeSession:
    """Records requests; leaks passwd when a traversal payload reaches the body."""
    def __init__(self):
        self.requests = []

    def request(self, method, url, data=None, headers=None, timeout=15):
        self.requests.append((method, url, data))
        if data and "etc/passwd" in data:
            return _Resp("root:x:0:0:root:/root:/bin/bash\n")
        return _Resp("not found", 404)


_PASSWD = {"path": "/etc/passwd", "signature": "root:[x*]:0:0:",
           "os": "linux", "category": "poc"}


def test_post_body_injection_hits():
    from traverse.scanner import scan
    s = _FakeSession()
    hits = scan(s, "http://h/download", data_template="file=FUZZ",
                targets=[_PASSWD], depth=2, delay=0)
    assert hits and hits[0]["confidence"] == "HIGH"
    assert any(m == "POST" and d and "etc/passwd" in d for (m, u, d) in s.requests)


def test_json_body_injection_hits():
    from traverse.scanner import scan
    s = _FakeSession()
    hits = scan(s, "http://h/api", json_template='{"path":"FUZZ"}',
                targets=[_PASSWD], depth=2, delay=0)
    assert hits and hits[0]["confidence"] == "HIGH"


def test_scan_requires_fuzz_marker():
    import pytest
    from traverse.scanner import scan
    with pytest.raises(ValueError):
        scan(_FakeSession(), "http://h/no-marker", targets=[_PASSWD])
