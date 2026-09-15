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


class _EchoSession:
    """Simulates a server that reflects the request so canaries/base64 surface."""
    def __init__(self, mode):
        self.mode = mode

    def request(self, method, url, data=None, headers=None, timeout=15):
        import base64
        import re
        if self.mode == "filter":
            return _Resp(base64.b64encode(b"<?php $secret=1;?>").decode())
        if self.mode == "input":  # server executes body PHP -> echoes the nonce
            m = re.search(r"echo '([^']+)'", data or "")
            return _Resp(m.group(1) if m else "no exec")
        return _Resp("nope", 200)


def test_run_wrapper_filter_reads_source():
    from traverse.scanner import run_wrapper
    hits = run_wrapper(_EchoSession("filter"), "http://h/fi?page=FUZZ",
                       "filter", resource="config.php")
    assert hits and hits[0]["confidence"] == "HIGH" and "secret" in hits[0]["snippet"]


def test_run_wrapper_input_rce_canary():
    from traverse.scanner import run_wrapper
    hits = run_wrapper(_EchoSession("input"), "http://h/fi?page=FUZZ",
                       "input", cmd="id")
    assert hits and hits[0]["confidence"] == "HIGH"


def test_run_wrapper_requires_fuzz():
    import pytest
    from traverse.scanner import run_wrapper
    with pytest.raises(ValueError):
        run_wrapper(_EchoSession("filter"), "http://h/fi", "filter", resource="x")
