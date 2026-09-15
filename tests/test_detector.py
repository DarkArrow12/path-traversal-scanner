from traverse.detector import matches_signature, classify

PASSWD = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"

def test_signature_matches_passwd():
    assert matches_signature(PASSWD, "root:[x*]:0:0:") is True

def test_signature_rejects_junk():
    assert matches_signature("Not found", "root:[x*]:0:0:") is False

def test_classify_high_on_signature():
    r = classify(PASSWD, 200, "root:[x*]:0:0:", baseline_len=20, baseline_status=200)
    assert r["hit"] is True and r["confidence"] == "HIGH"
    assert "root:x:0:0:" in r["snippet"]

def test_classify_medium_on_anomalous_length():
    body = "x" * 5000
    r = classify(body, 200, "root:[x*]:0:0:", baseline_len=20, baseline_status=200)
    assert r["hit"] is True and r["confidence"] == "MEDIUM"

def test_classify_none_when_matches_baseline():
    r = classify("file not found", 200, "root:[x*]:0:0:", baseline_len=14, baseline_status=200)
    assert r["hit"] is False and r["confidence"] == "NONE"


def test_php_filter_base64_detected():
    import base64
    from traverse.detector import looks_like_php_source
    blob = base64.b64encode(b"<?php $db='secret';?>").decode()
    ok, decoded = looks_like_php_source(blob)
    assert ok and "secret" in decoded


def test_php_filter_base64_in_surrounding_html():
    import base64
    from traverse.detector import looks_like_php_source
    blob = base64.b64encode(b"<?php echo 'hi';?>").decode()
    ok, decoded = looks_like_php_source(f"<html><body>{blob}</body></html>")
    assert ok and "echo" in decoded


def test_rce_canary():
    from traverse.detector import contains_canary
    assert contains_canary("uid=0 CANARY_abc123 gid=0", "CANARY_abc123")
    assert not contains_canary("nothing here", "CANARY_abc123")


def test_classify_canary_is_high():
    from traverse.detector import classify
    r = classify("uid=0(root) MARK123", 200, "no-match-sig", 10, 200, nonce="MARK123")
    assert r["hit"] and r["confidence"] == "HIGH"
