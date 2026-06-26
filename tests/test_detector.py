from detector import matches_signature, classify

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
