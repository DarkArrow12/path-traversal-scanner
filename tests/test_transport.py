import json

from traverse.transport import inject, inject_body, inject_json


def test_inject_replaces_fuzz_verbatim():
    assert inject("http://h/a?f=FUZZ", "%2500") == "http://h/a?f=%2500"


def test_inject_body_is_verbatim():
    assert inject_body("file=FUZZ&x=1", "../../etc/passwd") == "file=../../etc/passwd&x=1"


def test_inject_json_escapes_payload():
    out = inject_json('{"path":"FUZZ"}', '../"x')
    assert json.loads(out)["path"] == '../"x'


def test_inject_json_nested():
    out = inject_json('{"a":{"path":"FUZZ"},"b":1}', "../../etc/passwd")
    obj = json.loads(out)
    assert obj["a"]["path"] == "../../etc/passwd" and obj["b"] == 1
