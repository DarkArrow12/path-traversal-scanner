import json

from traverse.report import render_json, render_console


def test_render_json_schema():
    out = json.loads(render_json(
        [{"target": "/etc/passwd", "category": "poc", "confidence": "HIGH",
          "payload": "../../etc/passwd", "method": "GET", "snippet": "root:x:0:0:"}],
        {"target": "http://h"}))
    assert out["hits"][0]["confidence"] == "HIGH"
    assert out["tool"] == "traverse"
    assert out["target"] == "http://h"


def test_render_console_empty():
    assert "No traversal" in render_console([])
