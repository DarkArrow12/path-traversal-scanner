from traverse.cli import build_parser, build_session

def test_parser_requires_a_mode():
    parser = build_parser()
    ns = parser.parse_args(["-u", "http://x?f=FUZZ"])
    assert ns.url == "http://x?f=FUZZ"

def test_session_sets_cookie_and_header():
    s = build_session("session=abc123", ["X-Test: 1"])
    assert s.cookies.get("session") == "abc123"
    assert s.headers.get("X-Test") == "1"
