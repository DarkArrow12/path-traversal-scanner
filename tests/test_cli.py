from traverse.cli import build_parser, build_session

def test_parser_requires_a_mode():
    parser = build_parser()
    ns = parser.parse_args(["-u", "http://x?f=FUZZ"])
    assert ns.url == "http://x?f=FUZZ"

def test_session_sets_cookie_and_header():
    s = build_session("session=abc123", ["X-Test: 1"])
    assert s.cookies.get("session") == "abc123"
    assert s.headers.get("X-Test") == "1"


def test_parser_accepts_body_flags():
    args = build_parser().parse_args(
        ["-u", "http://h/dl", "--data", "file=FUZZ", "--threads", "4", "--output", "json"])
    assert args.data == "file=FUZZ" and args.threads == 4 and args.output == "json"


def test_parser_json_body_dest():
    args = build_parser().parse_args(["-u", "http://h/api", "--json", '{"p":"FUZZ"}'])
    assert args.json_body == '{"p":"FUZZ"}'


def test_parser_wrapper_flags():
    args = build_parser().parse_args(
        ["-u", "http://h/fi?page=FUZZ", "--wrapper", "filter", "--resource", "index.php"])
    assert args.wrapper == "filter" and args.resource == "index.php"
