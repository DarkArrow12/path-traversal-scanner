from traverse.payloads import generate_payloads

def test_includes_basic_traversal():
    p = generate_payloads("/etc/passwd", depth=4)
    assert "../../../etc/passwd" in p

def test_includes_absolute_path():
    assert "/etc/passwd" in generate_payloads("/etc/passwd")

def test_includes_nonrecursive():
    assert any(s.startswith("....//") for s in generate_payloads("/etc/passwd"))

def test_includes_single_and_double_encoding():
    p = generate_payloads("/etc/passwd")
    assert any("%2e%2e%2f" in s for s in p)
    assert any("%252e%252e%252f" in s for s in p)

def test_no_triple_encoding():
    assert all("%25252e" not in s for s in generate_payloads("/etc/passwd"))

def test_includes_leading_path_prefix():
    assert any(s.startswith("/var/www/images/") and s.endswith("etc/passwd")
               for s in generate_payloads("/etc/passwd"))

def test_includes_null_byte_extension():
    assert any("%00." in s for s in generate_payloads("/etc/passwd"))

def test_results_are_deduplicated():
    p = generate_payloads("/etc/passwd")
    assert len(p) == len(set(p))

def test_os_filter_windows_uses_backslash():
    p = generate_payloads("/windows/win.ini", os_filter="windows")
    assert any("\\" in s for s in p)
