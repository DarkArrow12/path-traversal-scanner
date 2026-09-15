from traverse.discover import find_params


def test_find_params_prefers_file_like_names():
    html = '<a href="/view?page=home">x</a><a href="/dl?filename=a.pdf&id=3">y</a>'
    params = find_params(html, "http://x")
    assert "filename" in params
    assert params.index("filename") <= params.index("id") if "id" in params else True
