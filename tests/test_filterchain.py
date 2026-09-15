import re

from traverse.filterchain import run_filter_chain, from_generator

# A stand-in generator: emits a php://filter line embedding the payload's nonce,
# so a reflecting session can "execute" it. (The real Synacktiv tool is not
# redistributed; traverse only drives it.)
_MOCK_GEN = (
    "import sys, re\n"
    "php = sys.argv[sys.argv.index('--chain') + 1]\n"
    "n = re.search(r\"echo '([^']+)'\", php).group(1)\n"
    "print('[+] Generating chain...')\n"
    "print('php://filter/echo_' + n + '/resource=php://temp')\n"
)


class _Resp:
    def __init__(self, text, status=200):
        self.text = text
        self.status_code = status


class _FCSession:
    """Reflects the chain so an embedded canary surfaces (simulated execution)."""
    def request(self, method, url, data=None, headers=None, timeout=15):
        m = re.search(r"echo_(TRAVERSE_[0-9a-f]+)", url)
        return _Resp(m.group(1) if m else "not found", 200)


def _write_gen(tmp_path):
    gen = tmp_path / "gen.py"
    gen.write_text(_MOCK_GEN)
    return str(gen)


def test_from_generator_parses_chain(tmp_path):
    chain = from_generator(_write_gen(tmp_path), "<?php echo 'TRAVERSE_abc'; ?>")
    assert chain.startswith("php://filter/") and "TRAVERSE_abc" in chain


def test_run_filter_chain_rce(tmp_path):
    hits = run_filter_chain(_FCSession(), "http://h/fi?page=FUZZ", "id",
                            generator_path=_write_gen(tmp_path))
    assert hits and hits[0]["confidence"] == "HIGH"


def test_run_filter_chain_requires_generator():
    import pytest
    with pytest.raises(ValueError):
        run_filter_chain(_FCSession(), "http://h/fi?page=FUZZ", "id", generator_path=None)


def test_run_filter_chain_requires_fuzz(tmp_path):
    import pytest
    with pytest.raises(ValueError):
        run_filter_chain(_FCSession(), "http://h/fi", "id",
                         generator_path=_write_gen(tmp_path))
