"""traverse — path traversal, file inclusion, and LFI-to-RCE testing toolkit.

AUTHORIZED USE ONLY. Test only systems you own or are explicitly permitted to test.
"""
__version__ = "0.2.0"

from .payloads import generate_payloads
from .detector import classify, matches_signature, looks_like_php_source, contains_canary
from .scanner import scan, run_wrapper, load_targets, inject
from .wrappers import php_filter_read, data_wrapper, expect_wrapper, php_input_body
from .cli import main, build_parser, build_session

__all__ = [
    "generate_payloads", "classify", "matches_signature",
    "looks_like_php_source", "contains_canary",
    "scan", "run_wrapper", "load_targets", "inject",
    "php_filter_read", "data_wrapper", "expect_wrapper", "php_input_body",
    "main", "build_parser", "build_session", "__version__",
]
