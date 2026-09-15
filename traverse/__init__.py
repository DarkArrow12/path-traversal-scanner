"""traverse — path traversal, file inclusion, and LFI-to-RCE testing toolkit.

AUTHORIZED USE ONLY. Test only systems you own or are explicitly permitted to test.
"""
__version__ = "0.2.0"

from .payloads import generate_payloads
from .detector import classify, matches_signature
from .scanner import scan, load_targets, inject
from .cli import main, build_parser, build_session

__all__ = [
    "generate_payloads", "classify", "matches_signature",
    "scan", "load_targets", "inject",
    "main", "build_parser", "build_session", "__version__",
]
