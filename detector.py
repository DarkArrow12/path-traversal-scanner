"""Confirmation layer: decide whether a response leaked a target file."""
import re

# A response whose length differs from the failure baseline by more than this
# ratio is treated as anomalous (possible blind hit).
ANOMALY_RATIO = 3.0


def matches_signature(text: str, pattern: str) -> bool:
    return re.search(pattern, text, re.MULTILINE) is not None


def _snippet(text: str, pattern: str) -> str:
    m = re.search(pattern, text, re.MULTILINE)
    if not m:
        return text[:200]
    start = max(0, m.start() - 20)
    return text[start:m.end() + 180]


def classify(text: str, status: int, signature: str,
             baseline_len: int, baseline_status: int) -> dict:
    # HIGH: the file's signature is present.
    if matches_signature(text, signature):
        return {"hit": True, "confidence": "HIGH", "snippet": _snippet(text, signature)}
    # MEDIUM: response diverges sharply from the known failure baseline.
    longer = baseline_len > 0 and len(text) > baseline_len * ANOMALY_RATIO
    status_changed = status != baseline_status and status < 500
    if longer or status_changed:
        return {"hit": True, "confidence": "MEDIUM", "snippet": text[:200]}
    return {"hit": False, "confidence": "NONE", "snippet": ""}
