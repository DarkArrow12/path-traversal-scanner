"""Network layer: inject payloads, send via a Session, classify responses."""
import time

from .payloads import generate_payloads
from .detector import classify
from .targets import load as load_targets, DEFAULT_TARGETS  # noqa: F401 (re-export)
from .transport import inject, FUZZ  # noqa: F401 (re-export)


def _baseline(session, url_template):
    """Send a junk filename to learn the failure response."""
    resp = session.get(inject(url_template, "this_file_does_not_exist_zzz"),
                       timeout=15)
    return len(resp.text), resp.status_code


def scan(session, url_template, depth=8, delay=0.3, stop_on_first=True,
         os_filter="both", targets=None):
    if FUZZ not in url_template:
        raise ValueError("URL must contain the FUZZ marker (e.g. ?filename=FUZZ)")
    targets = targets if targets is not None else load_targets(os_filter=os_filter)
    base_len, base_status = _baseline(session, url_template)
    hits = []
    for target in targets:
        for payload in generate_payloads(target["path"], depth, os_filter):
            url = inject(url_template, payload)
            try:
                resp = session.get(url, timeout=15)
            except Exception as e:  # network error: record, keep going
                print(f"[!] error on {payload[:40]}: {e}")
                continue
            result = classify(resp.text, resp.status_code, target["signature"],
                              base_len, base_status)
            if result["hit"]:
                hit = {"target": target["path"], "payload": payload,
                       "confidence": result["confidence"], "snippet": result["snippet"]}
                hits.append(hit)
                if stop_on_first and result["confidence"] == "HIGH":
                    return hits
            time.sleep(delay)
    return hits
