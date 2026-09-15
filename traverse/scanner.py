"""Network layer: inject payloads, send via a Session, classify responses."""
import time

from .payloads import generate_payloads
from .detector import classify
from .targets import load as load_targets, DEFAULT_TARGETS  # noqa: F401 (re-export)
from .transport import (  # noqa: F401 (inject/FUZZ re-exported)
    inject, inject_body, inject_json, send, FUZZ,
)


def _prepare(url_template, data_template, json_template, payload):
    """Build (url, data, json_body) for one payload, injecting into whichever
    location carries the FUZZ marker."""
    if json_template is not None:
        return url_template, None, inject_json(json_template, payload)
    if data_template is not None:
        return url_template, inject_body(data_template, payload), None
    return inject(url_template, payload), None, None


def _baseline(session, method, url_template, data_template, json_template):
    """Send a junk filename to learn the failure response for this mode."""
    url, data, json_body = _prepare(url_template, data_template, json_template,
                                    "this_file_does_not_exist_zzz")
    resp = send(session, method, url, data=data, json_body=json_body)
    return len(resp.text), resp.status_code


def _probe(session, method, target, payload, url_t, data_t, json_t,
           base_len, base_status):
    """Send one payload; return a hit dict or None."""
    url, data, json_body = _prepare(url_t, data_t, json_t, payload)
    try:
        resp = send(session, method, url, data=data, json_body=json_body)
    except Exception as e:  # network error: record, keep going
        print(f"[!] error on {payload[:40]}: {e}")
        return None
    result = classify(resp.text, resp.status_code, target["signature"],
                      base_len, base_status)
    if result["hit"]:
        return {"target": target["path"], "category": target.get("category"),
                "payload": payload, "method": method,
                "confidence": result["confidence"], "snippet": result["snippet"]}
    return None


def scan(session, url_template, depth=8, delay=0.3, stop_on_first=True,
         os_filter="both", targets=None, method=None,
         data_template=None, json_template=None, null_exts=None, threads=1):
    fuzz_in = (json_template if json_template is not None else
               data_template if data_template is not None else url_template)
    if FUZZ not in (fuzz_in or ""):
        raise ValueError("A FUZZ marker is required (in the URL, --data, or --json).")
    if method is None:
        method = "POST" if (data_template or json_template) else "GET"
    targets = targets if targets is not None else load_targets(os_filter=os_filter)
    base_len, base_status = _baseline(session, method, url_template,
                                      data_template, json_template)
    tasks = [(t, p) for t in targets
             for p in generate_payloads(t["path"], depth, os_filter, null_exts)]
    hits = []

    if threads and threads > 1:
        # Concurrent mode scans every payload (stop-on-first is not honoured).
        from concurrent.futures import ThreadPoolExecutor

        def work(task):
            t, p = task
            if delay:
                time.sleep(delay)
            return _probe(session, method, t, p, url_template,
                          data_template, json_template, base_len, base_status)

        with ThreadPoolExecutor(max_workers=threads) as ex:
            for r in ex.map(work, tasks):
                if r:
                    hits.append(r)
        return hits

    for t, p in tasks:
        r = _probe(session, method, t, p, url_template, data_template,
                   json_template, base_len, base_status)
        if r:
            hits.append(r)
            if stop_on_first and r["confidence"] == "HIGH":
                return hits
        time.sleep(delay)
    return hits
