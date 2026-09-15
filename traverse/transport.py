"""Transport: inject the FUZZ marker into a request and send it via a Session.

The FUZZ marker can live in the URL (query string or path segment), a raw POST
body, or inside a JSON body. Payloads are inserted verbatim into URL/body so
deliberate percent-encoding (e.g. %252e) survives; JSON substitution round-trips
through the parser so payloads are correctly escaped.
"""
import json as _json

import requests

FUZZ = "FUZZ"


def inject(template: str, payload: str) -> str:
    """Replace the FUZZ marker verbatim (URL or raw body)."""
    return template.replace(FUZZ, payload)


# A raw POST body is substituted the same way as a URL.
inject_body = inject


def inject_json(json_template: str, payload: str) -> str:
    """Substitute FUZZ into a JSON template, then re-serialize so the payload is
    correctly JSON-escaped regardless of quotes/backslashes it contains."""
    def walk(value):
        if isinstance(value, str):
            return value.replace(FUZZ, payload)
        if isinstance(value, list):
            return [walk(v) for v in value]
        if isinstance(value, dict):
            return {k: walk(v) for k, v in value.items()}
        return value

    return _json.dumps(walk(_json.loads(json_template)))


def build_session(cookie=None, headers=None) -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": "traverse (authorized testing)"})
    if cookie and "=" in cookie:
        name, _, value = cookie.partition("=")
        s.cookies.set(name.strip(), value.strip())
    for h in headers or []:
        if ":" in h:
            name, _, value = h.partition(":")
            s.headers[name.strip()] = value.strip()
    return s


def send(session, method: str, url: str, *, data=None, json_body=None, timeout: int = 15):
    """Dispatch a request. `data` is a raw body; `json_body` is a pre-serialized
    JSON string sent verbatim with an application/json content type."""
    if json_body is not None:
        return session.request(method, url, data=json_body,
                               headers={"Content-Type": "application/json"},
                               timeout=timeout)
    return session.request(method, url, data=data, timeout=timeout)
