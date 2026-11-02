"""Execute a bounded provider probe and assess/redact its observations."""

from __future__ import annotations

import re

from threatlint.dast_evidence import redact_response, redact_text
from threatlint.dast_passive import _headers, passive_checks
from threatlint.dast_requests import plan_requests
from threatlint.runtime_env import EnvironmentProvider

SQL_ERRORS = (("MySQL syntax error", r"(?i)SQL syntax"), ("SQLite error", r"(?i)sqlite3?\.OperationalError|unrecognized token"),
              ("PostgreSQL error", r"(?i)unterminated quoted string|psycopg2?\.errors|syntax error at or near"), ("Oracle error", r"ORA-\d{5}"),
              ("PDO error", r"SQLSTATE\["), ("SQL Server error", r"(?i)Unclosed quotation mark"), ("JDBC error", r"(?i)SQLException"), ("PHP MySQL error", r"(?i)mysql_fetch"))


def assess(finding: dict, requests: list[dict], responses: list[dict], marker: str = "") -> dict:
    """What the targeted check observed for this finding. An observation, never a verdict: the reviewer decides."""
    by_id = {response["id"]: response for response in responses}
    body = lambda key: (by_id.get(key) or {}).get("body") or ""
    status = lambda key: (by_id.get(key) or {}).get("status")
    ctype = lambda key: (_headers(by_id.get(key) or {}).get("content-type") or [""])[0]
    kind, signals, observed = finding["kind"], [], None
    if not status("baseline"):
        return {"kind": kind, "observed": None, "signals": [f"No response to the baseline request: {(by_id.get('baseline') or {}).get('error', 'not sent')}"]}
    signals.append(f"Baseline {finding['method']} {requests[0]['path']} -> HTTP {status('baseline')} ({ctype('baseline')[:40] or 'no content type'}, {len(body('baseline'))} bytes)")
    if kind == "xss":
        raw, encoded = f"<tl{marker}>" in body("marker"), f"&lt;tl{marker}&gt;" in body("marker") or f"\\u003ctl{marker}" in body("marker")
        html = "text/html" in ctype("marker").lower()
        observed = raw and html
        signals.append(f"Marker with < > \" ' in {finding['parameter']}: " + ("reflected unencoded in an HTML response" if observed else
                       "reflected unencoded, but the response is not HTML" if raw else "reflected HTML-encoded" if encoded else "not reflected"))
        csp = (_headers(by_id.get("marker") or {}).get("content-security-policy") or [""])[0]
        signals.append(f"Content-Security-Policy: {csp[:120] if csp else 'none'}")
    elif kind == "sqli":
        errors = [label for label, pattern in SQL_ERRORS if re.search(pattern, body("quote")) and not re.search(pattern, body("baseline"))]
        signals.append(f"Single quote -> HTTP {status('quote')}; database error signatures: {', '.join(errors) if errors else 'none'}")
        def differential(true_key: str, false_key: str) -> bool:
            same = lambda a, b: status(a) == status(b) and abs(len(body(a)) - len(body(b))) <= max(8, len(body(b)) // 20)
            return bool(status(true_key)) and same(true_key, "baseline") and not same(false_key, "baseline")
        boolean = differential("true", "false") or differential("num-true", "num-false")
        signals.append("Boolean pair: " + ("TRUE condition matches the baseline and FALSE differs" if boolean else "no differential") +
                       f" (string {status('true')}/{status('false')}, numeric {status('num-true')}/{status('num-false')})")
        observed = bool(errors) or boolean
    elif kind == "redirect":
        hits = [key for key in ("absolute", "scheme-relative") if str(status(key) or "").startswith("3")
                and "threatlint-redirect-probe.invalid" in ((_headers(by_id.get(key) or {}).get("location") or [""])[0])]
        observed = bool(hits)
        signals.append(f"Redirect to an external probe origin: {', '.join(hits) if hits else 'not observed'} (redirects are never followed)")
    elif kind == "traversal":
        hits = [key for key in ("relative", "nested", "absolute") if re.search(r"root:[x*]?:0:0:", body(key))]
        observed = bool(hits)
        signals.append(f"/etc/passwd content returned: {', '.join(hits) if hits else 'no'}")
    elif kind == "dirlist":
        observed = bool(re.search(r"(?i)<title>\s*(index of|directory listing for)", body("baseline")))
        signals.append(f"Directory index page: {'yes' if observed else 'no'}")
    else:
        rules = {"cors": ("RT-CORS-REFLECT",), "cookie": ("RT-COOKIE-FLAGS",), "headers": ("RT-HDR-HSTS", "RT-HDR-CSP", "RT-HDR-XCTO", "RT-HDR-FRAME"),
                 "disclosure": ("RT-DISCLOSE-VERSION",), "debug": ("RT-DEBUG-LEAK",)}.get(kind)
        if rules:
            hits = [item for response in responses for item in passive_checks(response, finding["path"]) if item["rule"] in rules]
            observed = bool(hits)
            signals += [f"{item['rule']}: {item['observation']}" for item in hits] or [f"No {', '.join(rules)} observation on {finding['path']}"]
            if kind == "headers" and re.search(r"strict[- ]transport|hsts", finding["vulnerability"], re.I):
                observed = None
                signals.append("HSTS is set by the HTTPS edge; the sandbox serves plain HTTP without that edge, so it cannot show HSTS either way")
        else:
            signals.append("No targeted check for this vulnerability class; the request was replayed for the passive checks only")
    return {"kind": kind, "observed": observed, "signals": signals}


def collect_probe(state: dict, env: EnvironmentProvider, marker: str) -> dict:
    """Keep raw provider responses local; only redacted evidence leaves this boundary."""
    finding = state["finding"]
    requests = plan_requests(finding, marker)
    responses = env.probe(state, requests)
    result = assess(finding, requests, responses, marker)
    passive = [item for response in responses for item in passive_checks(response, finding["path"])]
    return {"requests": [{**{k: v for k, v in item.items() if k != "headers"}, "headers": item["headers"], "body": redact_text(item.get("body", "")) or None} for item in requests],
            "responses": [redact_response(response, marker) for response in responses], "assessment": result,
            "passive": list({(item["rule"], item["observation"]): item for item in passive}.values()),
            "target": f"http://{state['plan']['app']}:{state['plan']['port']} (sandbox only; scanned origin {finding['scanned_origin']} was not contacted)"}
