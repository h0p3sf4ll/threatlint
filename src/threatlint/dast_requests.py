"""Pure bounded DAST request planning; requests remain sandbox-relative."""

from __future__ import annotations

import secrets
import urllib.parse

from threatlint.avit_resolve import ResolveError

PROBE_ORIGIN = "https://threatlint-cors-probe.invalid"
REDIRECT_PROBE = "https://threatlint-redirect-probe.invalid/tl"


def _request(identifier: str, finding: dict, value: str | None = None, headers: dict | None = None) -> dict:
    """The finding's request with the vulnerable parameter set to value (None keeps the original)."""
    query = urllib.parse.parse_qsl(finding["query"], keep_blank_values=True)
    parameter, method = finding.get("parameter", ""), finding["method"]
    body = None
    if parameter and value is not None:
        if method == "POST":
            body = urllib.parse.urlencode([(parameter, value)])
        else:
            query = [(k, v) for k, v in query if k != parameter] + [(parameter, value)]
    path = finding["path"] + ("?" + urllib.parse.urlencode(query) if query else "")
    request = {"id": identifier, "method": method, "path": path, "headers": {"User-Agent": "threatlint-dast/1", **(headers or {})}}
    if body is not None:
        request.update(body=body)
        request["headers"]["Content-Type"] = "application/x-www-form-urlencoded"
    return request


def plan_requests(finding: dict, marker: str = "") -> list[dict]:
    """Bounded requests (at most 8) for the finding's vulnerability class, all to the finding's path on the sandbox."""
    marker = marker or secrets.token_hex(4)
    original = dict(urllib.parse.parse_qsl(finding["query"])).get(finding.get("parameter", ""), "1")
    kind, plan = finding["kind"], [_request("baseline", finding)]
    if kind in ("xss", "sqli", "redirect", "traversal") and not finding.get("parameter"):
        raise ResolveError(f"The {kind} finding names no vulnerable parameter; cannot target the check")
    if kind == "xss":
        plan.append(_request("marker", finding, f"tl{marker}\"'<tl{marker}>"))
    elif kind == "sqli":
        plan += [_request("quote", finding, original + "'"), _request("true", finding, original + "' AND '1'='1"), _request("false", finding, original + "' AND '1'='2"),
                 _request("num-true", finding, original + " AND 1=1"), _request("num-false", finding, original + " AND 1=2")]
    elif kind == "redirect":
        plan += [_request("absolute", finding, REDIRECT_PROBE), _request("scheme-relative", finding, "//threatlint-redirect-probe.invalid/tl")]
    elif kind == "traversal":
        plan += [_request("relative", finding, "../../../../../../../../etc/passwd"), _request("nested", finding, "....//....//....//....//etc/passwd"),
                 _request("absolute", finding, "/etc/passwd")]
    elif kind == "cors":
        plan.append(_request("origin", finding, None, {"Origin": PROBE_ORIGIN}))
    return plan
