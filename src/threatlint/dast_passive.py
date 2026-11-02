"""Pure passive response observations, matching Workbench runtime rule IDs."""

from __future__ import annotations

import re

from threatlint.dast_requests import PROBE_ORIGIN

HEADER_CHECKS = (
    {"id": "RT-HDR-HSTS", "header": "strict-transport-security", "https": True, "severity": "MEDIUM", "title": "Missing Strict-Transport-Security", "cwe": "CWE-319"},
    {"id": "RT-HDR-CSP", "header": "content-security-policy", "html": True, "severity": "MEDIUM", "title": "Missing Content-Security-Policy on HTML", "cwe": "CWE-1021"},
    {"id": "RT-HDR-XCTO", "header": "x-content-type-options", "severity": "LOW", "title": "Missing X-Content-Type-Options: nosniff", "cwe": "CWE-693"},
    {"id": "RT-HDR-FRAME", "header": "x-frame-options", "html": True, "alt": "frame-ancestors", "severity": "LOW", "title": "HTML can be framed (no X-Frame-Options or frame-ancestors)", "cwe": "CWE-1021"},
)
DEBUG_SIGNATURES = (r"Traceback \(most recent call last\)", r"at [\w$.]+\([\w./-]+\.java:\d+\)", r"(?i)Werkzeug Debugger", r"(?i)Whoops! There was an error",
                    r"DEBUG\s*=\s*True", r"at Object\.<anonymous> \(", r"System\.NullReferenceException", r"Microsoft\.AspNetCore\.Diagnostics")


def _headers(response: dict) -> dict[str, list[str]]:
    headers: dict[str, list[str]] = {}
    for name, value in response.get("headers") or []:
        headers.setdefault(name.lower(), []).append(value)
    return headers


def passive_checks(response: dict, path: str, scanned_https: bool = False) -> list[dict]:
    """Observe headers/cookies/debug output; HTTPS-edge properties need an HTTPS response."""
    if not response.get("status"):
        return []
    headers, found = _headers(response), []
    one = lambda name: (headers.get(name) or [""])[0]
    html = bool(re.search(r"text/html", one("content-type"), re.I))
    for check in HEADER_CHECKS:
        if (check.get("https") and not scanned_https) or (check.get("html") and not html) or headers.get(check["header"]):
            continue
        if check.get("alt") and check["alt"] in one("content-security-policy").lower():
            continue
        found.append({"rule": check["id"], "severity": check["severity"], "title": check["title"], "cwe": check["cwe"], "path": path,
                      "observation": f"{path} returned {response['status']} without {check['header']}"})
    for cookie in headers.get("set-cookie", []):
        name, flags = cookie.split("=")[0].strip()[:80], cookie.lower()
        missing = [flag for flag, ok in (("HttpOnly", "httponly" in flags), ("Secure", not scanned_https or "secure" in flags), ("SameSite", "samesite" in flags)) if not ok]
        if missing:
            found.append({"rule": "RT-COOKIE-FLAGS", "severity": "MEDIUM" if "HttpOnly" in missing and re.search(r"sess|auth|token|sid", name, re.I) else "LOW",
                          "title": f"Cookie {name} is missing {', '.join(missing)}", "cwe": "CWE-1004", "path": path, "observation": f"Set-Cookie for {name} lacks {', '.join(missing)}"})
    acao, credentials = one("access-control-allow-origin"), one("access-control-allow-credentials").lower() == "true"
    if acao and (acao == PROBE_ORIGIN or (acao == "*" and credentials)):
        found.append({"rule": "RT-CORS-REFLECT", "severity": "HIGH" if credentials else "MEDIUM", "title": "CORS reflects an untrusted origin", "cwe": "CWE-942", "path": path,
                      "observation": f"Access-Control-Allow-Origin: {acao[:80]}{' with credentials allowed' if credentials else ''}"})
    for name in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
        if re.search(r"\d", one(name)):
            found.append({"rule": "RT-DISCLOSE-VERSION", "severity": "INFO", "title": f"Version disclosed in {name}", "cwe": "CWE-200", "path": path, "observation": f"{name}: {one(name)[:80]}"})
    signature = next((pattern for pattern in DEBUG_SIGNATURES if re.search(pattern, response.get("body") or "")), None)
    if signature:
        found.append({"rule": "RT-DEBUG-LEAK", "severity": "MEDIUM", "title": "Stack trace or debug output in response", "cwe": "CWE-209", "path": path,
                      "observation": f"{path} matched the debug signature {signature[:60]}"})
    return found
