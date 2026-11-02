"""Load AVIT records and normalize supported Invicti dynamic findings."""

from __future__ import annotations

import json
import os
import re
import urllib.parse

from threatlint import servicenow as sn
from threatlint.avit_resolve import ResolveError

_INVICTI = re.compile(r"invicti|netsparker", re.I)
_FIELDS = {
    "source": ("source", "scansource", "findingsource", "securityfindingsource", "scanner", "tool"),
    "scan_type": ("scantype", "testtype", "scanmethod", "analysistype"),
    "url": ("vulnerableurl", "affectedurl", "url", "uri", "location", "endpoint", "vulnerabilityurl", "page"),
    "parameter": ("vulnerableparameter", "parameter", "parametername", "param", "inputname"),
    "method": ("httpmethod", "method", "requestmethod"),
    "vulnerability": ("vulnerabilitytype", "vulnerabilityname", "vulnerability", "issuetype", "type", "name", "shortdescription"),
    "severity": ("severity", "risk", "riskrating", "scannerseverity"),
    "issue_id": ("invictiissueid", "externalid", "sourceid", "scannerissueid", "issueid", "findingid"),
    "proof": ("proof", "evidence", "proofofconcept", "attackpattern", "payload"),
    "cwe": ("cwe", "cweid", "classification"),
}
_KINDS = (
    ("xss", r"cross[- ]?site scripting|\bxss\b|html injection"),
    ("sqli", r"sql injection|\bsqli\b"),
    ("redirect", r"open redirect|unvalidated redirect"),
    ("traversal", r"path traversal|directory traversal|local file inclusion|\blfi\b"),
    ("dirlist", r"directory listing|directory browsing"),
    ("cors", r"\bcors\b|cross[- ]origin resource sharing|access-control-allow-origin"),
    ("cookie", r"cookie"),
    ("headers", r"strict[- ]transport|\bhsts\b|content[- ]security[- ]policy|\bcsp\b|x-frame-options|clickjacking|frame|x-content-type|nosniff|security header"),
    ("disclosure", r"version disclosure|server header|x-powered-by|banner|technology disclosure"),
    ("debug", r"stack trace|debug|error message|exception"),
)


def _norm(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", re.sub(r"^u_", "", name.lower()))


def load_avit_file(path: str) -> dict[str, str]:
    """AVIT fields from a JSON record (Table API row, {"result": [row]}, or flat) or a Markdown field list/table."""
    try:
        with open(os.path.expanduser(path), encoding="utf-8") as handle:
            text = handle.read(1024 * 1024)
    except OSError as exc:
        raise ResolveError(f"Cannot read the AVIT file: {exc}") from exc
    if path.lower().endswith(".json") or text.lstrip().startswith(("{", "[")):
        try:
            data = json.loads(text)
        except ValueError as exc:
            raise ResolveError(f"The AVIT file is not valid JSON: {exc}") from exc
        if isinstance(data, dict) and isinstance(data.get("result"), list):
            data = data["result"]
        if isinstance(data, list):
            if len(data) != 1:
                raise ResolveError("The AVIT file must hold exactly one record")
            data = data[0]
        if not isinstance(data, dict):
            raise ResolveError("The AVIT file must hold one JSON object")
        return sn._flatten(data)
    fields = {}
    for line in text.splitlines():
        match = re.match(r"\s*[-*]?\s*\**([A-Za-z][\w /.-]{0,60}?)\**\s*:\s*(.+)$", line) or re.match(r"\s*\|\s*([A-Za-z][\w /.-]{0,60}?)\s*\|\s*(.+?)\s*\|\s*$", line)
        if match and match.group(1).strip().lower() not in ("field", "item", "---"):
            fields.setdefault(re.sub(r"[ /.-]+", "_", match.group(1).strip().lower()), match.group(2).replace("`", "").strip())
    if not fields:
        raise ResolveError("The AVIT file has no `field: value` lines or field table")
    return fields


def invicti_finding(fields: dict[str, str], avit: str = "") -> dict[str, str]:
    """The Invicti finding the AVIT describes; refuses AVITs that are not Invicti dynamic findings."""
    by_name = {_norm(name): str(value) for name, value in fields.items() if value}
    finding = {key: next((by_name[name] for name in names if by_name.get(name)), "") for key, names in _FIELDS.items()}
    number = (fields.get("number") or avit or "").upper()
    if avit and number and number != avit:
        raise ResolveError(f"The AVIT record is {number}, not {avit}")
    [number] = sn.parse_avit_numbers(number or "missing")
    if not _INVICTI.search(finding["source"]) or not re.search(r"dynamic|dast", finding["scan_type"], re.I):
        raise ResolveError(f"{number} is not an Invicti dynamic finding (source {finding['source'] or 'not set'}, scan type "
                           f"{finding['scan_type'] or 'not set'}); SAST/SCA/Secrets AVITs use `avit checkout` and the FP review")
    url = urllib.parse.urlsplit(finding["url"])
    if url.scheme not in ("http", "https") or not url.hostname:
        raise ResolveError(f"{number} has no absolute vulnerable URL; cannot target the check")
    method = (finding["method"] or "GET").upper()
    if method not in ("GET", "POST", "HEAD"):
        raise ResolveError(f"Unsupported HTTP method on the finding: {method[:10]}")
    # Only the path and query are kept: the sandbox app is the only host that ever receives a request.
    path = urllib.parse.quote(url.path or "/", safe="/%:@!$&'()*+,;=-._~")
    return {**finding, "avit": number, "method": method, "path": path, "query": url.query, "scanned_origin": f"{url.scheme}://{url.hostname}",
            "kind": check_kind(finding["vulnerability"])}


def check_kind(vulnerability: str) -> str:
    return next((kind for kind, pattern in _KINDS if re.search(pattern, vulnerability or "", re.I)), "generic")
