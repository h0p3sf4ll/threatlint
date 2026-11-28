"""Aggregate scan metrics, kept locally and disclosed.

Each scan appends one JSON line with counts only: targets, scanned, vulnerable, errors,
findings by severity/confidence/advisory. No repository, organization, project or branch
names, file paths, commits, or credentials are recorded. The file lives at
``$THREATLINT_HOME/detect-2shell/metrics.jsonl`` (default ``~/.threatlint``).
Set ``THREATLINT_2SHELL_METRICS=off`` to disable.
"""
from __future__ import annotations

import json
import os
from collections import Counter
from pathlib import Path

# Write-only by design: nothing in ThreatLint (web routes, MCP tools, reports, CLI output)
# reads this file back. Only an operator with filesystem access on the server can read it.

DISABLE_ENV = "THREATLINT_2SHELL_METRICS"
NOTICE = ("Aggregate counts only (no repository names, paths or credentials) are appended to "
          "~/.threatlint/detect-2shell/metrics.jsonl; set THREATLINT_2SHELL_METRICS=off to disable.")


def metrics_path(environ=os.environ) -> Path:
    home = environ.get("THREATLINT_HOME") or os.path.join(os.path.expanduser("~"), ".threatlint")
    return Path(home) / "detect-2shell" / "metrics.jsonl"


def record(doc: dict, *, mode: str, environ=os.environ) -> Path | None:
    if environ.get(DISABLE_ENV, "").strip().lower() in ("off", "0", "false", "no"):
        return None
    findings = [f for r in doc["results"] for f in r["findings"]]
    entry = {
        "at": doc["generatedAt"],
        "mode": mode,
        "providers": sorted({r["provider"] for r in doc["results"]}),
        "summary": {k: doc["summary"][k] for k in ("targets", "scanned", "vulnerable", "clean", "notApplicable", "errors")},
        "findings": {
            "total": len(findings),
            "bySeverity": dict(Counter(f["severity"] for f in findings)),
            "byConfidence": dict(Counter(f["confidence"] for f in findings)),
            "byAdvisory": dict(Counter(f["advisory"] for f in findings)),
            "exposedTargets": sum(1 for r in doc["results"]
                                  if any(f["confidence"] != "THEORETICAL" for f in r["findings"])),
        },
    }
    path = metrics_path(environ)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, sort_keys=True) + "\n")
    except OSError:
        return None  # metrics must never break a scan
    return path

