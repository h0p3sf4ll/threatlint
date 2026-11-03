"""Base class for scanning tools.

A scanning tool **analyzes code itself** and owns the issues it raised: it decides what to flag, and its own
issue workflow (comment, false-positive / won't-fix / confirm transitions) is where a verdict belongs. SonarQube
and SonarCloud are the built-in example; Checkmarx, Snyk Code, Veracode, Fortify, or GitHub code scanning would
fit here.

What this type adds to `ReviewableIntegration`:
  - no attachments: the verdict is written as a comment that summarises it and names where the full report lives
    (`--report-url`, else the Word report's file name);
  - the tool's native transition expresses the disposition (e.g. SonarQube False Positive / Confirm / Safe).

Subclasses implement the `ReviewableIntegration` methods (references, fetch, search, get, resolve, note, describe,
auth_headers, validate_token).
"""

from __future__ import annotations

import os

from threatlint.integrations.common import ReviewableIntegration

KIND = "scanning"


class ScanningTool(ReviewableIntegration):
    kind = KIND
    supports_attachments = False

    def add_resolve_arguments(self, parser) -> None:
        parser.add_argument("--docx", help="Word report (named in the comment; not uploaded)")
        parser.add_argument("--report-url", help="Where the full report lives (named in the comment)")

    def report_location(self, args) -> str:
        """Where the comment says the full report lives."""
        where = (getattr(args, "report_url", None) or "").strip()
        if where:
            return where
        names = [os.path.basename(path) for path in (getattr(args, "docx", None), getattr(args, "report", None)) if path]
        return f"Threatlint report {names[0]} (kept by the reviewer; {self.label} does not store attachments)" if names \
            else "the Threatlint report kept by the reviewer"
