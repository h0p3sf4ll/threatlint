#!/usr/bin/env python3
"""Post a compact, revision-bound scanner comment. Requires the trusted Python package.

Use --post explicitly. The workflow checks out this script/package from the base
revision, not from PR source. Target code is never imported or executed.
"""

import argparse
import json
import os
import re
import subprocess
from pathlib import Path


def github_api(endpoint, *, method="GET", payload=None):
    args = ["gh", "api", "--method", method, endpoint]
    if payload is not None:
        args += ["--input", "-"]
    result = subprocess.run(args, input=json.dumps(payload) if payload is not None else None,
                            capture_output=True, text=True, timeout=30, check=False, shell=False)
    if result.returncode:
        raise ValueError("GitHub request failed; no comment outcome was assumed")
    return json.loads(result.stdout or "{}")


def added_lines(patch):
    """Only added right-side lines are eligible for a native suggestion."""
    result, line = set(), None
    for value in str(patch or "").splitlines():
        hunk = re.match(r'^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@', value)
        if hunk:
            line = int(hunk[1])
        elif line is not None and value.startswith('+'):
            result.add(line)
            line += 1
        elif line is not None and value.startswith(' '):
            line += 1
    return result


def publish(scan, repository, pr_number, server, *, api=github_api, proposer=None):
    from threatlint.security_scanner.github import build_comment, suggestion_payload
    from threatlint.security_scanner.fixes import propose_fix
    from threatlint.security_scanner.normalize import sort_findings
    from threatlint.security_scanner.snapshot import ScannerError
    proposer = proposer or propose_fix
    endpoint = f"repos/{repository}/pulls/{pr_number}"
    def current_head():
        pr = api(endpoint)
        if pr["head"]["sha"] != scan["binding"]["commit"]:
            raise ValueError("PR changed after the scan; refusing to publish a stale result")
        if pr["head"]["repo"]["full_name"] != repository:
            raise ValueError("Fork PR comments require a separately authorized trusted publishing deployment")
    current_head()
    changed = {}
    for page in range(1, 11):
        files = api(endpoint + f"/files?per_page=100&page={page}")
        for file in files:
            changed[file['filename']] = added_lines(file.get('patch'))
        if len(files) < 100:
            break
    suggestions = []
    for item in sort_findings(scan.get('findings', [])):
        if not item.get('fixAvailable') or item.get('line') not in changed.get(item.get('path'), set()):
            continue
        try:
            plan = proposer(scan, item['id'])
            payload = suggestion_payload(plan, scan['binding']['commit'])
        except (ScannerError, ValueError):
            continue
        # Use the same escaping/redaction as the compact summary; keep issue and impact beside the native action.
        from threatlint.security_scanner.github import _cell
        payload['body'] = f"**{_cell(item['severity'])} — {_cell(item['title'])}**\n\nImpact: {_cell(item['impact'])}\n\n" + payload['body']
        suggestions.append(payload)
        if len(suggestions) == 10:
            break
    current_head()
    body = build_comment(scan, f"{server}/{repository}/actions/workflows/appsec-auto-fix.yml")
    api(f"repos/{repository}/issues/{pr_number}/comments", method='POST', payload={'body': body})
    for payload in suggestions:
        current_head()
        api(endpoint + '/comments', method='POST', payload=payload)
    return len(suggestions)


def main(argv=None):
    from threatlint.security_scanner.github import build_comment
    parser = argparse.ArgumentParser()
    parser.add_argument("--scan", required=True)
    parser.add_argument("--pr", required=True, type=int)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--post", action="store_true")
    args = parser.parse_args(argv)
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repository) or args.pr < 1:
        raise ValueError("Invalid GitHub repository or PR")
    scan = json.loads(Path(args.scan).read_text(encoding="utf-8"))
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    if not re.fullmatch(r"https://[A-Za-z0-9.-]+", server):
        raise ValueError("Invalid GitHub server")
    body = build_comment(scan, f"{server}/{args.repository}/actions/workflows/appsec-auto-fix.yml")
    if not args.post:
        print(body)
        return 0
    publish(scan, args.repository, args.pr, server)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
