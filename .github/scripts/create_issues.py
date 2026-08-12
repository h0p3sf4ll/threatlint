#!/usr/bin/env python3
"""
Parse an AppSec report (Markdown) and open GitHub issues for qualifying findings.

Findings are identified by the standardized heading format:
  #### [TM-NNN] — Title   (threat model)
  #### [CR-NNN] — Title   (code review)

Filters applied before creating an issue:
  - Severity at or above --min-severity (default: HIGH)
  - Confidence is CONFIRMED or PLAUSIBLE (THEORETICAL skipped by default)
  - No existing open GitHub issue whose title contains the finding ID

Requires the GitHub CLI (gh) and a GH_TOKEN with issues:write permission.
"""
import argparse
import json
import re
import subprocess
import sys
from datetime import datetime, timezone

SEVERITY_RANK = {'CRITICAL': 5, 'HIGH': 4, 'MEDIUM': 3, 'LOW': 2, 'INFO': 1}

SEVERITY_COLORS = {
    'severity:critical': 'b91c1c',
    'severity:high':     'ef4444',
    'severity:medium':   'f97316',
    'severity:low':      'eab308',
    'severity:info':     '6b7280',
}


def extract_findings(report_path):
    with open(report_path) as f:
        content = f.read()

    findings = []

    # Split on finding headings; keep the heading in the block
    heading_re = re.compile(
        r'(?m)^#{4}\s+\[([TC][MR]-\d+)\]\s+[—\-–—]+\s+(.+)$'
    )
    positions = [(m.start(), m.group(1), m.group(2).strip()) for m in heading_re.finditer(content)]

    for i, (start, fid, title) in enumerate(positions):
        end = positions[i + 1][0] if i + 1 < len(positions) else len(content)
        block = content[start:end].strip()

        sev_m = re.search(r'\*\*Severity\*\*[:\s]+([A-Z]+)', block)
        conf_m = re.search(r'\*\*Confidence\*\*[:\s]+([A-Z]+)', block)

        findings.append({
            'id':         fid,
            'title':      title,
            'severity':   sev_m.group(1) if sev_m else 'UNKNOWN',
            'confidence': conf_m.group(1) if conf_m else 'UNKNOWN',
            'body':       block,
        })

    return findings


def gh(*args):
    result = subprocess.run(['gh', *args], capture_output=True, text=True)
    return result.returncode, result.stdout.strip(), result.stderr.strip()


def ensure_label(name, color, description=''):
    code, out, _ = gh('label', 'list', '--json', 'name')
    if code != 0:
        return
    existing = {l['name'] for l in json.loads(out or '[]')}
    if name not in existing:
        gh('label', 'create', name,
           '--color', color,
           '--description', description)


def issue_already_open(finding_id):
    code, out, _ = gh(
        'issue', 'list',
        '--search', f'"{finding_id}" in:title',
        '--label', 'security',
        '--state', 'open',
        '--json', 'number',
    )
    if code != 0:
        return False
    return len(json.loads(out or '[]')) > 0


def create_issue(finding, pr_number='', run_url=''):
    title = f"[{finding['severity']}] {finding['id']}: {finding['title']}"

    date_str = datetime.now(timezone.utc).strftime('%Y-%m-%d')
    meta_rows = [
        f'| **Severity** | {finding["severity"]} |',
        f'| **Confidence** | {finding["confidence"]} |',
        f'| **Date** | {date_str} |',
    ]
    if pr_number:
        meta_rows.append(f'| **Detected in** | PR #{pr_number} |')
    if run_url:
        meta_rows.append(f'| **Workflow run** | [Actions run]({run_url}) |')

    meta_table = '| | |\n|---|---|\n' + '\n'.join(meta_rows)

    body = f'## {finding["id"]}: {finding["title"]}\n\n{meta_table}\n\n---\n\n{finding["body"]}'

    sev_label = f'severity:{finding["severity"].lower()}'
    ensure_label('security', 'e11d48', 'Security finding from threatlint')
    ensure_label(sev_label, SEVERITY_COLORS.get(sev_label, '6b7280'))

    code, out, err = gh(
        'issue', 'create',
        '--title', title,
        '--body', body,
        '--label', f'security,{sev_label}',
    )
    if code == 0:
        print(f'  Created: {out}')
        return True
    print(f'  Failed ({finding["id"]}): {err}', file=sys.stderr)
    return False


def main():
    parser = argparse.ArgumentParser(description='Create GitHub issues from AppSec report findings')
    parser.add_argument('--report',        required=True, help='Path to the Markdown report')
    parser.add_argument('--pr',            default='',    help='PR number (optional)')
    parser.add_argument('--run-url',       default='',    help='Workflow run URL (optional)')
    parser.add_argument('--min-severity',  default='HIGH',
                        choices=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
                        help='Minimum severity to file as issue (default: HIGH)')
    parser.add_argument('--include-theoretical', action='store_true',
                        help='Also file issues for THEORETICAL confidence findings')
    args = parser.parse_args()

    min_rank = SEVERITY_RANK.get(args.min_severity, 4)

    findings = extract_findings(args.report)
    print(f'Parsed {len(findings)} finding(s) from report.')

    created = skipped = 0
    for f in findings:
        rank = SEVERITY_RANK.get(f['severity'], 0)
        if rank < min_rank:
            print(f'  Skip {f["id"]} — {f["severity"]} below {args.min_severity} threshold')
            skipped += 1
            continue

        if not args.include_theoretical and f['confidence'] == 'THEORETICAL':
            print(f'  Skip {f["id"]} — THEORETICAL confidence')
            skipped += 1
            continue

        if issue_already_open(f['id']):
            print(f'  Skip {f["id"]} — open issue already exists')
            skipped += 1
            continue

        print(f'  Filing {f["id"]} ({f["severity"]} / {f["confidence"]}) ...')
        if create_issue(f, pr_number=args.pr, run_url=args.run_url):
            created += 1

    print(f'\nResult: {created} issue(s) created, {skipped} skipped.')
    if created == 0 and skipped == 0:
        print('No qualifying findings found in report.')


if __name__ == '__main__':
    main()
