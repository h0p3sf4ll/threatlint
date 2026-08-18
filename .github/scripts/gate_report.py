#!/usr/bin/env python3
"""
Gate a CI pipeline based on findings in an AppSec report.

Exits 0 if no findings at or above the threshold severity exist.
Exits 1 if one or more qualifying findings exist (fails the pipeline step).

Usage:
  python3 gate_report.py --report /tmp/appsec-report.md
  python3 gate_report.py --report /tmp/appsec-report.md --severity HIGH
  python3 gate_report.py --report /tmp/appsec-report.md --severity CRITICAL --confidence CONFIRMED

Severity thresholds (high to low): CRITICAL > HIGH > MEDIUM > LOW > INFO
Confidence filter: CONFIRMED, PLAUSIBLE, THEORETICAL (default: CONFIRMED+PLAUSIBLE)
"""
import argparse
import re
import sys

SEVERITY_RANK = {'CRITICAL': 5, 'HIGH': 4, 'MEDIUM': 3, 'LOW': 2, 'INFO': 1}
CONFIDENCE_RANK = {'CONFIRMED': 3, 'PLAUSIBLE': 2, 'THEORETICAL': 1}

FINDING_RE = re.compile(
    r'(?m)^#{3,5}\s+\[(?:TM|CR|DA|IC|CI|AR|AU|SS|AC|RT|CD|VF)-\d+\]',
)


def parse_findings(text):
    findings = []
    heading_re = re.compile(
        r'(?m)^#{3,5}\s+\[((?:TM|CR|DA|IC|CI|AR|AU|SS|AC|RT|CD|VF)-\d+)\]\s+[—\-–—]+\s+(.+)$'
    )
    positions = [(m.start(), m.group(1), m.group(2).strip()) for m in heading_re.finditer(text)]
    for i, (start, fid, title) in enumerate(positions):
        end = positions[i + 1][0] if i + 1 < len(positions) else len(text)
        block = text[start:end]
        sev_m  = re.search(r'\*\*Severity\*\*[:\s]+([A-Z]+)', block)
        conf_m = re.search(r'\*\*Confidence\*\*[:\s]+([A-Z]+)', block)
        findings.append({
            'id':         fid,
            'title':      title,
            'severity':   sev_m.group(1)  if sev_m  else 'UNKNOWN',
            'confidence': conf_m.group(1) if conf_m else 'UNKNOWN',
        })
    return findings


def main():
    parser = argparse.ArgumentParser(description='Gate CI on AppSec report severity')
    parser.add_argument('--report',     required=True, help='Path to Markdown report')
    parser.add_argument('--severity',   default='HIGH',
                        choices=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'],
                        help='Minimum severity to gate on (default: HIGH)')
    parser.add_argument('--confidence', default='PLAUSIBLE',
                        choices=['CONFIRMED', 'PLAUSIBLE', 'THEORETICAL'],
                        help='Minimum confidence to gate on (default: PLAUSIBLE)')
    parser.add_argument('--allow-theoretical', action='store_true',
                        help='Include THEORETICAL findings (equivalent to --confidence THEORETICAL)')
    args = parser.parse_args()

    try:
        with open(args.report) as f:
            text = f.read()
    except OSError as exc:
        print(f'gate: cannot read report: {exc}', file=sys.stderr)
        sys.exit(2)

    min_sev  = SEVERITY_RANK.get(args.severity,   4)
    min_conf = CONFIDENCE_RANK.get('THEORETICAL' if args.allow_theoretical else args.confidence, 2)

    findings = parse_findings(text)
    blocking = [
        f for f in findings
        if SEVERITY_RANK.get(f['severity'], 0)   >= min_sev
        and CONFIDENCE_RANK.get(f['confidence'], 0) >= min_conf
    ]

    if not blocking:
        total = len(findings)
        print(f'gate: PASS — {total} finding(s) total, 0 at or above {args.severity}/{args.confidence}.')
        sys.exit(0)

    print(f'gate: BLOCK — {len(blocking)} finding(s) at or above {args.severity}/{args.confidence}:')
    for f in blocking:
        print(f"  [{f['id']}] {f['severity']}/{f['confidence']} — {f['title']}")
    print()
    print('Resolve these findings or lower APPSEC_GATE_SEVERITY to allow merge.')
    sys.exit(1)


if __name__ == '__main__':
    main()
