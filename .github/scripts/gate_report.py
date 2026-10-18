#!/usr/bin/env python3
"""
Gate a CI pipeline based on findings in an AppSec report.

Modes (--mode, or APPSEC_GATE_MODE; default: warn):
  warn  Findings at or above the threshold are reported as pipeline warnings; exit 0.
  fail  Findings at or above the threshold fail the step; exit 1.

A missing or unreadable report warns in warn mode and fails (exit 2) in fail mode.
Warnings use GitHub Actions (::warning::) or Azure Pipelines (##vso[...]) annotations when
running on those platforms; Azure warn results mark the step SucceededWithIssues.

Usage:
  python3 gate_report.py --report /tmp/appsec-report.md
  python3 gate_report.py --report /tmp/appsec-report.md --severity HIGH --mode fail
  python3 gate_report.py --report /tmp/appsec-report.md --severity CRITICAL --confidence CONFIRMED

Severity thresholds (high to low): CRITICAL > HIGH > MEDIUM > LOW > INFO
Confidence filter: CONFIRMED, PLAUSIBLE, THEORETICAL (default: CONFIRMED+PLAUSIBLE)
"""
import argparse
import os
import re
import sys
from typing import NamedTuple

SEVERITY_RANK = {'CRITICAL': 5, 'HIGH': 4, 'MEDIUM': 3, 'LOW': 2, 'INFO': 1}
CONFIDENCE_RANK = {'CONFIRMED': 3, 'PLAUSIBLE': 2, 'THEORETICAL': 1}
DEFAULT_CONFIDENCE = 'PLAUSIBLE'
THEORETICAL = 'THEORETICAL'
WARN, FAIL = 'warn', 'fail'
MODES = (WARN, FAIL)
LEVEL_WARNING, LEVEL_ERROR = 'warning', 'error'
GITHUB, AZURE, PLAIN = 'github', 'azure', 'plain'

class Finding(NamedTuple):
    id: str
    title: str
    severity: str
    confidence: str


# Any agent prefix (TM, CR, SG, PD, DX, ...), so newly added specialists gate too.
HEADING_RE = re.compile(r'(?m)^#{3,5}\s+\[([A-Z]{2,3}-\d+)\]\s+[—\-–]+\s+(.+)$')


def parse_findings(text):
    findings = []
    positions = [(m.start(), m.group(1), m.group(2).strip()) for m in HEADING_RE.finditer(text)]
    for i, (start, fid, title) in enumerate(positions):
        end = positions[i + 1][0] if i + 1 < len(positions) else len(text)
        block = text[start:end]
        sev_m = re.search(r'\*\*Severity\*\*[:\s]+([A-Z]+)', block)
        conf_m = re.search(r'\*\*Confidence\*\*[:\s]+([A-Z]+)', block)
        findings.append(Finding(fid, title, sev_m.group(1) if sev_m else 'UNKNOWN', conf_m.group(1) if conf_m else 'UNKNOWN'))
    return findings


def platform():
    if os.environ.get('GITHUB_ACTIONS') == 'true':
        return GITHUB
    if os.environ.get('TF_BUILD'):
        return AZURE
    return PLAIN


def annotate(level, message):
    """Emit a warning/error the CI system shows on the run summary."""
    message = message.replace('\r', ' ').replace('\n', ' ')
    where = platform()
    if where == GITHUB:
        print(f'::{level}::{message}')
    elif where == AZURE:
        print(f'##vso[task.logissue type={level}]{message}')
    else:
        print(f'{level.upper()}: {message}')


def level_for(mode):
    return LEVEL_ERROR if mode == FAIL else LEVEL_WARNING


def finish(mode):
    """Exit according to the gate mode once a gate condition has been met."""
    if mode == FAIL:
        sys.exit(1)
    if platform() == AZURE:
        print('##vso[task.complete result=SucceededWithIssues;]Threatlint gate in warn mode')
    sys.exit(0)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description='Gate CI on AppSec report severity')
    parser.add_argument('--report', required=True, help='Path to Markdown report')
    parser.add_argument('--severity', default='HIGH', type=str.upper, choices=list(SEVERITY_RANK),
                        help='Minimum severity to gate on (default: HIGH)')
    parser.add_argument('--confidence', default=DEFAULT_CONFIDENCE, choices=list(CONFIDENCE_RANK),
                        help=f'Minimum confidence to gate on (default: {DEFAULT_CONFIDENCE})')
    parser.add_argument('--allow-theoretical', action='store_true',
                        help=f'Include {THEORETICAL} findings (equivalent to --confidence {THEORETICAL})')
    parser.add_argument('--mode', type=str.lower, choices=MODES,
                        default=(os.environ.get('APPSEC_GATE_MODE') or WARN).lower(),
                        help='warn (default) reports findings without failing; fail exits 1')
    args = parser.parse_args(argv)
    if args.mode not in MODES:
        parser.error('APPSEC_GATE_MODE must be warn or fail')
    if args.allow_theoretical:
        args.confidence = THEORETICAL
    return args


def read_report(path, mode):
    try:
        with open(path, encoding='utf-8') as f:
            return f.read()
    except OSError as exc:
        annotate(level_for(mode), f'Threatlint gate: no readable report ({exc.strerror or exc}); severity was not evaluated.')
        if mode == FAIL:
            sys.exit(2)
        finish(mode)


def gated(findings, severity, confidence):
    min_sev, min_conf = SEVERITY_RANK[severity], CONFIDENCE_RANK[confidence]
    return [f for f in findings
            if SEVERITY_RANK.get(f.severity, 0) >= min_sev and CONFIDENCE_RANK.get(f.confidence, 0) >= min_conf]


def main(argv=None):
    args = parse_args(argv)
    findings = parse_findings(read_report(args.report, args.mode))
    threshold = f'{args.severity}/{args.confidence}'
    blocking = gated(findings, args.severity, args.confidence)
    if not blocking:
        print(f'gate: PASS — {len(findings)} finding(s) total, 0 at or above {threshold}.')
        sys.exit(0)
    verdict = 'BLOCK' if args.mode == FAIL else 'WARN'
    print(f'gate: {verdict} — {len(blocking)} finding(s) at or above {threshold}:')
    for f in blocking:
        annotate(level_for(args.mode), f'[{f.id}] {f.severity}/{f.confidence} — {f.title}')
    print()
    if args.mode == FAIL:
        print('Resolve these findings, raise the gate severity, or set the gate mode to warn to allow merge.')
    else:
        print('Warn mode: the pipeline stays green. Set the gate mode to fail to block merges on these findings.')
    finish(args.mode)


if __name__ == '__main__':
    main()
