#!/usr/bin/env python3
"""
Convert a threatlint Markdown report to GitHub Code Scanning SARIF format.

Usage:
    python to_sarif.py --report /tmp/appsec-report.md --output results.sarif
    python to_sarif.py --report /tmp/appsec-report.md --output results.sarif \
                       --tool appsec-threat-modeler --commit-sha abc123def456
"""
import argparse
import json
import re
import sys
from datetime import datetime, timezone


SEVERITIES = {
    'CRITICAL': 'error',
    'HIGH': 'error',
    'MEDIUM': 'warning',
    'LOW': 'note',
    'INFO': 'note',
    'INFORMATIONAL': 'note',
}

SECURITY_SEVERITY = {
    'CRITICAL': '9.8',
    'HIGH': '8.0',
    'MEDIUM': '6.5',
    'LOW': '3.9',
    'INFO': '1.0',
    'INFORMATIONAL': '1.0',
}

FINDING_PATTERN = re.compile(
    r'^#### \[((?:TM|CR|DA|IC|CI|AR|AU|SS)-\d+)\] — (.+)$',
    re.MULTILINE,
)

SEVERITY_PATTERN = re.compile(r'\*\*Severity\*\*:\s*(CRITICAL|HIGH|MEDIUM|LOW|INFO|INFORMATIONAL)', re.IGNORECASE)
CONFIDENCE_PATTERN = re.compile(r'\*\*Confidence\*\*:\s*(CONFIRMED|PLAUSIBLE|THEORETICAL)', re.IGNORECASE)
FILE_PATTERN = re.compile(r'`([^`]+\.(?:py|js|ts|go|java|rb|php|rs|cs|cpp|c|kt|swift|yaml|yml|tf|json|toml)):(\d+)`')
OWASP_PATTERN = re.compile(r'\|\s*OWASP\s*\|\s*(.+?)\s*\|')
CWE_PATTERN = re.compile(r'\|\s*CWE\s*\|\s*(CWE-\d+)', re.IGNORECASE)


def extract_findings(report_text):
    """Extract structured finding data from a threatlint Markdown report."""
    findings = []
    # Split on finding headers
    sections = re.split(r'(?=^#### \[(?:TM|CR|DA|IC|CI|AR|AU|SS)-\d+\])', report_text, flags=re.MULTILINE)

    for section in sections:
        m = FINDING_PATTERN.match(section.strip())
        if not m:
            continue

        finding_id = m.group(1)
        title = m.group(2).strip()

        sev_m = SEVERITY_PATTERN.search(section)
        severity = sev_m.group(1).upper() if sev_m else 'MEDIUM'

        conf_m = CONFIDENCE_PATTERN.search(section)
        confidence = conf_m.group(1).upper() if conf_m else 'THEORETICAL'

        file_matches = FILE_PATTERN.findall(section)
        location_file = file_matches[0][0] if file_matches else None
        location_line = int(file_matches[0][1]) if file_matches else 1

        owasp_m = OWASP_PATTERN.search(section)
        owasp = owasp_m.group(1).strip() if owasp_m else None

        cwe_m = CWE_PATTERN.search(section)
        cwe = cwe_m.group(1).upper() if cwe_m else None

        # Extract the paragraph after the finding header as the description
        # (everything up to the first table row or **Severity** line)
        desc_match = re.search(r'\*\*Confidence\*\*:.+?\n\n(.*?)(?:\n\||\n\*\*|\Z)', section, re.DOTALL)
        description = desc_match.group(1).strip() if desc_match else title

        findings.append({
            'id': finding_id,
            'title': title,
            'severity': severity,
            'confidence': confidence,
            'file': location_file,
            'line': location_line,
            'owasp': owasp,
            'cwe': cwe,
            'description': description[:1000],  # SARIF message limit
        })

    return findings


def findings_to_sarif(findings, tool_name, commit_sha, report_path):
    rules = []
    rule_ids_seen = set()
    results = []

    for finding in findings:
        rule_id = finding['id']

        if rule_id not in rule_ids_seen:
            rule_ids_seen.add(rule_id)
            rule = {
                'id': rule_id,
                'name': re.sub(r'[^A-Za-z0-9]', '', finding['title'].title()),
                'shortDescription': {'text': finding['title']},
                'fullDescription': {'text': finding['title']},
                'defaultConfiguration': {
                    'level': SEVERITIES.get(finding['severity'], 'warning'),
                },
                'properties': {
                    'security-severity': SECURITY_SEVERITY.get(finding['severity'], '5.0'),
                    'confidence': finding['confidence'],
                    'tags': ['security'],
                },
            }
            if finding['owasp']:
                rule['help'] = {'text': f"OWASP: {finding['owasp']}"}
            if finding['cwe']:
                rule['properties']['tags'].append(finding['cwe'].lower())
            rules.append(rule)

        result = {
            'ruleId': rule_id,
            'level': SEVERITIES.get(finding['severity'], 'warning'),
            'message': {'text': finding['description'] or finding['title']},
            'properties': {
                'confidence': finding['confidence'],
                'severity': finding['severity'],
            },
        }

        if finding['file']:
            result['locations'] = [{
                'physicalLocation': {
                    'artifactLocation': {'uri': finding['file'], 'uriBaseId': '%SRCROOT%'},
                    'region': {'startLine': finding['line']},
                },
            }]
        else:
            result['locations'] = [{
                'physicalLocation': {
                    'artifactLocation': {'uri': report_path, 'uriBaseId': '%SRCROOT%'},
                    'region': {'startLine': 1},
                },
            }]

        results.append(result)

    sarif = {
        'version': '2.1.0',
        '$schema': 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Documents/CommitteeSpecifications/2.1.0/sarif-schema-2.1.0.json',
        'runs': [{
            'tool': {
                'driver': {
                    'name': tool_name,
                    'version': '1.0.0',
                    'informationUri': 'https://github.com/h0p3sf4ll/threatlint',
                    'rules': rules,
                },
            },
            'results': results,
            'invocations': [{
                'executionSuccessful': True,
                'endTimeUtc': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
            }],
            'versionControlProvenance': [{'revisionId': commit_sha}] if commit_sha else [],
        }],
    }
    return sarif


def main():
    parser = argparse.ArgumentParser(description='Convert threatlint report to SARIF')
    parser.add_argument('--report', required=True, help='Path to Markdown report')
    parser.add_argument('--output', required=True, help='Output SARIF file path')
    parser.add_argument('--tool', default='threatlint', help='Tool name for SARIF driver')
    parser.add_argument('--commit-sha', default='', help='Git commit SHA for provenance')
    args = parser.parse_args()

    try:
        with open(args.report) as f:
            report_text = f.read()
    except OSError as e:
        print(f'ERROR: Cannot read report: {e}', file=sys.stderr)
        sys.exit(1)

    findings = extract_findings(report_text)
    if not findings:
        print(f'No findings extracted from {args.report} — writing empty SARIF.', flush=True)

    sarif = findings_to_sarif(findings, args.tool, args.commit_sha, args.report)

    with open(args.output, 'w') as f:
        json.dump(sarif, f, indent=2)

    print(f'SARIF written to {args.output} ({len(findings)} findings, {len(sarif["runs"][0]["tool"]["driver"]["rules"])} rules).', flush=True)


if __name__ == '__main__':
    main()
