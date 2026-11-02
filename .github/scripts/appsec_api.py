#!/usr/bin/env python3
"""
Run snapshot AppSec analysis via OpenAI, GitHub Models, or LM Studio.

Providers: openai (OPENAI_API_KEY), github-models (GH_TOKEN / GITHUB_TOKEN),
lmstudio (LMSTUDIO_BASE_URL / LMSTUDIO_MODEL; no API key required).

Install this script alongside all _appsec_prompts*.py siblings and gate_report.py.
The prompt catalogs have no package dependencies; file-based imports work too.
"""
import argparse
import os
import subprocess
import sys
from pathlib import Path

# Installed scripts and spec_from_file_location callers need the same sibling imports.
_SCRIPT_DIR = str(Path(__file__).resolve().parent)
if _SCRIPT_DIR not in sys.path:
    sys.path.insert(0, _SCRIPT_DIR)

from _appsec_prompts import (
    API_SECURITY_SYSTEM, API_SECURITY_TEMPLATE,
    ATTACK_TREE_SYSTEM, ATTACK_TREE_TEMPLATE,
    AUTH_REVIEW_SYSTEM, AUTH_REVIEW_TEMPLATE,
    CICD_AUDIT_SYSTEM, CICD_AUDIT_TEMPLATE,
    COMPLIANCE_CHECK_SYSTEM, COMPLIANCE_CHECK_TEMPLATE,
    DEPENDENCY_AUDIT_SYSTEM, DEPENDENCY_AUDIT_TEMPLATE,
    IAC_REVIEW_SYSTEM, IAC_REVIEW_TEMPLATE,
    PR_REVIEW_SYSTEM, PR_REVIEW_TEMPLATE,
    RED_TEAM_SYSTEM, RED_TEAM_TEMPLATE,
    SECRETS_SCAN_SYSTEM, SECRETS_SCAN_TEMPLATE,
    THREAT_DELTA_SYSTEM, THREAT_DELTA_TEMPLATE,
    THREAT_MODEL_DEEP_SYSTEM, THREAT_MODEL_DEEP_TEMPLATE,
    THREAT_MODEL_SYSTEM, THREAT_MODEL_TEMPLATE,
    VERIFY_FIX_SYSTEM, VERIFY_FIX_TEMPLATE,
)


_SPECIALIST_MODES = {
    'runtime-review': 'appsec-runtime-reviewer',
    'business-logic-review': 'appsec-business-logic-reviewer',
    'client-security-review': 'appsec-client-security-reviewer',
    'crypto-review': 'appsec-crypto-reviewer',
    'ai-security-review': 'appsec-ai-security-reviewer',
    'security-test-plan': 'appsec-security-test-planner',
    'secure-codegen-review': 'appsec-secure-codegen-reviewer',
    'privacy-review': 'appsec-privacy-reviewer',
}

_MODE_TO_AGENT = {
    'pr-review': 'appsec-code-reviewer', 'threat-model': 'appsec-threat-modeler',
    'secrets-scan': 'appsec-secrets-scanner', 'iac-review': 'appsec-iac-reviewer',
    'cicd-audit': 'appsec-cicd-auditor', 'dependency-audit': 'appsec-dependency-auditor',
    'api-security': 'appsec-api-security-reviewer', 'auth-review': 'appsec-auth-reviewer',
    'red-team': 'appsec-red-team', 'attack-tree': 'appsec-attack-tree',
    'compliance-check': 'appsec-compliance-checker', 'threat-delta': 'appsec-threat-delta',
    'verify-fix': 'appsec-verify-fix', 'fp-review': 'appsec-fp-reviewer',
    **_SPECIALIST_MODES,
}


def required_workflows(mode):
    """Load the canonical role prompt and skills rather than rely on divergent short templates."""
    try:
        from threatlint.skills import agent_prompt
        return agent_prompt(_MODE_TO_AGENT[mode])
    except ImportError:
        pass
    import json
    import re
    here = Path(__file__).resolve()
    # Packaged copy: <data>/scripts/appsec_api.py. Checkout copy: <repo>/.github/scripts/appsec_api.py.
    roots = [here.parent.parent, *[parent / 'src/threatlint/data' for parent in here.parents]]
    for root in roots:
        registry = root / 'agent-skills.json'
        if not registry.is_file():
            continue
        mapping = json.loads(registry.read_text(encoding='utf-8'))
        agent_id = _MODE_TO_AGENT[mode]
        paths = [root / 'agents' / f'{agent_id}.md']
        paths += [root / 'skills' / name / 'SKILL.md' for name in mapping[agent_id]]
        bodies = [re.sub(r'^---\n[\s\S]*?\n---\n', '', source.read_text(encoding='utf-8')).strip() for source in paths]
        return '\n\n'.join(bodies)
    raise RuntimeError('Required Threatlint skills are unavailable; install threatlint or include src/threatlint/data in the checkout')


MAX_DIFF_CHARS = 80_000
MAX_FILE_BYTES = 6_000
MAX_CONTEXT_FILES = 6
MAX_TOTAL_PARTS = 15
# Local models often have smaller context windows; use a tighter cap by default.
MAX_DIFF_CHARS_LOCAL = 40_000
MAX_FILE_BYTES_LOCAL = 4_000


def run(cmd, **kwargs):
    return subprocess.run(cmd, capture_output=True, text=True, **kwargs)


def get_diff(base, head, max_chars=MAX_DIFF_CHARS):
    diff = run(['git', 'diff', f'{base}..{head}']).stdout
    if len(diff) > max_chars:
        diff = diff[:max_chars] + (
            f'\n\n[diff truncated — {len(diff) - max_chars:,} additional characters omitted]'
        )
    return diff


def get_changed_files(base, head):
    out = run(['git', 'diff', '--name-only', f'{base}..{head}']).stdout.strip()
    return out.split('\n') if out else []


def read_file_safe(path, max_bytes=MAX_FILE_BYTES):
    try:
        size = os.path.getsize(path)
        with open(path, encoding="utf-8", errors='replace') as f:
            content = f.read(max_bytes)
        if size > max_bytes:
            content += f'\n[...truncated at {max_bytes} bytes...]'
        return content
    except OSError:
        return None


CONTEXT_MANIFESTS = (
    'README.md', 'readme.md', 'ARCHITECTURE.md',
    'package.json', 'package-lock.json', 'yarn.lock',
    'go.mod', 'go.sum',
    'requirements.txt', 'Pipfile.lock', 'poetry.lock',
    'Cargo.toml', 'Cargo.lock',
    'pom.xml', 'build.gradle', 'pyproject.toml',
    'Gemfile', 'Gemfile.lock',
    'composer.json', 'composer.lock',
    'Dockerfile', 'docker-compose.yml', 'docker-compose.yaml',
    '.env.example', '.env.sample',
)
CONTEXT_IAC_DIRS = ('infra', 'terraform', 'k8s', 'helm', 'deploy', '.github/workflows')
IAC_FILES_PER_DIR = 3


def _append_file(parts, path, max_file_bytes):
    """Add one file section if there is room and the file is readable. Returns False when full."""
    if len(parts) >= MAX_TOTAL_PARTS:
        return False
    if path and os.path.isfile(path):
        content = read_file_safe(path, max_bytes=max_file_bytes)
        if content:
            parts.append(f'## {path}\n```\n{content}\n```')
    return True


def _iac_files(search_dir):
    if not os.path.isdir(search_dir):
        return []
    found = run([
        'find', search_dir,
        '(', '-name', '*.yml', '-o', '-name', '*.yaml', '-o', '-name', '*.tf', ')',
        '-type', 'f',
    ]).stdout.strip().split('\n')
    return found[:IAC_FILES_PER_DIR]


def _context_paths():
    """Manifests first, then a few IaC/workflow files per directory, in a stable order."""
    yield from CONTEXT_MANIFESTS
    for search_dir in CONTEXT_IAC_DIRS:
        yield from _iac_files(search_dir)


def gather_repo_context(max_file_bytes=MAX_FILE_BYTES):
    file_list = run(['git', 'ls-files']).stdout
    parts = [f'## Repository file listing\n```\n{file_list[:4000]}\n```']
    for path in _context_paths():
        if not _append_file(parts, path, max_file_bytes):
            break
    return '\n\n'.join(parts)


def _lmstudio_call(system_prompt, user_prompt, model_override):
    """Call LM Studio using only stdlib — no openai package required."""
    import json
    import urllib.error
    import urllib.request

    base_url = os.environ.get('LMSTUDIO_BASE_URL', 'http://localhost:1234/v1')
    model = model_override or os.environ.get('LMSTUDIO_MODEL', '')

    if not model:
        try:
            with urllib.request.urlopen(f'{base_url}/models', timeout=5) as resp:
                data = json.loads(resp.read())
            loaded = [m['id'] for m in data.get('data', [])]
            if not loaded:
                print('ERROR: No model loaded in LM Studio. '
                      'Open LM Studio, load a model, and start the local server.',
                      file=sys.stderr)
                sys.exit(1)
            model = loaded[0]
            print(f'Auto-detected LM Studio model: {model}', flush=True)
        except OSError as exc:  # urllib.error.URLError is an OSError
            print(f'ERROR: Cannot reach LM Studio at {base_url}: {exc}\n'
                  'Make sure LM Studio is running and the local server is started.',
                  file=sys.stderr)
            sys.exit(1)

    payload = json.dumps({
        'model': model,
        'messages': [
            {'role': 'system', 'content': system_prompt},
            {'role': 'user',   'content': user_prompt},
        ],
        'max_tokens': 8_000,
    }).encode()

    req = urllib.request.Request(
        f'{base_url}/chat/completions',
        data=payload,
        headers={'Content-Type': 'application/json'},
        method='POST',
    )
    print(f'Calling lmstudio with model {model}...', flush=True)
    try:
        with urllib.request.urlopen(req, timeout=600) as resp:
            result = json.loads(resp.read())
        return result['choices'][0]['message']['content']
    except (urllib.error.URLError, KeyError, json.JSONDecodeError) as exc:
        print(f'ERROR: LM Studio request failed: {exc}', file=sys.stderr)
        sys.exit(1)


def _openai_call(provider, system_prompt, user_prompt, model_override):
    """Call OpenAI or GitHub Models using the openai package."""
    from openai import OpenAI

    if provider == 'github-models':
        token = os.environ.get('GH_TOKEN') or os.environ.get('GITHUB_TOKEN')
        if not token:
            print('ERROR: GH_TOKEN or GITHUB_TOKEN must be set for github-models provider.',
                  file=sys.stderr)
            sys.exit(1)
        client = OpenAI(base_url='https://models.inference.ai.azure.com', api_key=token)
        model = model_override or 'openai/gpt-4o'
    else:
        client = OpenAI()
        model = model_override or 'gpt-4o'

    print(f'Calling {provider} with model {model}...', flush=True)
    response = client.chat.completions.create(
        model=model,
        messages=[
            {'role': 'system', 'content': system_prompt},
            {'role': 'user',   'content': user_prompt},
        ],
        max_tokens=16_000,
    )
    return response.choices[0].message.content


def call_api(provider, system_prompt, user_prompt, model_override):
    if provider == 'lmstudio':
        return _lmstudio_call(system_prompt, user_prompt, model_override)
    return _openai_call(provider, system_prompt, user_prompt, model_override)


# Modes whose prompt is "<target line> + repository context": (template, system, label, default scope).
_CONTEXT_MODES = {
    'secrets-scan': (SECRETS_SCAN_TEMPLATE, SECRETS_SCAN_SYSTEM, 'Secrets scan target',
                     'Scan the entire repository for hardcoded secrets and credential management issues.'),
    'iac-review': (IAC_REVIEW_TEMPLATE, IAC_REVIEW_SYSTEM, 'IaC review target',
                   'Review all Infrastructure as Code in the repository.'),
    'cicd-audit': (CICD_AUDIT_TEMPLATE, CICD_AUDIT_SYSTEM, 'CI/CD audit target',
                   'Audit all CI/CD pipeline configuration in the repository.'),
    'dependency-audit': (DEPENDENCY_AUDIT_TEMPLATE, DEPENDENCY_AUDIT_SYSTEM, 'Dependency audit target',
                         'Audit all package manifests and lockfiles in the repository.'),
    'api-security': (API_SECURITY_TEMPLATE, API_SECURITY_SYSTEM, 'API security review target',
                     'Review all API endpoints discovered in the repository.'),
    'auth-review': (AUTH_REVIEW_TEMPLATE, AUTH_REVIEW_SYSTEM, 'Auth review target',
                    'Review all authentication and authorization code in the repository.'),
    'red-team': (RED_TEAM_TEMPLATE, RED_TEAM_SYSTEM, 'Red team target',
                 'Select the 5 highest-risk attack surfaces from the repository.'),
    'compliance-check': (COMPLIANCE_CHECK_TEMPLATE, COMPLIANCE_CHECK_SYSTEM, 'Compliance check target',
                         'Map all security findings in the repository to applicable compliance frameworks.'),
    'threat-delta': (THREAT_DELTA_TEMPLATE, THREAT_DELTA_SYSTEM, 'Prior report for delta analysis',
                     'Compare the prior security findings to the current repository state.'),
}

_AUTONOMOUS_THREAT_MODEL_SCOPE = (
    'No target specified. Autonomously inventory the repository, rank candidate '
    'components by external exposure, privilege level, sensitive-data handling, and '
    'blast radius, then select the highest-risk scope and explain the selection before '
    'producing the full report.'
)
_UNSPECIFIED = 'unspecified'

SNAPSHOT_RULES = (
    '\nOnly supplied context is available in this snapshot runner. Disclose truncation and uninspected files; '
    'never claim tool calls or tests were executed.'
    '\nNo runtime or browser tools are available. Do not make requests, collect captures, log in, automate '
    'SSO/MFA, or run scans/tests. Runtime/auth evidence must be explicitly supplied and redacted; missing '
    'evidence is a limitation, not a verified result. Proposed validation is NOT RUN; report persistence is host-owned.'
)


def _parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description='Run AppSec analysis via OpenAI, GitHub Models, or LM Studio'
    )
    parser.add_argument('--mode', choices=list(_MODE_TO_AGENT), required=True)
    parser.add_argument('--provider', choices=['openai', 'github-models', 'lmstudio'], required=True)
    parser.add_argument('--base',   default='', help='Base commit SHA (pr-review only)')
    parser.add_argument('--head',   default='', help='Head commit SHA (pr-review only)')
    parser.add_argument('--target', default='', help='Component, scope, or review objective')
    parser.add_argument('--findings', default='', help='UTF-8 SARIF/JSON/Markdown/text evidence for fp-review or specialist modes (up to 5 MB; redact secrets)')
    parser.add_argument('--deep',   action='store_true',
                        help='Use aggressive deep-dive mode (threat-model only)')
    parser.add_argument('--output', required=True, help='Output path for the Markdown report')
    parser.add_argument('--model',  default='', help='Model override')
    parser.add_argument('--gate',   default='',
                        choices=['', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
                        help='Gate on CONFIRMED/PLAUSIBLE findings at or above this severity; APPSEC_GATE_MODE=warn (default) or fail')
    return parser, parser.parse_args(argv)


def _findings_context(path):
    """Import the packaged evidence wrapper, preferring a source checkout when present."""
    source_root = Path(__file__).resolve().parents[2] / 'src'
    if source_root.is_dir():
        sys.path.insert(0, str(source_root))
    from threatlint.skills import findings_context
    return findings_context(path)


def _pr_review_prompt(args, limits, parser):
    if not args.base or not args.head:
        parser.error('--base and --head are required for pr-review mode.')
    diff = get_diff(args.base, args.head, max_chars=limits['diff'])
    changed = get_changed_files(args.base, args.head)
    files_str = '\n'.join(f'- {f}' for f in changed[:60])
    return PR_REVIEW_SYSTEM, PR_REVIEW_TEMPLATE.format(files=files_str, diff=diff)


def _threat_model_prompt(args, limits, _parser):
    context = gather_repo_context(max_file_bytes=limits['file'])
    target_line = f'Threat model target: **{args.target}**' if args.target else _AUTONOMOUS_THREAT_MODEL_SCOPE
    if args.deep:
        return THREAT_MODEL_DEEP_SYSTEM, THREAT_MODEL_DEEP_TEMPLATE.format(target_line=target_line, context=context)
    return THREAT_MODEL_SYSTEM, THREAT_MODEL_TEMPLATE.format(target_line=target_line, context=context)


def _attack_tree_prompt(args, limits, _parser):
    context = gather_repo_context(max_file_bytes=limits['file'])
    target = args.target or 'the highest-risk component in the repository'
    return ATTACK_TREE_SYSTEM, ATTACK_TREE_TEMPLATE.format(target=target, context=context)


def _verify_fix_prompt(args, limits, _parser):
    context = gather_repo_context(max_file_bytes=limits['file'])
    # --target format: "FINDING_ID|Title|file:line|description"
    defaults = [_UNSPECIFIED, _UNSPECIFIED, _UNSPECIFIED, 'Verify the finding is remediated.']
    supplied = args.target.split('|') if args.target else []
    parts = [value or default for value, default in zip(supplied + [''] * 4, defaults)]
    user_prompt = VERIFY_FIX_TEMPLATE.format(finding_id=parts[0], finding_title=parts[1],
                                             finding_evidence=parts[2], finding_description=parts[3], context=context)
    return VERIFY_FIX_SYSTEM, user_prompt


def _fp_review_prompt(args, limits, parser):
    if not args.findings:
        parser.error('--findings is required for fp-review; use the tool-enabled CLI for repository inspection')
    return '', gather_repo_context(max_file_bytes=limits['file']) + _findings_context(args.findings)


def _specialist_prompt(args, limits, _parser):
    user_prompt = (
        f'Specialist review: {args.mode}\n'
        f'Scope / objective: {args.target or "Review only the supplied evidence; identify missing context."}\n\n'
        '## Repository Snapshot\n\n' + gather_repo_context(max_file_bytes=limits['file'])
    )
    if args.findings:
        user_prompt += _findings_context(args.findings)
    return '', user_prompt


def _context_mode_prompt(args, limits, _parser):
    template, system_prompt, label, default_scope = _CONTEXT_MODES[args.mode]
    context = gather_repo_context(max_file_bytes=limits['file'])
    target_line = f'{label}: **{args.target}**' if args.target else default_scope
    return system_prompt, template.format(target_line=target_line, context=context)


_PROMPT_BUILDERS = {
    'pr-review': _pr_review_prompt,
    'threat-model': _threat_model_prompt,
    'attack-tree': _attack_tree_prompt,
    'verify-fix': _verify_fix_prompt,
    'fp-review': _fp_review_prompt,
    **dict.fromkeys(_SPECIALIST_MODES, _specialist_prompt),
    **dict.fromkeys(_CONTEXT_MODES, _context_mode_prompt),
}


def build_prompts(args, parser):
    """Return (system_prompt, user_prompt) for a mode, including the canonical agent and skills."""
    local = args.provider == 'lmstudio'
    limits = {'diff': MAX_DIFF_CHARS_LOCAL if local else MAX_DIFF_CHARS,
              'file': MAX_FILE_BYTES_LOCAL if local else MAX_FILE_BYTES}
    system_prompt, user_prompt = _PROMPT_BUILDERS[args.mode](args, limits, parser)
    system_prompt += '\n\n## Required Agent and Skill Workflows\n' + required_workflows(args.mode) + SNAPSHOT_RULES
    return system_prompt, user_prompt


def _run_gate(report_path, severity):
    import importlib.util
    spec = importlib.util.spec_from_file_location('gate_report', Path(__file__).parent / 'gate_report.py')
    gate_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate_mod)
    saved = sys.argv
    sys.argv = ['gate_report', '--report', report_path, '--severity', severity]
    try:
        gate_mod.main()
    finally:
        sys.argv = saved


def main(argv=None):
    parser, args = _parse_args(argv)
    system_prompt, user_prompt = build_prompts(args, parser)
    report = call_api(args.provider, system_prompt, user_prompt, args.model)
    with open(args.output, 'w', encoding='utf-8') as f:
        f.write(report)
    print(f'Report written to {args.output} ({len(report):,} characters).', flush=True)
    if args.gate:
        _run_gate(args.output, args.gate)


if __name__ == '__main__':
    main()
