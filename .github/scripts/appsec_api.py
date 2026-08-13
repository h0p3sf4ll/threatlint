#!/usr/bin/env python3
"""
Run an AppSec analysis via the OpenAI API, GitHub Models API, or a local LM Studio instance.
Used by GitHub Actions workflows and Claude Code local-model slash commands.

Providers
---------
openai        Authenticated with OPENAI_API_KEY. Default model: gpt-4o
github-models Authenticated with GITHUB_TOKEN (no extra secret needed).
              Base URL: https://models.inference.ai.azure.com
              Default model: openai/gpt-4o
lmstudio      Local model served by LM Studio (OpenAI-compatible API).
              Base URL: http://localhost:1234/v1 (override with LMSTUDIO_BASE_URL)
              Model: auto-detected from LM Studio (override with LMSTUDIO_MODEL or --model)
              No API key required.
"""
import argparse
import os
import subprocess
import sys

MAX_DIFF_CHARS = 80_000
MAX_FILE_BYTES = 6_000
MAX_CONTEXT_FILES = 6
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
        with open(path, errors='replace') as f:
            content = f.read(max_bytes)
        if size > max_bytes:
            content += f'\n[...truncated at {max_bytes} bytes...]'
        return content
    except OSError:
        return None


def gather_repo_context(max_file_bytes=MAX_FILE_BYTES):
    parts = []

    file_list = run(['git', 'ls-files']).stdout
    parts.append(f'## Repository file listing\n```\n{file_list[:4000]}\n```')

    for fname in [
        'README.md', 'readme.md', 'ARCHITECTURE.md',
        'package.json', 'go.mod', 'requirements.txt', 'Cargo.toml',
        'pom.xml', 'build.gradle', 'pyproject.toml',
        'Dockerfile', 'docker-compose.yml', 'docker-compose.yaml',
        '.env.example', '.env.sample',
    ]:
        if os.path.isfile(fname):
            content = read_file_safe(fname, max_bytes=max_file_bytes)
            if content:
                parts.append(f'## {fname}\n```\n{content}\n```')
            if len(parts) >= MAX_CONTEXT_FILES + 1:
                break

    for search_dir in ['infra', 'terraform', 'k8s', 'helm', 'deploy', '.github/workflows']:
        if not os.path.isdir(search_dir):
            continue
        found = run([
            'find', search_dir,
            '(', '-name', '*.yml', '-o', '-name', '*.yaml', '-o', '-name', '*.tf', ')',
            '-type', 'f',
        ]).stdout.strip().split('\n')
        for fpath in found[:3]:
            if fpath and os.path.isfile(fpath):
                content = read_file_safe(fpath, max_bytes=max_file_bytes)
                if content:
                    parts.append(f'## {fpath}\n```\n{content}\n```')

    return '\n\n'.join(parts)


# ─── System prompts ──────────────────────────────────────────────────────────

PR_REVIEW_SYSTEM = (
    'You are an expert application security engineer performing a security-focused code review. '
    'Apply an aggressive analysis posture: escalate borderline THEORETICAL/PLAUSIBLE findings to '
    'PLAUSIBLE when preconditions are realistic; enumerate at least one bypass path for every '
    'defensive control touched or removed; chain low-severity findings that together create a '
    'higher-impact scenario; assume full attacker knowledge of the source. '
    'Report only security regressions and missing controls — exclude style, performance, and '
    'maintainability findings.'
)

THREAT_MODEL_SYSTEM = (
    'You are an expert application security engineer producing an evidence-based threat model. '
    'Apply an aggressive analysis posture: escalate borderline THEORETICAL/PLAUSIBLE findings to '
    'PLAUSIBLE when preconditions are realistic; enumerate at least one bypass path for every '
    'defensive control; chain findings into multi-step kill chains; assume full attacker knowledge. '
    'Ground every material claim in the repository context provided. Label all assumptions explicitly.'
)

THREAT_MODEL_DEEP_SYSTEM = (
    THREAT_MODEL_SYSTEM +
    ' Use AGGRESSIVE DEEP-DIVE mode: '
    '(1) Default to PLAUSIBLE for borderline findings when preconditions are realistic in production. '
    'State explicitly which assumption would promote each PLAUSIBLE to CONFIRMED. '
    '(2) For EVERY defensive control discovered — auth middleware, authz checks, input validation, '
    'rate limiting — enumerate at least one bypass path. State feasible/not-feasible/needs-runtime for each. '
    '(3) Construct chained attack paths combining two or more findings into a higher-impact scenario. '
    'Show the full kill chain: foothold → escalation → lateral movement → data access or persistence. '
    '(4) Include at least one evaluated finding for each applicable category: injection, authentication, '
    'authorization, secrets/credentials, cryptography, error handling/info disclosure, CI/CD/supply chain, '
    'infrastructure. If a category has no findings, state "No findings — [reason tied to reviewed code]." '
    '(5) For every critical security decision deferred to runtime (env vars, cloud IAM, secrets managers), '
    'produce an explicit Runtime Blindspot entry in Residual Risk.'
)

# ─── Prompt templates ────────────────────────────────────────────────────────

PR_REVIEW_TEMPLATE = '''\
## Changed Files
{files}

## Diff
```diff
{diff}
```

## Required Report Format

Produce a two-tier Markdown security code review.

### TIER 1 — EXECUTIVE SUMMARY

**Change Risk Level**: CRITICAL / HIGH / MEDIUM / LOW / CLEAN

One-sentence risk summary.

**Finding Summary**:
| Severity | Count | CONFIRMED | PLAUSIBLE | THEORETICAL |
|----------|-------|-----------|-----------|-------------|
| Critical | | | | |
| High | | | | |
| Medium | | | | |
| Low | | | | |

**Top Issues** (Critical and High only):
- **[CR-NNN]** *Title* — business risk. Required fix.

**Merge Recommendation**: BLOCK / MERGE WITH ACTION / MERGE

---

### TIER 2 — TECHNICAL REVIEW

**Review Scope**: changed files, context, numbered assumptions.

For each finding:

#### [CR-NNN] — *Finding Title*

**Severity**: CRITICAL / HIGH / MEDIUM / LOW / INFO
**Confidence**: CONFIRMED / PLAUSIBLE / THEORETICAL

| Field | Detail |
|-------|--------|
| OWASP | |
| CWE | |
| Changed File | `path/to/file.ext:NN` |
| Evidence | quoted `+` lines from the diff |
| Exploit Path | 1. → 2. → 3. |
| Impact | |
| Likelihood | |
| Mitigation | |
| Effort | Immediate / Short-term |

**Remediation Guidance**: numbered steps with before/after code snippets.

**Test Case**: concrete reproduction or unit test.

---

**Security-Positive Changes**: controls added or correctly hardened.

**Residual Risk**: THEORETICAL findings needing confirmation, open questions.
'''

THREAT_MODEL_TEMPLATE = '''\
{target_line}

## Repository Context

{context}

## Required Report Format

Produce a two-tier Markdown threat model.

### TIER 1 — EXECUTIVE SUMMARY

**Risk Posture**: 1–2 sentences.

**Finding Summary**:
| Severity | Count | CONFIRMED | PLAUSIBLE | THEORETICAL |
|----------|-------|-----------|-----------|-------------|

**Top Immediate Actions** (Critical and High only): business risk and required action per finding.

**Recommended Next Step**: single most important action.

---

### TIER 2 — TECHNICAL THREAT MODEL

**Scope and Assumptions**: reviewed components, excluded areas, numbered assumptions [A-N].

**System Model**: assets with data classifications, actors with trust levels, entry points, trust boundaries.

For each finding:

#### [TM-NNN] — *Finding Title*

**Severity**: CRITICAL / HIGH / MEDIUM / LOW / INFO
**Confidence**: CONFIRMED / PLAUSIBLE / THEORETICAL
**Persona**: applicable attacker persona(s)

| Field | Detail |
|-------|--------|
| STRIDE | |
| OWASP | |
| CWE | |
| Preconditions | |
| Attack Steps | 1. → 2. → 3. |
| Evidence | `path/to/file:NN` |
| Impact | |
| Mitigation | |
| Effort | |

**Remediation Guidance**: numbered steps with before/after snippets.

**Validation**: concrete step that confirms the fix.

---

**Prioritized Remediation Roadmap**:
| Priority | ID | Title | Severity | Effort |
|----------|----|-------|----------|--------|

**Residual Risk**: THEORETICAL findings, open questions.

**Suggested Focused Follow-Ups**: 3–5 ready-to-send prompts naming specific discovered components.
'''

THREAT_MODEL_DEEP_TEMPLATE = '''\
{target_line}

## Repository Context

{context}

## Required Report Format

Produce a two-tier Markdown threat model in AGGRESSIVE DEEP-DIVE mode.

### TIER 1 — EXECUTIVE SUMMARY

**Risk Posture**: 1–2 sentences.

**Finding Summary**:
| Severity | Count | CONFIRMED | PLAUSIBLE | THEORETICAL |
|----------|-------|-----------|-----------|-------------|

**Top Immediate Actions** (Critical and High only): business risk and required action per finding.

**Recommended Next Step**: single most important action.

---

### TIER 2 — TECHNICAL THREAT MODEL

**Scope and Assumptions**: reviewed components, excluded areas, numbered assumptions [A-N].

**System Model**: assets with data classifications, actors with trust levels, entry points, trust boundaries.

For each finding:

#### [TM-NNN] — *Finding Title*

**Severity**: CRITICAL / HIGH / MEDIUM / LOW / INFO
**Confidence**: CONFIRMED / PLAUSIBLE / THEORETICAL
**Persona**: applicable attacker persona(s)

| Field | Detail |
|-------|--------|
| STRIDE | |
| OWASP | |
| CWE | |
| Preconditions | |
| Attack Steps | 1. → 2. → 3. |
| Evidence | `path/to/file:NN` |
| Impact | |
| Mitigation | |
| Effort | |

**Remediation Guidance**: numbered steps with before/after snippets.

**Validation**: concrete step that confirms the fix.

---

**Control Bypass Analysis**: for every defensive control examined, state bypass paths found
and their feasibility (feasible / not feasible / requires runtime confirmation).

**Chained Attack Scenarios**: multi-step kill chains combining two or more findings.
Show: foothold → privilege escalation → lateral movement / data access / persistence.

**Coverage Audit**: confirm which categories were evaluated —
injection, authentication, authorization, secrets/credentials, cryptography,
error handling/info disclosure, CI/CD/supply chain, infrastructure/configuration.
For any category with no findings, state the reason tied to the reviewed code.

**Prioritized Remediation Roadmap**:
| Priority | ID | Title | Severity | Effort |
|----------|----|-------|----------|--------|

**Residual Risk and Runtime Blindspots**: THEORETICAL findings, open questions, and a
Runtime Blindspot entry for every security decision deferred to runtime (env vars, IAM, secrets managers).

**Suggested Focused Follow-Ups**: 3–5 ready-to-send prompts naming specific discovered components.
'''


# ─── API callers ─────────────────────────────────────────────────────────────

def _openai_client_and_model(provider, model_override):
    from openai import OpenAI

    if provider == 'github-models':
        token = os.environ.get('GH_TOKEN') or os.environ.get('GITHUB_TOKEN')
        if not token:
            print('ERROR: GH_TOKEN or GITHUB_TOKEN must be set for github-models provider.',
                  file=sys.stderr)
            sys.exit(1)
        return OpenAI(base_url='https://models.inference.ai.azure.com', api_key=token), \
               model_override or 'openai/gpt-4o'

    if provider == 'lmstudio':
        base_url = os.environ.get('LMSTUDIO_BASE_URL', 'http://localhost:1234/v1')
        client = OpenAI(base_url=base_url, api_key='lm-studio')
        model = model_override or os.environ.get('LMSTUDIO_MODEL', '')
        if not model:
            try:
                models = client.models.list()
                loaded = [m.id for m in models.data]
                if not loaded:
                    print('ERROR: No model loaded in LM Studio. '
                          'Open LM Studio, load a model, and start the local server.',
                          file=sys.stderr)
                    sys.exit(1)
                model = loaded[0]
                print(f'Auto-detected LM Studio model: {model}', flush=True)
            except Exception as exc:
                print(f'ERROR: Cannot reach LM Studio at {base_url}: {exc}\n'
                      'Make sure LM Studio is running and the local server is started.',
                      file=sys.stderr)
                sys.exit(1)
        return client, model

    # openai
    return OpenAI(), model_override or 'gpt-4o'


def call_api(provider, system_prompt, user_prompt, model_override):
    client, model = _openai_client_and_model(provider, model_override)
    max_tokens = 8_000 if provider == 'lmstudio' else 16_000

    print(f'Calling {provider} with model {model}...', flush=True)
    response = client.chat.completions.create(
        model=model,
        messages=[
            {'role': 'system', 'content': system_prompt},
            {'role': 'user', 'content': user_prompt},
        ],
        max_tokens=max_tokens,
    )
    return response.choices[0].message.content


# ─── Entry point ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='Run AppSec analysis via OpenAI, GitHub Models, or LM Studio'
    )
    parser.add_argument('--mode', choices=['pr-review', 'threat-model'], required=True)
    parser.add_argument('--provider', choices=['openai', 'github-models', 'lmstudio'], required=True)
    parser.add_argument('--base',   default='', help='Base commit SHA (pr-review only)')
    parser.add_argument('--head',   default='', help='Head commit SHA (pr-review only)')
    parser.add_argument('--target', default='', help='Threat model target (threat-model only)')
    parser.add_argument('--deep',   action='store_true',
                        help='Use aggressive deep-dive mode (threat-model only)')
    parser.add_argument('--output', required=True, help='Output path for the Markdown report')
    parser.add_argument('--model',  default='', help='Model override')
    args = parser.parse_args()

    is_local = args.provider == 'lmstudio'
    max_diff  = MAX_DIFF_CHARS_LOCAL  if is_local else MAX_DIFF_CHARS
    max_file  = MAX_FILE_BYTES_LOCAL  if is_local else MAX_FILE_BYTES

    if args.mode == 'pr-review':
        if not args.base or not args.head:
            print('ERROR: --base and --head are required for pr-review mode.', file=sys.stderr)
            sys.exit(1)
        diff    = get_diff(args.base, args.head, max_chars=max_diff)
        changed = get_changed_files(args.base, args.head)
        files_str    = '\n'.join(f'- {f}' for f in changed[:60])
        user_prompt  = PR_REVIEW_TEMPLATE.format(files=files_str, diff=diff)
        system_prompt = PR_REVIEW_SYSTEM
    else:
        context = gather_repo_context(max_file_bytes=max_file)
        target_line = (
            f'Threat model target: **{args.target}**'
            if args.target
            else (
                'No target specified. Autonomously inventory the repository, rank candidate '
                'components by external exposure, privilege level, sensitive-data handling, and '
                'blast radius, then select the highest-risk scope and explain the selection before '
                'producing the full report.'
            )
        )
        if args.deep:
            user_prompt   = THREAT_MODEL_DEEP_TEMPLATE.format(target_line=target_line, context=context)
            system_prompt = THREAT_MODEL_DEEP_SYSTEM
        else:
            user_prompt   = THREAT_MODEL_TEMPLATE.format(target_line=target_line, context=context)
            system_prompt = THREAT_MODEL_SYSTEM

    report = call_api(args.provider, system_prompt, user_prompt, args.model)

    with open(args.output, 'w') as f:
        f.write(report)

    print(f'Report written to {args.output} ({len(report):,} characters).', flush=True)


if __name__ == '__main__':
    main()
