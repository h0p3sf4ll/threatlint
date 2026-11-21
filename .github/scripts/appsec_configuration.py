#!/usr/bin/env python3
"""Preflight optional model-backed CI reviews using credential-presence booleans.

An unconfigured template reports that no review ran. Enabled reviews fail if the
provider is unavailable; opting in or setting a blocking gate cannot skip analysis.
"""

import os
from pathlib import Path


def evaluate(env):
    provider = env.get('APPSEC_PROVIDER', '').strip() or 'claude'
    has_claude = env.get('HAS_ANTHROPIC_KEY', '').lower() == 'true'
    has_openai = env.get('HAS_OPENAI_KEY', '').lower() == 'true'
    enabled = (
        env.get('EVENT_NAME') == 'workflow_dispatch'
        or env.get('APPSEC_ENABLED', '').lower() == 'true'
        or bool(env.get('APPSEC_PROVIDER', '').strip())
        or env.get('APPSEC_GATE_MODE', '').lower() == 'fail'
        or has_claude
        or has_openai
    )
    if not enabled:
        return False, 'disabled', (
            'No AI security review ran. Automatic model reviews are not configured. '
            'Set APPSEC_REVIEWS_ENABLED=true and configure ANTHROPIC_API_KEY '
            '(default Claude provider), or select openai with APPSEC_PROVIDER and '
            'configure OPENAI_API_KEY. Tests, builds and other checks run separately.'
        )
    if provider == 'github-models':
        return True, 'error', (
            'GitHub Models was retired on July 30, 2026. Select claude or openai '
            'with APPSEC_PROVIDER and configure the matching provider secret. '
            'No AI security review ran. See https://docs.github.com/en/github-models.'
        )
    if provider not in {'claude', 'openai'}:
        return True, 'error', 'Unsupported APPSEC_PROVIDER. Select claude or openai. No AI security review ran.'
    if not (has_claude if provider == 'claude' else has_openai):
        required = 'ANTHROPIC_API_KEY' if provider == 'claude' else 'OPENAI_API_KEY'
        return True, 'error', (
            f'This model review is enabled but {required} is unavailable. Configure '
            'the repository or organization Actions secret and grant this repository '
            'access. No AI security review ran.'
        )
    return True, 'ready', (
        f'The {provider} provider is configured. The separate review job must '
        'complete successfully and produce its report before analysis is considered complete.'
    )


def main(env=None):
    env = os.environ if env is None else env
    enabled, status, message = evaluate(env)
    output = env.get('GITHUB_OUTPUT')
    if output:
        with Path(output).open('a', encoding='utf-8') as stream:
            stream.write(f'enabled={str(enabled).lower()}\n')
    summary = env.get('GITHUB_STEP_SUMMARY')
    if summary:
        with Path(summary).open('a', encoding='utf-8') as stream:
            stream.write(f'## Model review configuration: {status}\n\n{message}\n')
    print(f'::{"error" if status == "error" else "notice"}::{message}')
    return 1 if status == 'error' else 0


if __name__ == '__main__':
    raise SystemExit(main())
