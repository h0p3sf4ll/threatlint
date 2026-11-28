"""An enabled security review cannot become a passing configuration skip."""

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('appsec_configuration', ROOT / '.github/scripts/appsec_configuration.py')
CONFIGURATION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONFIGURATION)
AUTOMATIC_WORKFLOWS = [
    'appsec-api-security', 'appsec-auth-review', 'appsec-cicd-audit',
    'appsec-compliance-check', 'appsec-dependency-audit', 'appsec-detect-xshell', 'appsec-iac-review',
    'appsec-pr-review', 'appsec-red-team', 'appsec-scheduled', 'appsec-secrets-scan',
]


def test_unconfigured_automatic_template_reports_an_explicit_skip():
    enabled, status, message = CONFIGURATION.evaluate({'EVENT_NAME': 'pull_request'})
    assert not enabled and status == 'disabled'
    assert 'No AI security review ran' in message
    assert 'APPSEC_REVIEWS_ENABLED=true' in message


@pytest.mark.parametrize('configuration', [
    {'APPSEC_ENABLED': 'true'}, {'EVENT_NAME': 'workflow_dispatch'},
    {'APPSEC_GATE_MODE': 'fail', 'APPSEC_ENABLED': 'false'},
    {'APPSEC_PROVIDER': 'claude'}, {'APPSEC_PROVIDER': 'openai'},
])
def test_requested_and_blocking_reviews_fail_without_credentials(configuration):
    enabled, status, message = CONFIGURATION.evaluate(configuration)
    assert enabled and status == 'error'
    assert 'unavailable' in message and 'No AI security review ran' in message


@pytest.mark.parametrize('provider,credential', [('claude', 'HAS_ANTHROPIC_KEY'), ('openai', 'HAS_OPENAI_KEY')])
def test_existing_provider_configuration_keeps_analysis_enabled(provider, credential):
    enabled, status, message = CONFIGURATION.evaluate({'APPSEC_PROVIDER': provider, credential: 'true'})
    assert enabled and status == 'ready'
    assert 'separate review job must complete' in message


def test_default_claude_credential_keeps_existing_automatic_analysis_enabled():
    assert CONFIGURATION.evaluate({'HAS_ANTHROPIC_KEY': 'true'})[:2] == (True, 'ready')


@pytest.mark.parametrize('provider', ['github-models', 'unknown-provider'])
def test_unavailable_providers_fail_explicitly(provider):
    assert CONFIGURATION.evaluate({'APPSEC_PROVIDER': provider})[:2] == (True, 'error')


def test_runner_outputs_failure_and_honest_summary_without_receiving_secrets(tmp_path, capsys):
    output, summary = tmp_path / 'output', tmp_path / 'summary'
    status = CONFIGURATION.main({'APPSEC_ENABLED': 'true', 'GITHUB_OUTPUT': str(output), 'GITHUB_STEP_SUMMARY': str(summary)})
    assert status == 1
    assert output.read_text(encoding='utf-8') == 'enabled=true\n'
    assert 'No AI security review ran' in summary.read_text(encoding='utf-8')
    assert '::error::' in capsys.readouterr().out


@pytest.mark.parametrize('workflow', AUTOMATIC_WORKFLOWS)
def test_automatic_workflows_gate_only_model_review_on_read_only_preflight(workflow):
    text = (ROOT / '.github/workflows' / f'{workflow}.yml').read_text(encoding='utf-8')
    configuration, review = text.split('    needs: configuration\n', maxsplit=1)
    assert 'name: Model review configuration' in configuration
    assert 'permissions:\n      contents: read\n' in configuration
    assert 'github.event.pull_request.head.repo.full_name == github.repository' in configuration
    assert "HAS_ANTHROPIC_KEY: ${{ secrets.ANTHROPIC_API_KEY != '' }}" in configuration
    assert "HAS_OPENAI_KEY: ${{ secrets.OPENAI_API_KEY != '' }}" in configuration
    assert 'python3 .github/scripts/appsec_configuration.py' in configuration
    assert "needs.configuration.outputs.enabled == 'true'" in review
    assert 'Gate on severity threshold' in review
    assert 'GATE_MODE:' in review
    if workflow == 'appsec-pr-review':
        assert 'github.event.pull_request.draft == false' in configuration
        assert 'github.event.pull_request.draft == false' in review
