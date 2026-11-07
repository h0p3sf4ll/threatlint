"""Synthetic scanner coverage and remediation trust-boundary regressions."""

import copy
import importlib.util
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from threatlint.security_scanner.scan import scan_repository
from threatlint.security_scanner.snapshot import ScannerError
from threatlint.security_scanner.engines import external_scans, normalize_semgrep, normalize_trivy
from threatlint.security_scanner.fixes import apply_fix, propose_fix
from threatlint.security_scanner.github import build_comment, suggestion_payload


def repository(tmp_path):
    subprocess.run(['git', 'init', '-b', 'main', str(tmp_path)], check=True, capture_output=True)
    (tmp_path / 'settings.py').write_text('DEBUG = True\nvalue = 3\n')
    subprocess.run(['git', '-C', str(tmp_path), 'add', '.'], check=True, capture_output=True)
    subprocess.run(['git', '-C', str(tmp_path), '-c', 'user.name=Synthetic', '-c', 'user.email=test@example.invalid',
                    'commit', '-m', 'Synthetic fixture'], check=True, capture_output=True)
    return tmp_path


def proposal(tmp_path):
    repository(tmp_path)
    report = scan_repository(str(tmp_path))
    item = next(item for item in report['findings'] if item['ruleId'] == 'TL-DEBUG-ENABLED')
    return report, propose_fix(report, item['id'])


def test_baseline_covers_categories_redacts_secrets_and_never_claims_full_coverage(tmp_path):
    (tmp_path / 'app.py').write_text('eval(request_data)\nDEBUG = True\n')
    credential = 'ghp_' + 'A' * 40
    (tmp_path / '.env').write_text('TOKEN=' + credential)
    (tmp_path / 'pod.yaml').write_text('securityContext:\n  privileged: true\n')
    (tmp_path / 'package.json').write_text('{"dependencies":{"fixture-library":"^1.0.0"}}')
    report = scan_repository(str(tmp_path), external=lambda files, requested: external_scans(files, requested, which=lambda engine: None))
    assert {finding['category'] for finding in report['findings']} == {'sast', 'sca', 'secrets', 'iac'}
    assert credential not in json.dumps(report)
    assert report['status'] == 'partial'
    assert report['coverage']['status'] == 'partial'
    assert [engine['status'] for engine in report['engines']] == ['completed', 'unavailable', 'unavailable']
    assert report['findings'][0]['severity'] == 'CRITICAL'
    assert all(item['evidence'][0]['verification'] == 'reported' for item in report['findings'])


def test_snapshot_excludes_symlinks_large_files_and_dependency_lock_is_seen(tmp_path):
    outside = tmp_path.parent / 'outside-security-scanner.py'
    outside.write_text('DEBUG = True\n')
    (tmp_path / 'link.py').symlink_to(outside)
    (tmp_path / 'large.py').write_text('x' * 1_000_001)
    (tmp_path / 'package.json').write_text('{"dependencies":{"fixture":"*"}}')
    (tmp_path / 'yarn.lock').write_text('# synthetic lock')
    report = scan_repository(str(tmp_path))
    assert report['findings'] == []
    assert report['coverage']['skipped']['symlink'] == 1
    assert report['coverage']['skipped']['large'] == 1


def test_engine_errors_are_not_clean_and_scanners_only_receive_snapshot(tmp_path):
    seen = []
    def runner(engine, directory):
        seen.append(engine)
        assert sorted(path.name for path in Path(directory).iterdir()) == ['fixture.py']
        return SimpleNamespace(returncode=2, stdout='secret output', stderr='credential output')
    findings, engines = external_scans({'fixture.py': b'print(1)'}, ['semgrep', 'trivy'], runner=runner, which=lambda name: '/synthetic/' + name)
    assert not findings and seen == ['semgrep', 'trivy']
    assert all(engine['status'] == 'failed' for engine in engines)
    assert 'credential' not in json.dumps(engines)


def test_engine_normalization_retains_severity_package_and_secret_redaction():
    semgrep = normalize_semgrep({'results': [{'check_id': 'fixture', 'path': '/scan/a.py', 'start': {'line': 1},
                                              'extra': {'message': 'Fixture', 'severity': 'ERROR', 'metadata': {'severity': 'CRITICAL'}}}]}, '/scan', {'a.py': b'eval(data)'})
    assert semgrep[0]['severity'] == 'CRITICAL' and semgrep[0]['path'] == 'a.py'
    trivy = normalize_trivy({'Results': [{'Target': 'package-lock.json', 'Vulnerabilities': [{'VulnerabilityID': 'SYNTHETIC-001',
                         'PkgName': 'fixture', 'InstalledVersion': '1', 'FixedVersion': '2', 'Severity': 'HIGH'}],
                         'Secrets': [{'RuleID': 'fixture-secret', 'Match': 'DO-NOT-EXPOSE', 'Severity': 'HIGH'}]}]}, '/scan', {'package-lock.json': b'{}'})
    assert trivy[0]['package']['fixedVersion'] == '2'
    assert 'DO-NOT-EXPOSE' not in json.dumps(trivy)


def test_fix_requires_review_then_validates_and_rescans(tmp_path):
    _report, plan = proposal(tmp_path)
    with pytest.raises(ScannerError, match='explicitly confirm'):
        apply_fix(plan)
    result = apply_fix(plan, confirm=True)
    assert (tmp_path / 'settings.py').read_text() == 'DEBUG = False\nvalue = 3\n'
    assert result['validation'] == {'syntax': 'passed', 'baselineRescan': 'passed', 'applicationTests': 'not_run'}
    assert not any(item['id'] == plan['findingId'] for item in result['scan']['findings'])


@pytest.mark.parametrize('change', ['content', 'branch', 'commit', 'replacement', 'path'])
def test_stale_or_tampered_plan_cannot_write(tmp_path, change):
    _report, plan = proposal(tmp_path)
    before = (tmp_path / 'settings.py').read_bytes()
    if change == 'content':
        (tmp_path / 'other.py').write_text('unrelated = 1\n')
    elif change == 'branch':
        subprocess.run(['git', '-C', str(tmp_path), 'checkout', '-b', 'other'], check=True, capture_output=True)
    elif change == 'commit':
        plan['binding']['commit'] = 'a' * 40
    elif change == 'replacement':
        plan['after'] = "__import__('os').system('do not run')"
    else:
        plan['path'] = '../outside.py'
    with pytest.raises(ScannerError):
        apply_fix(plan, confirm=True)
    assert (tmp_path / 'settings.py').read_bytes() == before


def test_failed_rescan_rolls_back_the_exact_original(tmp_path):
    _report, plan = proposal(tmp_path)
    def fail_scan(_repo):
        raise ScannerError('synthetic rescan failed')
    with pytest.raises(ScannerError, match='restored'):
        apply_fix(plan, confirm=True, scan=fail_scan)
    assert (tmp_path / 'settings.py').read_text().startswith('DEBUG = True')


def test_changed_repository_during_rescan_does_not_claim_validated_fix(tmp_path):
    _report, plan = proposal(tmp_path)
    def changed_scan(repo):
        result = scan_repository(repo)
        (tmp_path / 'other.py').write_text('changed = True\n')
        return result
    with pytest.raises(ScannerError, match='restored'):
        apply_fix(plan, confirm=True, scan=changed_scan)
    assert (tmp_path / 'settings.py').read_text().startswith('DEBUG = True')
    assert (tmp_path / 'other.py').read_text() == 'changed = True\n'


def test_auto_apply_requires_specific_explicit_policy(tmp_path):
    _report, plan = proposal(tmp_path)
    with pytest.raises(ScannerError):
        apply_fix(plan, policy={'autoApply': True, 'rules': ['arbitrary']})
    assert apply_fix(plan, policy={'autoApply': True, 'rules': ['TL-DEBUG-ENABLED']})['autoApplied'] is True


def test_protected_files_and_source_strings_are_never_fixable(tmp_path):
    (tmp_path / '.github').mkdir()
    (tmp_path / '.github/settings.py').write_text('DEBUG = True\n')
    (tmp_path / 'credentials.py').write_text('DEBUG = True\n')
    (tmp_path / 'docstring.py').write_text('"""\nDEBUG = True\n"""\n')
    (tmp_path / 'comment.py').write_text('DEBUG = True # ' + 'ghp_' + 'A' * 40 + '\n')
    report = scan_repository(str(tmp_path))
    assert report['findings'] and not any(item['fixAvailable'] for item in report['findings'])
    assert 'ghp_' + 'A' * 40 not in json.dumps(report)


def test_symlink_swap_rejects_fix_and_preserves_external_file(tmp_path):
    _report, plan = proposal(tmp_path)
    outside = tmp_path.parent / 'security-scanner-outside-settings.py'
    outside.write_text('DEBUG = True\nvalue = 3\n')
    (tmp_path / 'settings.py').unlink()
    (tmp_path / 'settings.py').symlink_to(outside)
    with pytest.raises(ScannerError):
        apply_fix(plan, confirm=True)
    assert outside.read_text().startswith('DEBUG = True')


def test_pr_summary_is_compact_sorted_escaped_and_action_is_trusted(tmp_path):
    report, plan = proposal(tmp_path)
    item = copy.deepcopy(report['findings'][0])
    item.update(title='<script>@everyone|injection</script>', severity='CRITICAL')
    report['findings'].append(item)
    comment = build_comment(report, 'javascript:alert(1)')
    assert comment.index('CRITICAL') < comment.index('MEDIUM')
    assert '<script>' not in comment and '@everyone' not in comment and 'javascript:' not in comment
    payload = suggestion_payload(plan, report['binding']['commit'])
    assert payload['side'] == 'RIGHT' and '```suggestion\nDEBUG = False\n```' in payload['body']
    with pytest.raises(ValueError):
        suggestion_payload(plan, 'f' * 40)


def test_cli_is_registered_and_scripts_are_mirrored():
    from threatlint.cli import build_parser
    args = build_parser().parse_args(['security-scanner', 'scan', '--engine', 'semgrep'])
    assert args.engine == ['semgrep'] and callable(args.integration_handler)
    root = Path(__file__).resolve().parents[1]
    for name in ('security_scanner_pr.py', 'security_scanner_fix.py'):
        assert (root / '.github/scripts' / name).read_bytes() == (root / 'src/threatlint/data/scripts' / name).read_bytes()


def test_workflow_has_no_issue_comment_execution_or_target_install():
    root = Path(__file__).resolve().parents[1]
    workflow = (root / '.github/workflows/appsec-auto-fix.yml').read_text()
    assert 'issue_comment:' not in workflow and 'github.event.comment.body' not in workflow
    assert 'expected_sha:' in workflow and 'default: false' in workflow and 'persist-credentials: false' in workflow
    assert 'pip install' not in workflow and 'git add -A' not in workflow


def test_native_suggestions_publish_only_eligible_changed_lines_at_current_head(tmp_path):
    report, plan = proposal(tmp_path)
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location('security_scanner_pr_test', root / '.github/scripts/security_scanner_pr.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    posts = []
    def api(endpoint, *, method='GET', payload=None):
        if method == 'POST':
            posts.append((endpoint, payload))
            return {}
        if '/files?' in endpoint:
            return [{'filename': 'settings.py', 'patch': '@@ -1 +1 @@\n-DEBUG = False\n+DEBUG = True'}]
        return {'head': {'sha': report['binding']['commit'], 'repo': {'full_name': 'fixture/repo'}}}
    assert module.publish(report, 'fixture/repo', 1, 'https://github.com', api=api) == 1
    assert len(posts) == 2
    suggestion = posts[1][1]
    assert suggestion['commit_id'] == plan['binding']['commit'] and suggestion['line'] == 1
    assert '**MEDIUM' in suggestion['body'] and 'Impact:' in suggestion['body'] and '```suggestion' in suggestion['body']
    def stale_api(endpoint, **kwargs):
        return {'head': {'sha': 'f' * 40, 'repo': {'full_name': 'fixture/repo'}}}
    with pytest.raises(ValueError, match='PR changed'):
        module.publish(report, 'fixture/repo', 1, 'https://github.com', api=stale_api)
    assert module.added_lines('@@ -8,2 +8,2 @@\n context\n-before\n+after') == {9}


def test_engine_cancellation_is_not_swallowed():
    from threatlint.security_scanner.snapshot import ScannerCancelled
    def cancelled(engine, directory):
        raise ScannerCancelled('synthetic cancellation')
    with pytest.raises(ScannerCancelled):
        external_scans({}, ['semgrep'], runner=cancelled, which=lambda name: '/synthetic/' + name)


def test_semgrep_uses_shared_pro_policy_and_never_falls_back(monkeypatch):
    from threatlint import semgrep_platform
    from threatlint.security_scanner import engines
    captured = []
    monkeypatch.setattr(semgrep_platform, 'engine_flags', lambda engine: ['--pro'] if engine == 'pro' else pytest.fail('Unexpected engine downgrade'))
    monkeypatch.setattr(semgrep_platform, 'resolve_token', lambda: ('synthetic-token', 'synthetic'))
    monkeypatch.setattr(engines, '_run', lambda args, root, env: captured.append((args, env)) or SimpleNamespace(returncode=0, stdout='{"results":[]}'))
    engines.run_engine('semgrep', '/synthetic')
    assert '--pro' in captured[0][0] and '--oss-only' not in captured[0][0]
    assert captured[0][1]['SEMGREP_APP_TOKEN'] == 'synthetic-token'
    def unavailable(engine):
        raise semgrep_platform.SemgrepError('Synthetic missing Pro')
    monkeypatch.setattr(semgrep_platform, 'engine_flags', unavailable)
    findings, statuses = engines.external_scans({}, ['semgrep'], which=lambda name: '/synthetic/' + name)
    assert not findings and statuses[0]['status'] == 'unavailable'
    assert statuses[0]['mode'] == 'pro' and 'no Community Edition fallback' in statuses[0]['detail']
    assert len(captured) == 1
