"""Synthetic scanner coverage and remediation trust-boundary regressions."""

import copy
import importlib.util
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from threatlint.security_scanner.scan import scan_repository
from threatlint.security_scanner.snapshot import ScannerError, snapshot
from threatlint.security_scanner.engines import external_scans, normalize_semgrep, normalize_trivy
from threatlint.security_scanner.fixes import apply_fix, propose_fix, supports_safe_replacement
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


def assert_advisory_if_unsupported(plan, **kwargs):
    """Exercise the real platform's denied-write contract rather than skip tests."""
    if supports_safe_replacement():
        return False
    repository = plan['binding']['repository']
    before = snapshot(repository)
    def unexpected_rescan(_repo):
        pytest.fail('An unsupported writer must not reach the rescan callback')
    assert plan['canApply'] is False
    assert 'apply the reviewed diff manually' in plan['applyUnavailableReason']
    with pytest.raises(ScannerError, match='apply the reviewed diff manually.*No files were changed'):
        apply_fix(plan, scan=unexpected_rescan, **kwargs)
    assert snapshot(repository) == before
    return True


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
    if assert_advisory_if_unsupported(plan, confirm=True):
        return
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
    if assert_advisory_if_unsupported(plan, confirm=True):
        return
    def fail_scan(_repo):
        raise ScannerError('synthetic rescan failed')
    with pytest.raises(ScannerError, match='restored'):
        apply_fix(plan, confirm=True, scan=fail_scan)
    assert (tmp_path / 'settings.py').read_text().startswith('DEBUG = True')


def test_changed_repository_during_rescan_does_not_claim_validated_fix(tmp_path):
    _report, plan = proposal(tmp_path)
    if assert_advisory_if_unsupported(plan, confirm=True):
        assert not (tmp_path / 'other.py').exists()
        return
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
    if assert_advisory_if_unsupported(plan, policy={'autoApply': True, 'rules': ['TL-DEBUG-ENABLED']}):
        return
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


@pytest.mark.parametrize(('rule', 'source', 'expected'), [
    ('TL-PY-YAML', 'import yaml\nresult = yaml.load(data)\n', 'result = yaml.safe_load(data)'),
    ('TL-PY-YAML', 'import yaml\nresult = yaml.unsafe_load(data)\n', 'result = yaml.safe_load(data)'),
    ('TL-PY-YAML', 'import yaml\nresult = yaml.load_all(data)\n', 'result = yaml.safe_load_all(data)'),
    ('TL-PY-YAML', 'import yaml\nresult = yaml.load(data, Loader=yaml.Loader)\n', 'result = yaml.load(data, Loader=yaml.SafeLoader)'),
    ('TL-PY-YAML', 'import yaml\nresult = yaml.load_all(data, Loader=yaml.CUnsafeLoader)\n', 'result = yaml.load_all(data, Loader=yaml.CSafeLoader)'),
    ('TL-TLS-VERIFY-OFF', 'import requests\ndef fetch(url):\n    return requests.get(url, verify=False)\n', '    return requests.get(url, verify=True)'),
    ('TL-TLS-VERIFY-OFF', 'import requests\r\nresponse = requests.get("https://example.invalid/é", verify=False) # keep\r\n', 'response = requests.get("https://example.invalid/é", verify=True) # keep'),
])
def test_supported_source_edits_are_precise_reviewable_and_rescanned(tmp_path, rule, source, expected):
    file = tmp_path / 'app.py'
    file.write_bytes(source.encode())
    report = scan_repository(str(tmp_path))
    item = next(item for item in report['findings'] if item['ruleId'] == rule)
    assert item['fixAvailable']
    plan = propose_fix(report, item['id'])
    assert plan['after'] == expected and plan['ruleId'] == rule
    with pytest.raises(ScannerError):
        apply_fix(plan, policy={'autoApply': True, 'rules': ['TL-DEBUG-ENABLED']})
    bound_plan = {**plan, 'binding': {**plan['binding'], 'commit': 'a' * 40}}
    payload = suggestion_payload(bound_plan, 'a' * 40)
    assert expected in payload['body'] and 'Commit this native suggestion' in payload['body']
    bound_plan['after'] += '; malicious()'
    with pytest.raises(ValueError):
        suggestion_payload(bound_plan, 'a' * 40)
    if assert_advisory_if_unsupported(plan, policy={'autoApply': True, 'rules': [rule]}):
        assert file.read_bytes() == source.encode()
        return
    result = apply_fix(plan, policy={'autoApply': True, 'rules': [rule]})
    assert result['autoApplied'] and result['validation']['baselineRescan'] == 'passed'
    assert file.read_bytes() == source.replace(plan['before'], expected).encode()


@pytest.mark.parametrize('source', [
    'yaml.load(data)',
    'import yaml\nyaml = unknown\nyaml.load(data)',
    'import yaml, alternate as yaml\nyaml.load(data)',
    'import yaml\ndef f(yaml):\n    return yaml.load(data)',
    'import yaml\nyaml.load(data, Loader=CustomLoader)',
    'import yaml\nyaml.load(data, yaml.Loader)',
    'import yaml\nyaml.load(data, **options)',
    'import yaml\nyaml.load(a); yaml.load(b)',
    'import yaml\n"""\nyaml.load(data)\n"""',
    'import yaml\nsetattr(yaml, "load", replacement)\nyaml.load(data)',
    'import requests\nrequests.get = replacement\nrequests.get(url, verify=False)',
    'import requests, alternate as requests\nrequests.get(url, verify=False)',
    'import requests\nrequests.__dict__["get"] = replacement\nrequests.get(url, verify=False)',
    'import requests\ndef f(requests):\n    return requests.get(url, verify=False)',
    'import requests\nother.get(url, verify=False)',
    'import requests\nrequests.get(url, verify=False, **options)',
    'import requests\nrequests.get(\n    url, verify=False\n)',
])
def test_ambiguous_source_calls_remain_advisory(tmp_path, source):
    (tmp_path / 'app.py').write_text(source + '\n')
    report = scan_repository(str(tmp_path))
    assert report['findings']
    assert not any(item['fixAvailable'] for item in report['findings'])


def test_local_library_shadowing_and_secret_bearing_lines_are_advisory(tmp_path):
    (tmp_path / 'requests.py').write_text('# local module\n')
    (tmp_path / 'app.py').write_text('import requests\nrequests.get(url, verify=False)\n')
    assert not any(item['fixAvailable'] for item in scan_repository(str(tmp_path))['findings'])
    (tmp_path / 'requests.py').unlink()
    (tmp_path / 'app.py').write_text('import requests\nrequests.get(url, verify=False) # ghp_' + 'A' * 40 + '\n')
    assert not any(item['fixAvailable'] for item in scan_repository(str(tmp_path))['findings'])


@pytest.mark.parametrize('change', ['failed', 'missing-baseline', 'finding-limit'])
def test_incomplete_rescan_rolls_back_even_when_finding_is_absent(tmp_path, change):
    _report, plan = proposal(tmp_path)
    if assert_advisory_if_unsupported(plan, confirm=True):
        return
    def incomplete(repo):
        scan = scan_repository(repo)
        if change == 'failed':
            scan['status'] = 'failed'
        elif change == 'missing-baseline':
            scan['engines'] = []
        else:
            scan['coverage']['findingLimitReached'] = True
        return scan
    with pytest.raises(ScannerError, match='restored'):
        apply_fix(plan, confirm=True, scan=incomplete)
    assert (tmp_path / 'settings.py').read_text().startswith('DEBUG = True')


def test_engine_provenance_records_only_supported_fields():
    from threatlint.security_scanner.engines import engine_provenance
    semgrep = engine_provenance('semgrep', json.dumps({'version': '1.183.0', 'token': 'never-display'}))
    assert semgrep['engineVersion'] == '1.183.0'
    assert semgrep['rulePack'] == {'source': 'p/security-audit', 'revision': 'unrecorded', 'pinned': False}
    trivy = engine_provenance('trivy', json.dumps({'Version': '0.76.1', 'VulnerabilityDB': {
        'Version': 2, 'UpdatedAt': '2026-11-07T12:00:00Z', 'DownloadedAt': '2026-11-07T13:00:00.123Z',
        'secret': 'never-display', 'NextUpdate': 'not-a-timestamp'}}))
    assert trivy['databases']['VulnerabilityDB'] == {'schemaVersion': 2, 'updatedAt': '2026-11-07T12:00:00Z', 'downloadedAt': '2026-11-07T13:00:00.123Z'}
    assert 'never-display' not in json.dumps([semgrep, trivy])
    assert engine_provenance('trivy', '{bad')['engineVersion'] == 'unrecorded'


def test_branch_and_packaged_python_changes_trigger_validation():
    root = Path(__file__).resolve().parents[1]
    unit = (root / '.github/workflows/tests.yml').read_text()
    desktop = (root / '.github/workflows/desktop-build.yml').read_text()
    assert "'codex/security-platform-foundation'" in unit and "'codex/security-platform-foundation'" in desktop
    assert desktop.count("- 'src/threatlint/**'") == 2
    assert desktop.count("- 'pyproject.toml'") == 2
    workflow = (root / '.github/workflows/security-scanner.yml').read_text()
    assert 'github.event.pull_request.base.sha || github.event.repository.default_branch' in workflow
    fix = (root / '.github/workflows/appsec-auto-fix.yml').read_text()
    assert 'default: none' in fix and 'options: [none, TL-DEBUG-ENABLED, TL-PY-YAML, TL-TLS-VERIFY-OFF]' in fix


def test_workflow_script_prepares_new_rule_without_publication(tmp_path, monkeypatch):
    repo = repository(tmp_path / 'repo')
    (repo / 'settings.py').write_text('import yaml\nparsed = yaml.load(data, Loader=yaml.Loader)\n')
    subprocess.run(['git', '-C', str(repo), 'add', '.'], check=True, capture_output=True)
    subprocess.run(['git', '-C', str(repo), '-c', 'user.name=Synthetic', '-c', 'user.email=test@example.invalid', 'commit', '-m', 'Synthetic loader'], check=True, capture_output=True)
    report = scan_repository(str(repo))
    finding = next(item for item in report['findings'] if item['ruleId'] == 'TL-PY-YAML')
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location('security_scanner_fix_preview_test', root / '.github/scripts/security_scanner_fix.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    calls = []
    original_run = module.run
    def run(args, **kwargs):
        calls.append(args)
        assert args[:2] == ['git', 'check-ref-format']
        return original_run(args, **kwargs)
    monkeypatch.setattr(module, 'run', run)
    output = tmp_path / 'output'
    assert module.main(['--repo', str(repo), '--repository', 'fixture/repo', '--base-branch', 'main',
                        '--expected-sha', report['binding']['commit'], '--finding-id', finding['id'], '--output-dir', str(output)]) == 0
    plan = json.loads((output / 'proposal.json').read_text())
    assert plan['ruleId'] == 'TL-PY-YAML' and plan['after'] == 'parsed = yaml.load(data, Loader=yaml.SafeLoader)'
    assert len(calls) == 1 and 'yaml.Loader' in (repo / 'settings.py').read_text()


@pytest.mark.parametrize('authorization', [{'confirm': True}, {'policy': {'autoApply': True, 'rules': ['TL-DEBUG-ENABLED']}}])
def test_missing_write_capability_preserves_proposal_and_denies_without_mutation(tmp_path, monkeypatch, authorization):
    from threatlint.security_scanner import fixes
    repository(tmp_path)
    monkeypatch.setattr(fixes, 'supports_safe_replacement', lambda: False)
    report = scan_repository(str(tmp_path))
    finding = next(item for item in report['findings'] if item['ruleId'] == 'TL-DEBUG-ENABLED')
    assert finding['fixAvailable'] and finding['localApplyAvailable'] is False
    assert report['policy']['localApplySupported'] is False
    plan = propose_fix(report, finding['id'])
    assert plan['canApply'] is False and plan['after'] == 'DEBUG = False'
    assert 'apply the reviewed diff manually' in plan['applyUnavailableReason']
    before = snapshot(str(tmp_path))
    monkeypatch.setattr(fixes, '_replace', lambda *_: pytest.fail('Unsupported platforms must never enter the writer'))
    with pytest.raises(ScannerError, match='apply the reviewed diff manually.*No files were changed') as error:
        apply_fix(plan, scan=lambda *_: pytest.fail('No rescan may run'), **authorization)
    assert 'restored' not in str(error.value)
    assert snapshot(str(tmp_path)) == before
    # A reviewable diff remains useful for external native GitHub suggestions.
    assert 'DEBUG = False' in suggestion_payload(plan, report['binding']['commit'])['body']


@pytest.mark.parametrize('missing', ['open', 'rename', 'stat', 'unlink', 'follow_symlinks', 'O_NOFOLLOW', 'O_DIRECTORY', 'fchmod'])
def test_safe_writer_requires_all_used_filesystem_capabilities(monkeypatch, missing):
    from threatlint.security_scanner import fixes
    if missing in {'open', 'rename', 'stat', 'unlink'}:
        monkeypatch.setattr(fixes.os, 'supports_dir_fd', fixes.os.supports_dir_fd - {getattr(fixes.os, missing)})
    elif missing == 'follow_symlinks':
        monkeypatch.setattr(fixes.os, 'supports_follow_symlinks', fixes.os.supports_follow_symlinks - {fixes.os.stat})
    else:
        monkeypatch.delattr(fixes.os, missing, raising=False)
    assert fixes.supports_safe_replacement() is False
