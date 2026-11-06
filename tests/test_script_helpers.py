"""Synthetic regression coverage for bundled, standalone script responsibilities."""
import argparse
import importlib.util
import io
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
from types import SimpleNamespace
import urllib.error

import pytest


ROOT = Path(__file__).resolve().parents[1]
PACKAGED = ROOT / 'src/threatlint/data/scripts'
MIRRORED = ROOT / '.github/scripts'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(params=[PACKAGED, MIRRORED], ids=['packaged', 'ci-mirror'])
def scripts(request):
    return request.param


@pytest.fixture
def api(scripts):
    return load('snapshot_under_test', scripts / 'appsec_api.py')


@pytest.fixture
def chat(scripts):
    return load('conversation_under_test', scripts / 'threatlint_chat.py')


def test_every_snapshot_mode_keeps_canonical_workflows_and_limits(api, monkeypatch):
    calls = []
    monkeypatch.setattr(api, 'required_workflows', lambda mode: f'WORKFLOW:{mode}')
    monkeypatch.setattr(api, 'gather_repo_context', lambda **kw: calls.append(kw) or 'SYNTHETIC REPOSITORY')
    monkeypatch.setattr(api, 'get_diff', lambda *args, **kw: calls.append(kw) or 'SYNTHETIC DIFF')
    monkeypatch.setattr(api, 'get_changed_files', lambda *args: ['a.py', 'b.py'])
    monkeypatch.setattr(api, '_findings_context', lambda path: f'FINDINGS:{path}')

    for mode in api._MODE_TO_AGENT:
        for provider in ('openai', 'lmstudio'):
            parser, args = api._parse_args([
                '--mode', mode, '--provider', provider, '--base', 'base', '--head', 'head',
                '--target', 'synthetic scope', '--findings', 'synthetic.sarif', '--output', 'unused.md',
            ])
            system, user = api.build_prompts(args, parser)
            assert f'WORKFLOW:{mode}' in system
            assert system.endswith(api.SNAPSHOT_RULES)
            assert 'Proposed validation is NOT RUN' in system
            expected = api.MAX_DIFF_CHARS_LOCAL if provider == 'lmstudio' else api.MAX_DIFF_CHARS
            if mode == 'pr-review':
                assert calls[-1] == {'max_chars': expected}
                assert 'SYNTHETIC DIFF' in user and '- a.py\n- b.py' in user
            else:
                expected = api.MAX_FILE_BYTES_LOCAL if provider == 'lmstudio' else api.MAX_FILE_BYTES
                assert calls[-1] == {'max_file_bytes': expected}
                assert 'SYNTHETIC REPOSITORY' in user
            if mode in api._SPECIALIST_MODES or mode == 'fp-review':
                assert 'FINDINGS:synthetic.sarif' in user


def test_snapshot_deep_and_verify_fix_targets_preserve_template_seams(api, monkeypatch):
    monkeypatch.setattr(api, 'gather_repo_context', lambda **kw: 'CONTEXT')
    monkeypatch.setattr(api, 'required_workflows', lambda mode: '')
    parser, args = api._parse_args([
        '--mode', 'threat-model', '--provider', 'lmstudio', '--deep', '--output', 'unused.md',
    ])
    system, user = api.build_prompts(args, parser)
    assert api.THREAT_MODEL_DEEP_SYSTEM in system
    assert api._AUTONOMOUS_THREAT_MODEL_SCOPE in user
    monkeypatch.setattr(api, 'THREAT_MODEL_DEEP_TEMPLATE', '{target_line}|{context}|OVERRIDE')
    assert api.build_prompts(args, parser)[1].endswith('|CONTEXT|OVERRIDE')

    args.mode, args.target = 'verify-fix', 'F-001||source.py:4|description'
    system, user = api.build_prompts(args, parser)
    assert api.VERIFY_FIX_SYSTEM in system
    assert 'F-001' in user and 'source.py:4' in user and 'unspecified' in user


@pytest.mark.parametrize('mode, message', [
    ('pr-review', '--base and --head are required'),
    ('fp-review', '--findings is required'),
])
def test_snapshot_required_inputs_still_fail_before_collection(api, monkeypatch, capsys, mode, message):
    monkeypatch.setattr(api, 'gather_repo_context', lambda **kw: pytest.fail('must validate first'))
    parser, args = api._parse_args(['--mode', mode, '--provider', 'openai', '--output', 'unused.md'])
    with pytest.raises(SystemExit) as exc:
        api.build_prompts(args, parser)
    assert exc.value.code == 2
    assert message in capsys.readouterr().err


def test_snapshot_context_collection_keeps_public_io_seams(api, monkeypatch):
    monkeypatch.setattr(api, 'run', lambda cmd: SimpleNamespace(stdout='x' * 10 if 'diff' in cmd else 'a.py\nb.py\n'))
    assert api.get_diff('a', 'b', max_chars=3) == 'xxx\n\n[diff truncated — 7 additional characters omitted]'
    assert api.get_changed_files('a', 'b') == ['xxxxxxxxxx']
    monkeypatch.setattr(api, '_context_paths', lambda: iter(['a.py', 'b.py']))
    monkeypatch.setattr(api.os.path, 'isfile', lambda path: True)
    monkeypatch.setattr(api, 'read_file_safe', lambda path, max_bytes: f'{path}:{max_bytes}')
    monkeypatch.setattr(api, 'MAX_TOTAL_PARTS', 2)
    assert api.gather_repo_context(3).endswith('## a.py\n```\na.py:3\n```')


def test_snapshot_main_keeps_model_and_gate_seams(api, monkeypatch, tmp_path):
    report = tmp_path / 'report.md'
    calls = []
    monkeypatch.setattr(api, 'build_prompts', lambda args, parser: ('SYSTEM', 'USER'))
    monkeypatch.setattr(api, 'call_api', lambda *args: calls.append(args) or 'synthetic report')
    monkeypatch.setattr(api, '_run_gate', lambda *args: calls.append(args))
    api.main(['--mode', 'threat-model', '--provider', 'lmstudio', '--output', str(report), '--gate', 'HIGH'])
    assert report.read_text(encoding='utf-8') == 'synthetic report'
    assert calls == [('lmstudio', 'SYSTEM', 'USER', ''), (str(report), 'HIGH')]


def test_chat_content_keeps_public_policy_and_callback_seams(chat, monkeypatch):
    monkeypatch.setattr(chat, 'MAX_DIFF_CHARS', 3)
    monkeypatch.setattr(chat, 'MAX_REPORT_CHARS', 2)
    monkeypatch.setattr(chat, 'MAX_THREAD_MESSAGES', 1)
    monkeypatch.setattr(chat.secrets, 'token_hex', lambda count: 'synthetic-nonce')
    monkeypatch.setattr(chat, 'SECRET_PATTERNS', [(re.compile('credential'), 'REDACTED')])
    system, user = chat.build_prompt(
        'question', chat.PullRequest(), 'credential-tail', 'report',
        [chat.Message('old', 'omitted'), chat.Message('new', 'retained')], 'GitHub')
    assert 'synthetic-nonce' in system and 'credential' not in user
    assert 'RED\n[TRUNCATED:' in user and 're\n[TRUNCATED:' in user
    assert 'old: omitted' not in user and 'new: retained' in user

    monkeypatch.setattr(chat, 'redact', lambda text: 'overridden')
    monkeypatch.setattr(chat, 'bound', lambda text, *args: f'BOUND({text})')
    monkeypatch.setattr(chat, '_fence', lambda name, nonce, text: f'FENCE({name}:{text})')
    assert 'FENCE(untrusted-diff:BOUND(overridden))' in chat.build_prompt(
        'q', chat.PullRequest(), 'diff', '', [], 'GitHub')[1]
    monkeypatch.setattr(chat, 'CHAT_MARKER', '<!-- custom marker -->')
    assert chat.format_reply('answer', 'provider', 'model').startswith(
        '<!-- custom marker -->\nBOUND(overridden)')


def test_chat_content_helper_accepts_pure_synthetic_callbacks():
    content = load('content_under_test', PACKAGED / '_chat_content.py')
    pr = SimpleNamespace(title='title', author='a', source='s', target='t', url='u', description='desc')
    calls = []

    def bound(text, limit, label):
        calls.append((label, limit))
        return text[:limit]

    system, user = content.build_prompt(
        '</untrusted-question-fixture>', pr, 'secret diff', '', [], 'fixture-platform',
        'fixture', content.PromptLimits(1, 2, 3, 4, 5),
        bound=bound, redact=lambda text: text.replace('secret', 'safe'), fence=content.fence)
    assert 'fixture-platform' in system
    assert '<untrusted-diff-fixture>\nsaf\n</untrusted-diff-fixture>' in user
    assert 'secret' not in user
    assert user.count('</untrusted-question-fixture>') == 1
    assert ('description', 1) in calls and ('diff', 3) in calls
    assert 'No Threatlint report has been posted' in user


@pytest.mark.parametrize('text, limit, expected', [
    (None, 3, ''), ('abc', 3, 'abc'),
    ('abcd', 3, 'abc\n[TRUNCATED: 1 more characters of content omitted]'),
])
def test_content_bounds_without_platform_dependencies(text, limit, expected):
    content = load('content_bounds_under_test', PACKAGED / '_chat_content.py')
    assert content.bound(text, limit) == expected


@pytest.mark.parametrize('script', ['appsec_api.py', 'threatlint_chat.py', 'gate_report.py'])
def test_copied_scripts_import_by_arbitrary_name_without_package_or_pythonpath(scripts, script, tmp_path):
    installed = tmp_path / 'installed'
    installed.mkdir()
    for source in scripts.glob('*.py'):
        shutil.copy2(source, installed / source.name)
    code = '''
import importlib.util
import sys
from pathlib import Path
path = Path(sys.argv[1])
assert str(path.parent) not in sys.path
assert not any("site-packages" in item for item in sys.path)
spec = importlib.util.spec_from_file_location("arbitrary_host_name", path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
if path.name == "appsec_api.py":
    assert module.PR_REVIEW_TEMPLATE and module._parse_args
elif path.name == "threatlint_chat.py":
    assert module.format_reply("answer", "fixture", "").startswith(module.CHAT_MARKER)
    import io
    def opener(request, timeout=None):
        assert request.get_method() == "POST"
        return io.BytesIO(b'{"choices":[{"message":{"content":"synthetic answer"}}]}')
    assert module.call_model("openai", "system", "user", "fixture-model",
                             {"OPENAI_API_KEY": "synthetic-key"}, opener) == (
                                 "fixture-model", "synthetic answer")
else:
    assert module.parse_findings("") == []
print("standalone import OK")
'''
    result = subprocess.run(
        [sys.executable, '-I', '-S', '-c', code, str(installed / script)],
        cwd=tmp_path, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'standalone import OK'
    help_result = subprocess.run(
        [sys.executable, '-I', '-S', str(installed / script), '--help'],
        cwd=tmp_path, capture_output=True, text=True)
    assert help_result.returncode == 0, help_result.stderr
    assert 'usage:' in help_result.stdout.lower()


def test_copied_snapshot_workflow_fallback_reads_installed_data_without_package(tmp_path):
    data = tmp_path / 'data'
    shutil.copytree(PACKAGED, data / 'scripts', ignore=shutil.ignore_patterns('__pycache__'))
    (data / 'agents').mkdir()
    (data / 'skills/fixture-skill').mkdir(parents=True)
    (data / 'agent-skills.json').write_text(
        json.dumps({'appsec-threat-modeler': ['fixture-skill']}), encoding='utf-8')
    (data / 'agent-contracts.json').write_text(json.dumps({'schemaVersion': 1, 'agents': {
        'appsec-threat-modeler': {'evidenceMode': 'source', 'inputs': 'FIXTURE INPUT', 'outputs': 'FIXTURE OUTPUT', 'boundaries': 'READ ONLY'},
    }}), encoding='utf-8')
    (data / 'agents/appsec-threat-modeler.md').write_text('---\nname: fixture\n---\nAGENT', encoding='utf-8')
    (data / 'skills/fixture-skill/SKILL.md').write_text('---\nname: fixture\n---\nSKILL', encoding='utf-8')
    result = subprocess.run(
        [sys.executable, '-I', '-S', '-c',
         'import runpy, sys; m = runpy.run_path(sys.argv[1]); print(m["required_workflows"]("threat-model"))',
         str(data / 'scripts/appsec_api.py')],
        cwd=tmp_path, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith('AGENT\n\nSKILL\n')
    assert 'FIXTURE INPUT' in result.stdout
    assert 'FIXTURE OUTPUT' in result.stdout
    assert 'READ ONLY' in result.stdout


def test_docx_renderer_remains_standalone_and_preserves_document_blocks(tmp_path):
    pytest.importorskip('docx')
    from docx import Document

    script = tmp_path / 'md_to_docx.py'
    shutil.copy2(PACKAGED / script.name, script)
    source, output = tmp_path / 'fixture.md', tmp_path / 'fixture.docx'
    source.write_text(
        '# Report **title**\n\nText with `code` and *emphasis*.\n'
        '| Finding | Level |\n| --- | --- |\n| F-001 | **HIGH** |\n\n'
        '- Bullet\n1. Numbered\n---\n```python\nprint("fixture")\n```\n',
        encoding='utf-8')
    result = subprocess.run(
        [sys.executable, '-I', str(script), str(source), str(output)],
        cwd=tmp_path, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    document = Document(output)
    texts = [paragraph.text for paragraph in document.paragraphs]
    assert 'Report title' in texts and 'print("fixture")' in texts
    assert document.tables[0].cell(1, 1).text == 'HIGH'
    assert any(run.bold for run in document.paragraphs[0].runs)


def test_script_helpers_are_installed_as_siblings(tmp_path):
    from threatlint.cli import cmd_install

    args = argparse.Namespace(local=True, directory=str(tmp_path), yes=True, quiet=True,
                              lmstudio=False, copilot=False)
    assert cmd_install(args) == 0
    installed = tmp_path / '.claude/scripts'
    for source in PACKAGED.glob('*.py'):
        assert (installed / source.name).read_bytes() == source.read_bytes()


def test_focused_gate_parser_and_thresholds_remain_independent(scripts):
    gate = load('gate_under_test', scripts / 'gate_report.py')
    findings = gate.parse_findings(
        '#### [TM-001] — First\n**Severity**: HIGH\n**Confidence**: CONFIRMED\n'
        '### [CR-002] - Second\n**Severity**: CRITICAL\n**Confidence**: THEORETICAL\n'
        '##### [SG-003] – Incomplete\n')
    assert findings == [
        gate.Finding('TM-001', 'First', 'HIGH', 'CONFIRMED'),
        gate.Finding('CR-002', 'Second', 'CRITICAL', 'THEORETICAL'),
        gate.Finding('SG-003', 'Incomplete', 'UNKNOWN', 'UNKNOWN'),
    ]
    assert gate.gated(findings, 'HIGH', 'PLAUSIBLE') == findings[:1]
    assert gate.gated(findings, 'CRITICAL', 'THEORETICAL') == findings[1:2]
    args = gate.parse_args(['--report', 'fixture.md', '--allow-theoretical'])
    assert args.confidence == 'THEORETICAL'


def test_prompt_catalog_aggregates_coherent_families_without_changing_exports(api, scripts):
    families = {
        'review': {'PR_REVIEW', 'API_SECURITY', 'AUTH_REVIEW'},
        'modeling': {'THREAT_MODEL', 'THREAT_MODEL_DEEP', 'RED_TEAM', 'ATTACK_TREE'},
        'operations': {'SECRETS_SCAN', 'IAC_REVIEW', 'CICD_AUDIT', 'DEPENDENCY_AUDIT'},
        'findings': {'COMPLIANCE_CHECK', 'THREAT_DELTA', 'VERIFY_FIX'},
    }
    catalog = load('catalog_under_test', scripts / '_appsec_prompts.py')
    expected = set()
    for family, modes in families.items():
        module = load(f'family_{family}', scripts / f'_appsec_prompts_{family}.py')
        names = {f'{mode}_{kind}' for mode in modes for kind in ('SYSTEM', 'TEMPLATE')}
        assert {name for name in vars(module) if name.isupper()} == names
        for name in names:
            assert getattr(api, name) == getattr(catalog, name) == getattr(module, name)
        expected.update(names)
    assert {name for name in vars(catalog) if name.isupper()} == expected


def test_chat_http_transport_preserves_bounded_reads_and_request_shape(chat, monkeypatch):
    reads, requests = [], []

    class Response(io.BytesIO):
        def read(self, size=-1):
            reads.append(size)
            return super().read(size)

    def opener(request, timeout=None):
        requests.append((request, timeout))
        return Response(b'abcdef')

    monkeypatch.setattr(chat, 'MAX_RESPONSE_BYTES', 3)
    assert chat.http('POST', 'https://fixture.invalid/path', {'X-Fixture': 'value'},
                     {'fixture': True}, raw=True, timeout=7, opener=opener) == 'abc'
    assert reads == [4]
    request, timeout = requests[0]
    assert timeout == 7 and json.loads(request.data) == {'fixture': True}
    assert request.get_header('X-fixture') == 'value'
    assert request.get_header('User-agent') == 'threatlint-pr-chat'


def test_chat_http_transport_reports_safe_http_error_location(chat):
    def opener(request, timeout=None):
        raise urllib.error.HTTPError(request.full_url, 401, 'unauthorized', {}, None)

    with pytest.raises(chat.ChatError) as exc:
        chat.http('GET', 'https://fixture.invalid/resource?key=synthetic-secret', opener=opener)
    assert str(exc.value) == 'GET /resource returned HTTP 401'


def test_chat_provider_protocols_keep_script_transport_message_and_timeout_seams(chat, monkeypatch):
    calls = []

    def http(*args, **kwargs):
        calls.append((args, kwargs))
        return {'content': [{'type': 'image', 'text': 'ignored'}, {'type': 'text', 'text': 'answer'}]}

    monkeypatch.setattr(chat, 'http', http)
    monkeypatch.setattr(chat, 'MODEL_TIMEOUT', 9)
    monkeypatch.setattr(chat, '_chat_messages', lambda system, user: ['system', 'CUSTOM MESSAGE'])
    model, answer = chat._claude({'url': 'https://fixture.invalid'}, 'system', 'user', 'fixture',
                                 {'ANTHROPIC_API_KEY': 'synthetic'}, None)
    assert (model, answer) == ('fixture', 'answer')
    args, kwargs = calls[0]
    assert args[3]['messages'] == ['CUSTOM MESSAGE']
    assert kwargs == {'timeout': 9, 'opener': None}
    assert args[2]['x-api-key'] == 'synthetic'


def test_chat_provider_dispatch_keeps_script_level_override_seams(chat, monkeypatch):
    monkeypatch.setattr(chat, '_claude', lambda *args: ('claude-override', args[3]))
    assert chat.call_model('claude', 's', 'u', env={'THREATLINT_GENERAL_MODEL': 'env-model'}) == (
        'claude-override', 'env-model')
    monkeypatch.setattr(chat, '_lmstudio_endpoint', lambda *args: ('local-url', None, 'local-model'))
    monkeypatch.setattr(chat, '_hosted_endpoint', lambda *args: ('hosted-url', 'key', 'hosted-model'))
    monkeypatch.setattr(chat, '_chat_completion', lambda url, key, system, user, model, opener: (url, model))
    assert chat.call_model('lmstudio', 's', 'u', env={}) == ('local-url', 'local-model')
    assert chat.call_model('openai', 's', 'u', env={}) == ('hosted-url', 'hosted-model')


def test_chat_local_model_discovery_and_hosted_key_fallback_are_synthetic(chat, monkeypatch):
    calls = []
    monkeypatch.setattr(chat, 'http', lambda *a, **k: calls.append((a, k)) or {'data': [{'id': 'loaded'}]})
    assert chat._lmstudio_endpoint('', {'LMSTUDIO_MODEL': 'preferred'}, None) == (
        'http://localhost:1234/v1/chat/completions', None, 'preferred')
    assert calls[0][0] == ('GET', 'http://localhost:1234/v1/models')
    spec = {'url': 'https://fixture.invalid', 'key': 'GH_TOKEN'}
    assert chat._hosted_endpoint('github-models', spec, 'fixture', {'GITHUB_TOKEN': 'synthetic'}) == (
        'https://fixture.invalid', 'synthetic', 'fixture')
    with pytest.raises(chat.ChatError, match='GH_TOKEN is not configured'):
        chat._hosted_endpoint('github-models', spec, 'fixture', {})


def test_github_context_selection_keeps_dynamic_trigger_and_bounds(chat, monkeypatch):
    context = chat.GitHubComment('', '', '', '', 3, None, 7)
    comments = [
        {'id': 1, 'user': {'login': 'dev'}, 'body': 'selected'},
        {'id': 2, 'body': 'ignored'},
        {'id': 3, 'body': 'selected'},
    ]
    monkeypatch.setattr(chat, 'is_trigger', lambda text: text == 'selected')
    monkeypatch.setattr(chat, 'MAX_MESSAGE_CHARS', 2)
    assert chat._github_thread(None, 7, context, comments) == [
        chat.Message('dev', 'se\n[TRUNCATED: 6 more characters of content omitted]')]


def test_azure_bounded_context_keeps_transport_and_section_seams(chat, monkeypatch):
    calls = []

    def http(method, url, headers, opener=None):
        calls.append(url)
        if '/iterations?' in url:
            return {'value': [{'id': 1}, {'id': 4}]}
        return {'changeEntries': [{'item': {'path': f'/file-{index}'}} for index in range(5)]}

    sections = []
    monkeypatch.setattr(chat, 'http', http)
    monkeypatch.setattr(chat, 'MAX_ADO_FILES', 2)
    monkeypatch.setattr(chat, '_ado_file_section', lambda change, *args: sections.append(change) or 'SECTION')
    result = chat.ado_changed_files('https://fixture.invalid/pr', 'items', 'commit', {}, None)
    assert len(sections) == 2 and result.endswith('SECTION\n\nSECTION')
    assert '/iterations/4/changes?' in calls[-1] and '$top=2' in calls[-1]


def test_azure_file_collection_uses_source_commit_and_handles_deleted_files(chat, monkeypatch):
    calls = []
    monkeypatch.setattr(chat, 'MAX_ADO_FILE_CHARS', 3)
    monkeypatch.setattr(chat, 'http', lambda *a, **k: calls.append(a[1]) or {'content': 'abcdef'})
    section = chat._ado_file_section(
        {'item': {'path': '/a file.py'}}, 'https://fixture.invalid/items', 'source-commit', {}, None)
    assert 'versionDescriptor.version=source-commit' in calls[0]
    assert 'path=%2Fa+file.py' in calls[0]
    assert section.endswith('abc\n[TRUNCATED: 3 more characters of /a file.py omitted]')
    assert chat._ado_file_section({'item': {'isFolder': True, 'path': '/folder'}}, 'items', 'c', {}, None) is None
    chat._ado_file_section({'changeType': 'delete', 'item': {'path': '/removed'}}, 'items', 'c', {}, None)
    assert len(calls) == 1


def test_azure_report_selection_excludes_deleted_comments_and_current_request(chat, monkeypatch):
    context = chat.AdoComment('', '', 4, 12, 'text', 5, None, None)
    threads = [
        {'id': 1, 'comments': [
            {'content': '<!-- threatlint:report -->old', 'publishedDate': '2026-01-01'},
            {'content': '<!-- threatlint:report -->new', 'publishedDate': '2026-02-01'},
            {'content': '<!-- threatlint:report -->deleted', 'publishedDate': '2026-03-01', 'isDeleted': True}]},
        {'id': 12, 'comments': [
            {'id': 2, 'content': 'long message'}, {'id': 4, 'content': 'current question'},
            {'id': 3, 'content': 'deleted', 'isDeleted': True}]},
    ]
    monkeypatch.setattr(chat, 'MAX_MESSAGE_CHARS', 4)
    report, history = chat._ado_report_and_thread(threads, context)
    assert report == '<!-- threatlint:report -->new'
    assert history == [chat.Message('?', 'long\n[TRUNCATED: 8 more characters of content omitted]')]
