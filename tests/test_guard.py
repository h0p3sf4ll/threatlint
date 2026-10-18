import json
import subprocess
import sys
from types import SimpleNamespace

import pytest

from threatlint import guard, ide
from threatlint.guard import RULES_BY_ID, scan_text

AWS = "AKIA" + "IOSFODNN7EXAMPLE"
GH = "ghp_" + "a" * 36
PEM = "-----BEGIN " + "RSA PRIVATE KEY-----"

# rule id -> (language, insecure line, secure line)
CASES = {
    "TL-PY-EVAL": ("python", "result = eval(user_input)", "result = ast.literal_eval(user_input)"),
    "TL-JS-EVAL": ("javascript", "const v = eval(req.body.expr);", "const v = JSON.parse(req.body.expr);"),
    "TL-PY-SHELL": ("python", "subprocess.run(cmd, shell=True, check=False)", "subprocess.run(['ls', path], shell=False, check=False)"),
    "TL-JS-EXEC": ("javascript", "exec(`git log ${branch}`, cb);", "execFile('git', ['log', branch], cb);"),
    "TL-SQL-CONCAT": ("python", 'cursor.execute(f"SELECT * FROM users WHERE id = {uid}")',
                      'cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))'),
    "TL-PY-PICKLE": ("python", "obj = pickle.loads(blob)", "obj = json.loads(blob)"),
    "TL-PY-YAML": ("python", "cfg = yaml.load(stream)", "cfg = yaml.safe_load(stream)"),
    "TL-TLS-VERIFY-OFF": ("python", "requests.get(url, verify=False)", "requests.get(url, verify='/etc/ca.pem')"),
    "TL-WEAK-PASSWORD-HASH": ("python", "digest = hashlib.md5(password.encode()).hexdigest()",
                              "digest = argon2.PasswordHasher().hash(password)"),
    "TL-JS-INSECURE-RANDOM": ("javascript", "const token = Math.random().toString(36);",
                              "const token = crypto.randomBytes(32).toString('hex');"),
    "TL-PY-INSECURE-RANDOM": ("python", "token = random.choice(alphabet)", "token = secrets.token_urlsafe(32)"),
    "TL-SECRET-AWS": ("python", f'key = "{AWS}"', 'key = os.environ["AWS_ACCESS_KEY_ID"]'),
    "TL-SECRET-GITHUB": ("javascript", f"const t = '{GH}';", "const t = process.env.GITHUB_TOKEN;"),
    "TL-SECRET-PRIVATE-KEY": ("python", PEM, "key = load_key_from_vault()"),
    "TL-SECRET-GENERIC": ("python", 'api_key = "s3cr3tV4lu3XYZ123"', 'api_key = os.environ["API_KEY"]'),
    "TL-JS-INNERHTML": ("javascript", "el.innerHTML = comment.body;", "el.textContent = comment.body;"),
    "TL-JS-DANGEROUS-HTML": ("javascript", "<div dangerouslySetInnerHTML={{ __html: html }} />",
                             "<div>{text}</div>"),
    "TL-CORS-WILDCARD-CREDENTIALS": ("javascript", "app.use(cors({ origin: '*', credentials: true }));",
                                     "app.use(cors({ origin: ['https://app.example.com'], credentials: true }));"),
    "TL-PATH-TRAVERSAL": ("javascript", "res.sendFile(path.join(base, req.params.name));",
                          "res.sendFile(safeResolve(base, name));"),
    "TL-JWT-NO-VERIFY": ("python", 'jwt.decode(token, options={"verify_signature": False})',
                         'jwt.decode(token, key, algorithms=["RS256"], audience=AUD)'),
    "TL-DEBUG-ENABLED": ("python", "app.run(host='0.0.0.0', debug=True)", "app.run(debug=os.environ.get('DEBUG') == '1')"),
}


def test_every_rule_has_a_case():
    assert set(CASES) == set(RULES_BY_ID)


@pytest.mark.parametrize("rule_id", sorted(CASES))
def test_rule_positive_and_negative(rule_id):
    language, bad, good = CASES[rule_id]
    assert rule_id in {f.rule_id for f in scan_text(bad, language=language)}
    assert rule_id not in {f.rule_id for f in scan_text(good, language=language)}


def test_rules_have_secure_alternatives():
    for rule in RULES_BY_ID.values():
        assert rule.fix and rule.cwe.startswith("CWE-") and rule.severity in guard.SEVERITIES


def test_secret_snippets_are_redacted():
    finding = scan_text(f'key = "{AWS}"', language="python")[0]
    assert AWS not in finding.snippet and "[redacted]" in finding.snippet


def test_language_scoping():
    assert not scan_text("result = eval(user_input)", language="go")


def test_suppression_requires_rule_and_reason():
    same_line = "result = eval(x)  # threatlint-ignore: TL-PY-EVAL input is a constant table key"
    line_above = "# threatlint-ignore: TL-PY-EVAL validated against allowlist\nresult = eval(x)"
    no_reason = "result = eval(x)  # threatlint-ignore: TL-PY-EVAL"
    wrong_rule = "result = eval(x)  # threatlint-ignore: TL-PY-SHELL not relevant"
    assert not scan_text(same_line, language="python")
    assert not scan_text(line_above, language="python")
    assert scan_text(no_reason, language="python")
    assert scan_text(wrong_rule, language="python")


def test_sarif_shape(tmp_path):
    (tmp_path / "app.py").write_text("obj = pickle.loads(blob)\n")
    sarif = json.loads(guard.to_sarif(guard.scan_paths([str(tmp_path)])))
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "threatlint-guard"
    assert run["tool"]["driver"]["rules"][0]["id"] == "TL-PY-PICKLE"
    result = run["results"][0]
    assert result["ruleId"] == "TL-PY-PICKLE" and result["level"] == "error"
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 1


def test_scan_skips_dependency_directories(tmp_path):
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "lib.js").write_text("eval(x)\n")
    assert not guard.scan_paths([str(tmp_path)])


def test_fail_on_threshold():
    findings = scan_text("token = random.choice(alphabet)", language="python")
    assert guard.failing(findings, "medium")
    assert not guard.failing(findings, "high")
    assert not guard.failing(findings, "none")


def _guard_args(**overrides):
    base = {"hook": False, "list_rules": False, "paths": [], "staged": False, "format": "json", "output": None, "fail_on": "high"}
    base.update(overrides)
    return SimpleNamespace(**base)


def test_cmd_guard_exit_codes(tmp_path, capsys):
    bad = tmp_path / "bad.py"
    bad.write_text("subprocess.run(cmd, shell=True, check=False)\n")
    assert guard.cmd_guard(_guard_args(paths=[str(bad)])) == 1
    assert json.loads(capsys.readouterr().out)["findings"][0]["rule_id"] == "TL-PY-SHELL"
    good = tmp_path / "good.py"
    good.write_text("subprocess.run(['ls'], shell=False, check=False)\n")
    assert guard.cmd_guard(_guard_args(paths=[str(good)])) == 0


def test_hook_mode_exit_codes(tmp_path, capsys):
    bad = tmp_path / "bad.py"
    bad.write_text("cfg = yaml.load(stream)\n")
    payload = json.dumps({"hook_event_name": "PostToolUse", "tool_name": "Write", "tool_input": {"file_path": str(bad)}})
    assert guard.run_hook(payload) == 2
    assert "TL-PY-YAML" in capsys.readouterr().err
    good = tmp_path / "good.py"
    good.write_text("cfg = yaml.safe_load(stream)\n")
    assert guard.run_hook(json.dumps({"tool_input": {"file_path": str(good)}})) == 0
    assert guard.run_hook("not json") == 0


def test_cli_hook_subprocess(tmp_path):
    bad = tmp_path / "bad.js"
    bad.write_text("el.innerHTML = userHtml;\n")
    result = subprocess.run([sys.executable, "-m", "threatlint", "guard", "--hook"],
                            input=json.dumps({"tool_input": {"file_path": str(bad)}}),
                            capture_output=True, text=True, check=False)
    assert result.returncode == 2 and "TL-JS-INNERHTML" in result.stderr


def test_ide_install_is_idempotent_and_non_destructive(tmp_path):
    (tmp_path / "CLAUDE.md").write_text("# Project\n\nKeep this.\n")
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text(json.dumps({"permissions": {"allow": ["Bash(ls)"]}}))
    (tmp_path / ".vscode").mkdir()
    (tmp_path / ".vscode" / "tasks.json").write_text(json.dumps({"version": "2.0.0", "tasks": [{"label": "build"}]}))

    first = ide.install(tmp_path, list(ide.EDITORS))
    assert "added" in first.values()
    snapshot = {p: p.read_text() for p in tmp_path.rglob("*") if p.is_file()}
    second = ide.install(tmp_path, list(ide.EDITORS))
    assert set(second.values()) == {"unchanged"}
    assert snapshot == {p: p.read_text() for p in tmp_path.rglob("*") if p.is_file()}

    claude_md = (tmp_path / "CLAUDE.md").read_text()
    assert "Keep this." in claude_md and claude_md.count(ide.BEGIN) == 1
    settings = json.loads((tmp_path / ".claude" / "settings.json").read_text())
    assert settings["permissions"] == {"allow": ["Bash(ls)"]}
    hook = settings["hooks"]["PostToolUse"][0]
    assert hook["matcher"] == "Edit|Write|MultiEdit" and hook["hooks"][0]["command"] == "threatlint guard --hook"
    tasks = json.loads((tmp_path / ".vscode" / "tasks.json").read_text())["tasks"]
    assert tasks[0] == {"label": "build"} and len(tasks) == 1 + len(ide.VSCODE_TASKS)
    assert (tmp_path / ".github" / "instructions" / "threatlint-secure-code.instructions.md").read_text().startswith('---\napplyTo: "**"')
    assert "alwaysApply: true" in (tmp_path / ".cursor" / "rules" / "threatlint-secure-code.mdc").read_text()
    assert ide.BEGIN in (tmp_path / ".windsurfrules").read_text()
    assert "threatlint-guard" in (tmp_path / ".pre-commit-config.yaml").read_text()


def test_ide_install_updates_stale_section(tmp_path):
    target = tmp_path / ".windsurfrules"
    target.write_text(f"before\n{ide.BEGIN}\nold rules\n{ide.END}\nafter\n")
    assert ide.upsert_section(target) == "updated"
    text = target.read_text()
    assert "old rules" not in text and text.startswith("before\n") and text.endswith("after\n")


def test_ide_install_editor_subset(tmp_path):
    ide.install(tmp_path, ["cursor"])
    assert (tmp_path / ".cursor" / "rules" / "threatlint-secure-code.mdc").exists()
    assert not (tmp_path / "CLAUDE.md").exists() and not (tmp_path / ".github").exists()


def test_common_false_positives_are_not_flagged():
    assert not scan_text("const m = /x/.exec(line);", language="javascript")
    assert not scan_text("model.eval()", language="python")
    assert not scan_text("el.innerHTML = DOMPurify.sanitize(html);", language="javascript")
    assert not scan_text('msg = "eval() is dangerous"', language="python")


def test_file_level_suppression_names_rules():
    header = "# threatlint-ignore-file: TL-PY-EVAL test fixtures\n"
    assert not scan_text(header + "eval(x)", language="python")
    assert scan_text(header + "pickle.loads(b)", language="python")
    assert scan_text("# threatlint-ignore-file: ALL everything\neval(x)", language="python")


def test_suppression_lists_multiple_rules():
    line = "subprocess.run(eval(x), shell=True, check=False)  # threatlint-ignore: TL-PY-EVAL, TL-PY-SHELL constant fixture"
    assert not scan_text(line, language="python")
