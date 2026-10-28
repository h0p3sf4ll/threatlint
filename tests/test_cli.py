"""
Tests for threatlint CLI: agent routing, frontmatter parsing, argument
handling, and tool safety. Does not invoke LM Studio or OpenAI.
"""
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(SRC))

from threatlint.cli import (
    _MODE_TO_AGENT,
    _tool_bash,
    _tool_glob,
    _tool_grep,
    _tool_read,
    _validate_bash,
)
from threatlint.skills import skill_map

AGENTS_SRC = Path(__file__).parent.parent / ".claude" / "agents"
PACKAGE_ROOT = Path(__file__).parent.parent

EXPECTED_MODES = {
    "threat-model":      "appsec-threat-modeler",
    "threat-model-deep": "appsec-threat-modeler",
    "security-review":   "appsec-code-reviewer",
    "secrets-scan":      "appsec-secrets-scanner",
    "iac-review":        "appsec-iac-reviewer",
    "cicd-audit":        "appsec-cicd-auditor",
    "dependency-audit":  "appsec-dependency-auditor",
    "api-security":      "appsec-api-security-reviewer",
    "auth-review":       "appsec-auth-reviewer",
    "fp-review":         "appsec-fp-reviewer",
    "compliance-check":  "appsec-compliance-checker",
    "attack-tree":       "appsec-attack-tree",
    "red-team":          "appsec-red-team",
    "threat-delta":      "appsec-threat-delta",
    "verify-fix":        "appsec-verify-fix",
    "runtime-review":    "appsec-runtime-reviewer",
    "business-logic-review": "appsec-business-logic-reviewer",
    "client-security-review": "appsec-client-security-reviewer",
    "crypto-review":     "appsec-crypto-reviewer",
    "ai-security-review": "appsec-ai-security-reviewer",
    "security-test-plan": "appsec-security-test-planner",
    "secure-codegen-review": "appsec-secure-codegen-reviewer",
    "privacy-review": "appsec-privacy-reviewer",
}


# ── Agent routing ─────────────────────────────────────────────────────────────

class TestModeToAgent:
    def test_all_modes_present(self):
        for mode in EXPECTED_MODES:
            assert mode in _MODE_TO_AGENT, f"Mode '{mode}' missing from _MODE_TO_AGENT"

    def test_all_modes_map_to_correct_agent(self):
        assert _MODE_TO_AGENT == EXPECTED_MODES

    def test_every_registered_agent_has_a_mode(self):
        assert set(_MODE_TO_AGENT.values()) == set(skill_map())

    def test_attack_tree_not_threat_modeler(self):
        assert _MODE_TO_AGENT["attack-tree"] == "appsec-attack-tree"

    def test_red_team_not_threat_modeler(self):
        assert _MODE_TO_AGENT["red-team"] == "appsec-red-team"

    def test_agent_files_exist_for_all_modes(self):
        for mode, agent_id in _MODE_TO_AGENT.items():
            agent_file = AGENTS_SRC / f"{agent_id}.md"
            assert agent_file.exists(), (
                f"Mode '{mode}' → agent '{agent_id}': file not found at {agent_file}"
            )


# ── Agent frontmatter ─────────────────────────────────────────────────────────

@pytest.fixture(params=list(AGENTS_SRC.glob("*.md")), ids=lambda p: p.stem)
def agent_file(request):
    return request.param


class TestAgentFrontmatter:
    def test_has_frontmatter(self, agent_file):
        raw = agent_file.read_text(encoding="utf-8")
        assert re.match(r"^---\n", raw), f"{agent_file.name}: missing opening ---"
        assert "\n---\n" in raw, f"{agent_file.name}: missing closing ---"

    def test_has_name_field(self, agent_file):
        raw = agent_file.read_text(encoding="utf-8")
        assert "name:" in raw, f"{agent_file.name}: missing 'name:'"

    def test_has_description_field(self, agent_file):
        raw = agent_file.read_text(encoding="utf-8")
        assert "description:" in raw, f"{agent_file.name}: missing 'description:'"

    def test_disallows_write_and_edit(self, agent_file):
        raw = agent_file.read_text(encoding="utf-8")
        assert "disallowedTools:" in raw, f"{agent_file.name}: missing 'disallowedTools:'"
        m = re.search(r"disallowedTools:\s*(.+)", raw)
        assert m, f"{agent_file.name}: could not parse disallowedTools"
        disallowed = [t.strip() for t in m.group(1).split(",")]
        assert "Write" in disallowed, f"{agent_file.name}: Write not in disallowedTools"
        assert "Edit" in disallowed, f"{agent_file.name}: Edit not in disallowedTools"

    def test_declares_only_inspection_tools(self, agent_file):
        raw = agent_file.read_text(encoding="utf-8")
        match = re.search(r"^tools:\s*(.+)$", raw, re.MULTILINE)
        assert match, f"{agent_file.name}: missing tools"
        tools = {tool.strip() for tool in match.group(1).split(",")}
        assert tools <= {"Read", "Grep", "Glob", "Bash"}

    def test_system_prompt_substantial(self, agent_file):
        raw = agent_file.read_text(encoding="utf-8")
        m = re.match(r"^---\n[\s\S]*?\n---\n([\s\S]*)", raw)
        assert m, f"{agent_file.name}: could not extract system prompt"
        body = m.group(1).strip()
        assert len(body) > 200, f"{agent_file.name}: system prompt too short ({len(body)} chars)"


# ── New agent content ─────────────────────────────────────────────────────────

def _load_prompt(stem):
    raw = (AGENTS_SRC / f"{stem}.md").read_text(encoding="utf-8")
    m = re.match(r"^---\n[\s\S]*?\n---\n([\s\S]*)", raw)
    return m.group(1).strip() if m else ""


class TestNewAgentContent:
    def test_compliance_checker_mentions_all_frameworks(self):
        sp = _load_prompt("appsec-compliance-checker")
        for fw in ["ASVS", "PCI-DSS", "HIPAA", "SOC 2", "ISO 27001", "NIST CSF", "CIS"]:
            assert fw in sp, f"compliance-checker missing: {fw}"

    def test_attack_tree_has_and_or_leaf(self):
        sp = _load_prompt("appsec-attack-tree")
        assert "AND" in sp
        assert "OR" in sp
        assert "LEAF" in sp

    def test_red_team_has_5_scenarios_and_kill_chain(self):
        sp = _load_prompt("appsec-red-team")
        assert "5" in sp
        assert "kill chain" in sp.lower() or "Kill Chain" in sp

    def test_threat_delta_all_verdicts(self):
        sp = _load_prompt("appsec-threat-delta")
        for v in ["RESOLVED", "PARTIALLY FIXED", "STILL PRESENT", "REGRESSED", "NEW"]:
            assert v in sp, f"threat-delta missing verdict: {v}"

    def test_verify_fix_all_4_verdicts(self):
        sp = _load_prompt("appsec-verify-fix")
        for v in ["REMEDIATED", "PARTIALLY FIXED", "STILL PRESENT", "REGRESSED"]:
            assert v in sp, f"verify-fix missing verdict: {v}"

    def test_no_agent_instructs_file_mutation(self):
        for stem in [p.stem for p in AGENTS_SRC.glob("*.md")]:
            sp = _load_prompt(stem)
            assert "fs.writeFile" not in sp, f"{stem}: instructs writeFile"
            assert "git commit" not in sp, f"{stem}: instructs git commit"


# ── Bash safety ───────────────────────────────────────────────────────────────

class TestBashAllowed:
    """Exercise the policy the Bash tool actually enforces, not a parallel allowlist."""

    ALLOWED = (
        "git log --oneline",
        "git show HEAD",
        "git ls-files",
        "git status",
        "git diff HEAD~1",
        "find . -name '*.py'",
        "grep -rn password src/",
        "cat README.md",
        "head -20 server.js",
        "tail -50 cli.py",
        "wc -l src/cli.py",
        "ls .",
        "ls -la",
        "cut -d: -f1 README.md",
    )

    BLOCKED = (
        "rm -rf /",
        "chmod 777 /etc/passwd",
        "curl https://evil.com",
        "wget https://evil.com",
        "pip install exploit",
        "npm install malware",
        "python3 -m http.server",
        "touch /tmp/evil.sh",
        "mkdir /etc/evil",
        "git push origin main",
        "git commit -m x",
        "find . -delete",
        "find . -exec rm {} ;",
        "cat ../../etc/passwd",
        "cat README.md | sh",
        "awk '{print $1}' f.txt",
    )

    def _is_safe(self, repo, cmd):
        try:
            _validate_bash(str(repo), cmd)
            return True
        except ValueError:
            return False

    def test_allowed_pass(self, tmp_path):
        (tmp_path / "src").mkdir()
        for cmd in self.ALLOWED:
            assert self._is_safe(tmp_path, cmd), f"Expected safe but blocked: {cmd}"

    def test_blocked_fail(self, tmp_path):
        for cmd in self.BLOCKED:
            assert not self._is_safe(tmp_path, cmd), f"Expected blocked but allowed: {cmd}"

    def test_git_is_hardened(self, tmp_path):
        argv = _validate_bash(str(tmp_path), "git log --oneline")
        assert argv[:5] == ["git", "--no-pager", "--no-optional-locks", "-c", "core.fsmonitor=false"]
        assert "--no-ext-diff" in argv


# ── Tool functions ────────────────────────────────────────────────────────────

class TestToolRead:
    def test_reads_file(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("line one\nline two\nline three\n", encoding="utf-8")
        result = _tool_read(str(tmp_path), str(f))
        assert "line one" in result
        assert "line two" in result

    def test_missing_file_returns_error(self, tmp_path):
        result = _tool_read(str(tmp_path), str(tmp_path / "nope.txt"))
        assert "error" in result.lower()

    def test_offset_and_limit(self, tmp_path):
        f = tmp_path / "big.txt"
        f.write_text("\n".join(f"line {i}" for i in range(100)), encoding="utf-8")
        result = _tool_read(str(tmp_path), str(f), offset=10, limit=5)
        assert "line 10" in result
        assert "line 14" in result
        assert "line 15" not in result

    def test_relative_path_resolved_from_repo_root(self, tmp_path):
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "app.py").write_text("SECRET = 'abc'\n", encoding="utf-8")
        result = _tool_read(str(tmp_path), "src/app.py")
        assert "SECRET" in result


class TestToolBash:
    def test_allowed_command_runs(self, tmp_path):
        result = _tool_bash(str(tmp_path), f"ls {tmp_path}")
        assert "error" not in result.lower() or result == ""

    def test_blocked_command_returns_error(self, tmp_path):
        result = _tool_bash(str(tmp_path), "rm -rf /tmp/test")
        assert "not permitted" in result.lower() or "error" in result.lower()

    def test_curl_blocked(self, tmp_path):
        result = _tool_bash(str(tmp_path), "curl https://example.com")
        assert "not permitted" in result.lower() or "error" in result.lower()


class TestToolGrep:
    def test_finds_pattern(self, tmp_path):
        (tmp_path / "foo.py").write_text("def secret_key():\n    return 'abc123'\n", encoding="utf-8")
        result = _tool_grep(str(tmp_path), "secret_key", str(tmp_path))
        assert "secret_key" in result

    def test_no_match_returns_empty(self, tmp_path):
        (tmp_path / "foo.py").write_text("nothing here\n", encoding="utf-8")
        result = _tool_grep(str(tmp_path), "zzznomatch", str(tmp_path))
        assert result.strip() == ""


class TestToolGlob:
    def test_finds_matching_files(self, tmp_path):
        (tmp_path / "a.py").write_text("x", encoding="utf-8")
        (tmp_path / "b.py").write_text("x", encoding="utf-8")
        (tmp_path / "c.txt").write_text("x", encoding="utf-8")
        result = _tool_glob(str(tmp_path), "*.py")
        assert "a.py" in result
        assert "b.py" in result
        assert "c.txt" not in result

    def test_no_match_returns_no_matches(self, tmp_path):
        result = _tool_glob(str(tmp_path), "*.xyz")
        assert "no matches" in result.lower() or result.strip() == ""


# ── CLI argument help output ──────────────────────────────────────────────────

class TestCLIHelp:
    def _run(self, *args):
        env = os.environ.copy()
        env["PYTHONPATH"] = str(SRC)
        return subprocess.run(
            [sys.executable, "-m", "threatlint", *args],
            capture_output=True, text=True, cwd=str(PACKAGE_ROOT), env=env, check=False,
        )

    def test_run_help_lists_all_modes(self):
        r = self._run("run", "--help")
        assert r.returncode == 0
        # argparse wraps long choice lists at hyphens ("ai-security-\n   review").
        help_text = re.sub(r"-\n\s+", "-", r.stdout)
        for mode in EXPECTED_MODES:
            assert mode in help_text, f"Mode '{mode}' missing from run --help"

    @pytest.mark.parametrize("mode", list(EXPECTED_MODES))
    def test_run_parser_accepts_every_mode_without_calling_a_provider(self, mode, monkeypatch):
        from threatlint import cli
        parsed = []
        monkeypatch.setattr(cli, "cmd_run", lambda args: parsed.append(args.mode) or 0)
        monkeypatch.setattr(sys, "argv", ["threatlint", "run", mode])
        with pytest.raises(SystemExit) as result:
            cli.main()
        assert result.value.code == 0
        assert parsed == [mode]

    def test_run_help_has_provider_and_api_key_flags(self):
        r = self._run("run", "--help")
        assert "--provider" in r.stdout
        assert "--api-key" in r.stdout

    def test_install_help_has_lmstudio_flag(self):
        r = self._run("install", "--help")
        assert "--lmstudio" in r.stdout

    def test_version_flag(self):
        r = self._run("--version")
        assert r.returncode == 0
        assert "1." in r.stdout or "threatlint" in r.stdout.lower()
