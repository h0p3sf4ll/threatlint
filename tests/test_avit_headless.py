"""Headless Codex AVIT review joins model output to the existing resolver."""

from __future__ import annotations

import argparse
import importlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from threatlint import avit_headless, avit_resolve, cli, codex_cli, dast, isst, servicenow as sn


AVIT_FP = "AVIT000000095938462"
AVIT_TP = "AVIT000000095938463"


def _args(*avits: str) -> argparse.Namespace:
    return cli.build_parser().parse_args([
        "run", "fp-review", "--provider", "codex",
        *(part for avit in avits for part in ("--avit", avit)),
        "--resolve-avits", "--yes", "--snow-instance", "https://test.service-now.com",
    ])


def _item(avit: str) -> dict:
    return {"fields": {"number": avit}, "context": {"file_path": "src/flagged.js", "line": "2", "rule": "js.rule"}}


def test_headless_batch_attaches_each_verdict_from_temporary_artifacts(monkeypatch, tmp_path):
    args = _args(AVIT_FP, AVIT_TP)
    monkeypatch.setattr(sn, "requested_avits", lambda _args: [AVIT_FP, AVIT_TP])
    monkeypatch.setattr(avit_resolve, "_session", lambda _args: ("https://test.service-now.com", "token"))
    monkeypatch.setattr(sn, "fetch_avits", lambda *_: ([_item(AVIT_FP), _item(AVIT_TP)], [], []))
    monkeypatch.setattr(sn, "finding_kind", lambda _item: "sast")
    monkeypatch.setattr(sn, "avits_markdown", lambda _instance, _items, numbers, *_: f"Evidence for {numbers[0]}")
    monkeypatch.setattr(avit_headless, "_checkout", lambda _item, _args, repo: repo.mkdir() or {"name": "repo"})
    monkeypatch.setattr(avit_headless, "_rule_base", lambda *_: "\n```yaml\nrules: []\n```\n")
    reviewed = []

    def model(_system, prompt, repo, _model, **_kwargs):
        avit = AVIT_FP if AVIT_FP in prompt else AVIT_TP
        reviewed.append((avit, repo, prompt))
        disposition = "FALSE POSITIVE" if avit == AVIT_FP else "TRUE POSITIVE"
        return f"# False Positive Review\n\n#### [FP-001] — Finding\n**Original finding**: {avit}; js.rule; Semgrep; src/flagged.js:2\n**Disposition**: {disposition}\n**Confidence**: CONFIRMED\n**Evidence**: `src/flagged.js:2` uses a literal.\n**Verified Safe Behavior**: The literal cannot be influenced by a caller.\n"

    monkeypatch.setattr(codex_cli, "run_agent", model)
    monkeypatch.setattr(dast, "to_docx", lambda _markdown, docx: Path(docx).write_bytes(b"word report"))
    resolved = []

    def resolve(call):
        assert call.attachment_name.startswith(f"{call.number}-threatlint-fp-review-")
        assert call.attachment_name.endswith("Z.docx")
        assert call.require_complete_semgrep is True
        resolved.append((call.number, Path(call.report).read_text(), Path(call.docx).read_bytes(), call.yes, call.checkout))
        return 0

    monkeypatch.setattr(avit_resolve, "cmd_resolve", resolve)
    assert avit_headless.run(args, "reviewer instructions", "", "1.99") == 0
    assert [row[0] for row in resolved] == [AVIT_FP, AVIT_TP]
    assert ["FALSE POSITIVE" in row[1] for row in resolved] == [True, False]
    assert all(row[2] == b"word report" and row[3] is True for row in resolved)
    assert all("Evidence for " + row[0] in row[2] for row in reviewed)
    assert all(not Path(row[1]).exists() for row in reviewed), "temporary checkouts must be removed"


@pytest.mark.parametrize("pr_status", ["created", "existing", "skipped", "error", "spawn-error", "disabled"])
@pytest.mark.parametrize("scm", ["azure-devops", "github"])
def test_headless_true_positive_runs_draft_pr_after_report_writeback(monkeypatch, pr_status, scm):
    from threatlint import avit_pr

    args = _args(AVIT_TP)
    args.no_fix_pr = pr_status == "disabled"
    target = {"scm": scm, "organization": "contoso", "project": "project", "name": "repo", "branch": "main"}
    url = ("https://dev.azure.com/contoso/project/_git/repo/pullrequest/42" if scm == "azure-devops"
           else "https://git.example.com/contoso/repo/pull/42")
    monkeypatch.setattr(avit_headless, "_checkout", lambda _item, _args, repo: repo.mkdir() or target)
    monkeypatch.setattr(avit_headless, "_rule_base", lambda *_: "")
    monkeypatch.setattr(sn, "avits_markdown", lambda *_: "AVIT evidence")
    markdown = (f"# Finding Review\n\n#### [FP-001] — Finding\n**Original finding**: {AVIT_TP}; rule; scanner; src/flagged.js:2\n"
                "**Disposition**: TRUE POSITIVE\n**Confidence**: CONFIRMED\n**Evidence**: src/flagged.js:2\n")
    def review(_provider, _system, prompt, *_):
        assert ("**Proposed fix patch**:" in prompt) is (pr_status != "disabled")
        return markdown

    monkeypatch.setattr(avit_headless, "_run_review_model", review)
    monkeypatch.setattr(dast, "to_docx", lambda _md, docx: Path(docx).write_bytes(b"PKword"))
    calls = []
    monkeypatch.setattr(avit_resolve, "cmd_resolve", lambda _args: calls.append("resolve") or 0)

    def publish(avit, report, checkout, reviewed_target, **options):
        assert calls == ["resolve"]
        assert avit == AVIT_TP and report == markdown and Path(checkout).is_dir()
        assert reviewed_target == target and options["instance"] == "https://test.service-now.com"
        calls.append("pr")
        if pr_status == "error":
            raise avit_pr.ResolveError("The repository provider rejected the draft PR")
        if pr_status == "spawn-error":
            raise OSError("Git could not start")
        return {"status": pr_status, "url": url} if pr_status != "skipped" else {"status": "skipped", "reason": "No applicable proposed fix"}

    monkeypatch.setattr(avit_pr, "create_fix_pr", publish)
    outcome = avit_headless._review_one(args, _item(AVIT_TP), "https://test.service-now.com", "reviewer", "", "1.99")
    assert outcome["completed"] is (pr_status not in ("error", "spawn-error"))
    assert outcome["report_bytes"] == b"PKword", "a PR failure must preserve the completed report outcome"
    if pr_status == "disabled":
        assert calls == ["resolve"] and "pull_request" not in outcome
    else:
        assert calls == ["resolve", "pr"] and outcome["pull_request"]["status"] == ("error" if pr_status == "spawn-error" else pr_status)
        if pr_status in ("created", "existing"):
            assert outcome["pull_request"]["url"] == url


def test_no_resolve_when_word_report_fails_but_later_avit_continues(monkeypatch):
    args = _args(AVIT_FP, AVIT_TP)
    monkeypatch.setattr(sn, "requested_avits", lambda _args: [AVIT_FP, AVIT_TP])
    monkeypatch.setattr(avit_resolve, "_session", lambda _args: ("https://test.service-now.com", "token"))
    monkeypatch.setattr(sn, "fetch_avits", lambda *_: ([_item(AVIT_FP), _item(AVIT_TP)], [], []))
    monkeypatch.setattr(sn, "finding_kind", lambda _item: "sca")
    monkeypatch.setattr(sn, "avits_markdown", lambda _instance, _items, numbers, *_: numbers[0])
    monkeypatch.setattr(avit_headless, "_checkout", lambda _item, _args, repo: repo.mkdir() or {"name": "repo"})
    monkeypatch.setattr(avit_headless, "_rule_base", lambda *_: "")
    monkeypatch.setattr(codex_cli, "run_agent", lambda _system, prompt, *_args, **_kwargs:
                        f"# Review\n\n#### [FP-001] — Finding\n**Original finding**: {AVIT_FP if AVIT_FP in prompt else AVIT_TP}; rule; scanner; src/flagged.js:2\n**Disposition**: TRUE POSITIVE\n")
    converted = []

    def convert(markdown, docx):
        converted.append(markdown)
        if len(converted) == 1:
            raise RuntimeError("converter failed")
        Path(docx).write_bytes(b"word report")

    monkeypatch.setattr(dast, "to_docx", convert)
    resolved = []
    monkeypatch.setattr(avit_resolve, "cmd_resolve", lambda call: resolved.append(call.number) or 0)
    assert avit_headless.run(args, "reviewer", "", "1.99") == 1
    assert resolved == [AVIT_TP]
    assert all(not Path(path).exists() for path in converted)


def test_codesecurity_token_is_checked_before_any_review_or_write(monkeypatch):
    args = _args(AVIT_FP)
    item = {**_item(AVIT_FP), "in_view": True}
    monkeypatch.setattr(sn, "requested_avits", lambda _args: [AVIT_FP])
    monkeypatch.setattr(avit_resolve, "_session", lambda _args: ("https://test.service-now.com", "token"))
    monkeypatch.setattr(sn, "fetch_avits", lambda *_args: ([item], [], []))
    monkeypatch.setattr(avit_resolve, "semgrep_token", lambda _profile: (_ for _ in ()).throw(avit_headless.ResolveError("Run `threatlint semgrep login`")))
    monkeypatch.setattr(avit_headless, "_review_one", lambda *_args: pytest.fail("model and resolver must not run"))
    assert avit_headless.run(args, "reviewer", "", "1.99") == 1


def test_codesecurity_setup_failure_does_not_block_other_avit(monkeypatch):
    args = _args(AVIT_FP, AVIT_TP)
    monkeypatch.setattr(sn, "requested_avits", lambda _args: [AVIT_FP, AVIT_TP])
    monkeypatch.setattr(avit_resolve, "_session", lambda _args: ("https://test.service-now.com", "token"))
    monkeypatch.setattr(sn, "fetch_avits", lambda *_args: ([{**_item(AVIT_FP), "in_view": True}, {**_item(AVIT_TP), "in_view": False}], [], []))
    monkeypatch.setattr(avit_resolve, "semgrep_token", lambda _profile: (_ for _ in ()).throw(avit_headless.ResolveError("missing token")))
    reviewed = []
    monkeypatch.setattr(avit_headless, "_review_one", lambda _args, item, *_rest, **_kwargs: reviewed.append(item["fields"]["number"]) or True)
    assert avit_headless.run(args, "reviewer", "", "1.99") == 1
    assert reviewed == [AVIT_TP]


def test_report_redacts_credential_assignments_from_flagged_directory(tmp_path):
    repo = tmp_path / "repo"
    target = repo / "src" / "flagged.js"
    target.parent.mkdir(parents=True)
    target.write_text("client_secret = abcdefghijk123456789\n", encoding="utf-8")
    (target.parent / "config.js").write_text("api_key: zyxwvutsrq987654321\n", encoding="utf-8")
    text, count = avit_headless.redact_secrets("abcdefghijk123456789 and zyxwvutsrq987654321", repo, "src/flagged.js")
    assert text == "[REDACTED] and [REDACTED]" and count == 2
    evidence_only, count = avit_headless.redact_secrets("sk-abcdefghijklmnop1234", repo, "missing", "credential: sk-abcdefghijklmnop1234")
    assert evidence_only == "[REDACTED]" and count == 1
    assert avit_headless.redact_secrets("unchanged", repo, "../../elsewhere") == ("unchanged", 0)


def test_fp_tuning_guard_requires_rule_source_fixture_and_real_line(tmp_path):
    repo = tmp_path / "repo"
    flagged = repo / "src" / "flagged.js"
    flagged.parent.mkdir(parents=True)
    flagged.write_text("first\nsecond\n", encoding="utf-8")
    item = {**_item(AVIT_FP), "in_view": True}
    report = (f"**Original finding**: {AVIT_FP}; js.rule; Semgrep; src/flagged.js:2\n"
              "**Tuned rule**:\n```yaml\nrules:\n  - id: js.rule.tuned\n    pattern: foo(...)\n```\n"
              "**Tuned rule fixtures**:\n```javascript\n// ruleid: js.rule.tuned\nfoo(user);\n"
              "// ok: js.rule.tuned\nfoo(safe);\n```\n")
    avit_headless._guard_fp_rule(item, repo, "original rule source", report, AVIT_FP)
    with pytest.raises(avit_headless.ResolveError, match="rule source"):
        avit_headless._guard_fp_rule(item, repo, "", report, AVIT_FP)
    with pytest.raises(avit_headless.ResolveError, match="fixtures"):
        avit_headless._guard_fp_rule(item, repo, "original rule source", report.replace("// ok: js.rule.tuned", "// ordinary comment"), AVIT_FP)
    with pytest.raises(avit_headless.ResolveError, match="rule ID"):
        avit_headless._guard_fp_rule(item, repo, "original rule source", report.replace("js.rule.tuned", "other.rule.tuned"), AVIT_FP)
    flagged.unlink()
    with pytest.raises(avit_headless.ResolveError, match="checkout file"):
        avit_headless._guard_fp_rule(item, repo, "original rule source", report, AVIT_FP)


def test_headless_rule_repair_precedes_any_avit_write(monkeypatch):
    args = _args(AVIT_FP)
    item = {**_item(AVIT_FP), "in_view": True}
    item["context"]["finding_source"] = "SAST"
    monkeypatch.setattr(sn, "avits_markdown", lambda *_args: "AVIT evidence")

    def checkout(_item, _args, repo):
        flagged = repo / "src" / "flagged.js"
        flagged.parent.mkdir(parents=True)
        flagged.write_text("first\nfoo(safe)\n", encoding="utf-8")
        return {"name": "repo"}

    monkeypatch.setattr(avit_headless, "_checkout", checkout)
    monkeypatch.setattr(avit_headless, "_rule_base", lambda *_args: "original rule source")
    header = (f"#### [FP-001] — Finding\n**Original finding**: {AVIT_FP}; js.rule; Semgrep; src/flagged.js:2\n"
              "**Disposition**: FALSE POSITIVE\n**Evidence**: `src/flagged.js:2` uses a literal.\n**Verified Safe Behavior**: The literal cannot be influenced by a caller.\n")
    complete = (header + "**Tuned rule**:\n```yaml\nrules:\n  - id: js.rule.tuned\n    pattern: foo(...)\n```\n"
                "**Tuned rule fixtures**:\n```javascript\n// ruleid: js.rule.tuned\nfoo(user);\n"
                "// ok: js.rule.tuned\nfoo(safe);\n```\n")
    responses = iter([header, complete])
    prompts = []
    monkeypatch.setattr(avit_headless, "_run_review_model", lambda _provider, _system, prompt, *_args:
                        prompts.append(prompt) or next(responses))
    proof = []
    monkeypatch.setattr(avit_headless, "_prove_tuned_rule", lambda *_args: proof.append("validated"))
    monkeypatch.setattr(dast, "to_docx", lambda _markdown, docx: Path(docx).write_bytes(b"PKword"))
    writes = []
    monkeypatch.setattr(avit_resolve, "cmd_resolve", lambda _args: writes.append("resolved") or 0)
    outcome = avit_headless._review_one(args, item, "https://test.service-now.com", "reviewer", "", "1.99")
    assert outcome["completed"] and outcome["disposition"] == "FALSE POSITIVE"
    assert len(prompts) == 2 and "Revise the complete prior report" in prompts[1]
    assert proof == ["validated"] and writes == ["resolved"]


def test_tuned_rule_is_proven_against_flagged_file_before_writeback(monkeypatch, tmp_path):
    from threatlint import semgrep_platform as sp

    item = {**_item(AVIT_FP), "in_view": True}
    item["context"]["finding_source"] = "SAST"
    flagged = tmp_path / "src" / "flagged.js"
    flagged.parent.mkdir(parents=True)
    flagged.write_text("first\nfoo(safe)\n", encoding="utf-8")
    report = ("**Tuned rule**:\n```yaml\nrules:\n  - id: js.rule.tuned\n    pattern: foo(...)\n```\n"
              "**Tuned rule fixtures**:\n```javascript\n// ruleid: js.rule.tuned\nfoo(user);\n"
              "// ok: js.rule.tuned\nfoo(safe);\n```\n")
    monkeypatch.setattr(avit_resolve, "semgrep_token", lambda _profile: "synthetic-token")
    checked = []
    monkeypatch.setattr(sp, "validate_tuned_rule", lambda *values: checked.append(values) or {"dropped": True})
    avit_headless._prove_tuned_rule(item, tmp_path, report, AVIT_FP, _args(AVIT_FP))
    assert checked[0][1:4] == ("js.rule", str(flagged), 2)
    assert checked[0][5] == "synthetic-token"
    assert "ruleid: js.rule.tuned" in checked[0][4]


def test_isst_discovery_drives_same_avit_review_and_summary(monkeypatch):
    args = _args()
    args.isst = ["ISST0035374"]
    record = {"number": args.isst[0], "avits": [AVIT_FP, AVIT_TP]}
    monkeypatch.setattr(sn, "requested_avits", lambda _args: [])
    monkeypatch.setattr(avit_resolve, "_session", lambda _args: ("https://test.service-now.com", "token"))
    monkeypatch.setattr(isst, "discover", lambda _instance, _token, _number: (record, record["avits"]))
    monkeypatch.setattr(sn, "fetch_avits", lambda *_args: ([_item(AVIT_FP), _item(AVIT_TP)], [], []))
    monkeypatch.setattr(sn, "in_code_security_view", lambda _item: False)
    outcomes = []

    def review(_args, item, *_rest, **_kwargs):
        avit = item["fields"]["number"]
        return {"avit": avit, "disposition": "FALSE POSITIVE" if avit == AVIT_FP else "TRUE POSITIVE",
                "completed": True, "attachment_name": f"{avit}-threatlint-fp-review.docx",
                "report_bytes": b"PKword" if avit == AVIT_TP else b""}

    monkeypatch.setattr(avit_headless, "_review_one", review)
    monkeypatch.setattr(isst, "summarize", lambda _instance, _token, _record, result: outcomes.extend(result))
    assert avit_headless.run(args, "reviewer", "", "1.99", provider="claude-code") == 0
    assert [item["avit"] for item in outcomes] == record["avits"]
    assert [item["disposition"] for item in outcomes] == ["FALSE POSITIVE", "TRUE POSITIVE"]


def test_repeated_isst_inputs_review_shared_avits_once_and_summarize_each(monkeypatch):
    args = _args()
    args.isst = ["ISST0035374", "ISST0035375"]
    records = {
        args.isst[0]: {"number": args.isst[0], "avits": [AVIT_FP, AVIT_TP]},
        args.isst[1]: {"number": args.isst[1], "avits": [AVIT_TP]},
    }
    monkeypatch.setattr(sn, "requested_avits", lambda _args: [])
    monkeypatch.setattr(avit_resolve, "_session", lambda _args: ("https://test.service-now.com", "token"))
    monkeypatch.setattr(isst, "discover", lambda _instance, _token, number: (records[number], records[number]["avits"]))
    monkeypatch.setattr(sn, "fetch_avits", lambda _instance, _token, numbers: (
        [_item(number) for number in numbers], [], []))
    monkeypatch.setattr(sn, "in_code_security_view", lambda _item: False)
    reviewed, summaries = [], {}

    def review(_args, item, *_rest, **_kwargs):
        number = item["fields"]["number"]
        reviewed.append(number)
        return {"avit": number, "disposition": "TRUE POSITIVE", "completed": True,
                "attachment_name": f"{number}-threatlint-fp-review.docx", "report_bytes": b"PKword"}

    monkeypatch.setattr(avit_headless, "_review_one", review)
    monkeypatch.setattr(isst, "summarize", lambda _instance, _token, record, outcomes:
                        summaries.update({record["number"]: [item["avit"] for item in outcomes]}))
    assert avit_headless.run(args, "reviewer", "", "1.99") == 0
    assert reviewed == [AVIT_FP, AVIT_TP]
    assert summaries == {args.isst[0]: [AVIT_FP, AVIT_TP], args.isst[1]: [AVIT_TP]}


@pytest.mark.parametrize(("provider", "module_name"), [
    ("claude-code", "claude_code"), ("codex", "codex_cli"),
    ("copilot", "copilot_cli"), ("claude", "claude_api"),
])
def test_all_headless_providers_invoke_their_runner(monkeypatch, tmp_path, provider, module_name):
    module = importlib.import_module(f"threatlint.{module_name}")
    calls = []
    monkeypatch.setattr(module, "run_agent", lambda *values, **kwargs: calls.append((values, kwargs)) or "# Review")
    assert avit_headless._run_review_model(provider, "role", "evidence", tmp_path, "model",
                                           _args(AVIT_FP), "https://api.anthropic.com/v1", "key") == "# Review"
    assert len(calls) == 1
    assert "evidence" in calls[0][0]
    if provider == "claude":
        assert calls[0][0][0] == "https://api.anthropic.com/v1/messages"
        assert calls[0][1]["api_key"] == "key"


def test_deleted_avit_branch_cannot_auto_close_false_positive(monkeypatch):
    args = _args(AVIT_FP)
    item = {**_item(AVIT_FP), "in_view": False}
    monkeypatch.setattr(sn, "finding_kind", lambda _item: "sca")
    monkeypatch.setattr(sn, "avits_markdown", lambda *_args: "AVIT evidence")
    monkeypatch.setattr(avit_headless, "_checkout", lambda _item, _args, repo: repo.mkdir() or {"name": "repo", "branch_deleted": "develop"})
    monkeypatch.setattr(avit_headless, "_rule_base", lambda *_args: "")
    monkeypatch.setattr(codex_cli, "run_agent", lambda *_args, **_kwargs:
                        f"#### [FP-001] — Finding\n**Original finding**: {AVIT_FP}; rule; scanner; src/flagged.js:2\n**Disposition**: FALSE POSITIVE\n**Evidence**: `src/flagged.js:2` uses a literal.\n**Verified Safe Behavior**: The literal cannot be influenced by a caller.\n")
    monkeypatch.setattr(avit_resolve, "cmd_resolve", lambda *_args: pytest.fail("deleted-branch FP must stay open"))
    with pytest.raises(avit_headless.ResolveError, match="branch was deleted"):
        avit_headless._review_one(args, item, "https://test.service-now.com", "reviewer", "", "1.99")


def test_checkout_requires_noninteractive_credential(monkeypatch, tmp_path):
    monkeypatch.setattr(sn, "repository_target", lambda _context: {
        "scm": "azure-devops", "organization": "Org", "web_url": "https://dev.azure.com/Org/P/_git/R",
    })
    monkeypatch.setattr(sn, "git_credential", lambda *_args: ("", ""))
    with pytest.raises(avit_headless.ResolveError, match="threatlint ado login"):
        avit_headless._checkout(_item(AVIT_FP), SimpleNamespace(aws_profile=None), tmp_path / "repo")


@pytest.mark.parametrize("argv, error", [
    (["run", "fp-review", "--provider", "codex", "--avit", AVIT_FP, "--resolve-avits"], "requires --yes"),
    (["run", "fp-review", "--provider", "lmstudio", "--avit", AVIT_FP, "--resolve-avits", "--yes"], "requires `run fp-review`"),
    (["run", "threat-model", "--provider", "codex", "--avit", AVIT_FP, "--resolve-avits", "--yes"], "requires `run fp-review`"),
])
def test_resolve_flags_reject_unsupported_invocations(argv, error, capsys):
    assert cli.cmd_run(cli.build_parser().parse_args(argv)) == 1
    assert error in capsys.readouterr().out


def test_plain_avit_review_remains_report_only(monkeypatch, tmp_path):
    args = cli.build_parser().parse_args(["run", "fp-review", "--provider", "codex", "--avit", AVIT_FP])
    from threatlint import run_context

    monkeypatch.setattr(run_context, "_resolve_provider", lambda _args, **_kwargs: ("codex", "", ""))
    monkeypatch.setattr(cli, "_semgrep_version", lambda: "1.99")
    monkeypatch.setattr(cli, "_git_output", lambda *_args: str(tmp_path))
    monkeypatch.setattr(cli, "_load_requested_avits", lambda *_args: ("AVIT", "finding"))
    monkeypatch.setattr(codex_cli, "run_agent", lambda *_args, **_kwargs: "# Report\n")
    monkeypatch.setattr(cli, "_save_report", lambda *_args: tmp_path / "report.md")
    monkeypatch.setattr(avit_resolve, "cmd_resolve", lambda *_args: pytest.fail("report-only mode must not resolve AVITs"))
    assert cli.cmd_run(args) == 0


def test_cli_routes_explicit_headless_run_to_per_avit_orchestrator(monkeypatch):
    args = _args(AVIT_FP)
    from threatlint import run_context

    monkeypatch.setattr(run_context, "_resolve_provider", lambda _args, **_kwargs: ("codex", "", ""))
    monkeypatch.setattr(cli, "_semgrep_version", lambda: "1.99")
    seen = []
    monkeypatch.setattr(avit_headless, "run", lambda *values, **kwargs: seen.append((values, kwargs)) or 0)
    monkeypatch.setattr(cli, "_load_requested_avits", lambda *_args: pytest.fail("combined AVIT loading must not run"))
    assert cli.cmd_run(args) == 0
    assert seen[0][0][0] is args and seen[0][0][3] == "1.99"
    assert seen[0][1] == {"provider": "codex", "base_url": "", "api_key": ""}
