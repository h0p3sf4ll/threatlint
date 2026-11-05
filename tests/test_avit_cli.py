"""Compatibility boundaries for the extracted ServiceNow, AVIT, Semgrep, and SCTASK CLIs."""

import argparse
import io
import json
from types import SimpleNamespace

import pytest

from threatlint import avit_resolve as ar
from threatlint import sctask
from threatlint import semgrep_platform as sp
from threatlint import servicenow as sn

AVIT = "AVIT0042599"
TASK = "SCTASK1234567"
INSTANCE = "https://example.service-now.com"


@pytest.fixture
def parser(monkeypatch, tmp_path):
    monkeypatch.setenv("THREATLINT_HOME", str(tmp_path))
    monkeypatch.delenv(sn.INSTANCE_ENV, raising=False)
    monkeypatch.setattr(sn, "saved_config", lambda: {})
    parser = argparse.ArgumentParser()
    actions = parser.add_subparsers(dest="command", required=True)
    sn.add_avit_parser(actions)
    sp.add_semgrep_parser(actions)
    sctask.add_sctask_parser(actions)
    return parser


@pytest.mark.parametrize(
    ("arguments", "field", "expected"),
    [
        (["avit", "fetch", AVIT, "-o", "r.md"], "avit_command", "fetch"),
        (["avit", "checkout", AVIT, "--dir", "checkout"], "avit_command", "checkout"),
        (["avit", "resolve", AVIT, "--report", "r.md", "--docx", "r.docx"], "avit_command", "resolve"),
        (["avit", "semgrep", AVIT, "--line", "42"], "line", 42),
        (["avit", "note", AVIT, "--message", "synthetic"], "avit_command", "note"),
        (["avit", "close-removed", AVIT, "--yes"], "yes", True),
        (["avit", "fix-pr", AVIT, "--report", "r.md", "--checkout", "repo", "--target", "target.json", "--yes"], "avit_command", "fix-pr"),
        (["semgrep", "login", "--token-stdin"], "token_stdin", True),
        (["semgrep", "status"], "semgrep_command", "status"),
        (["semgrep", "logout"], "semgrep_command", "logout"),
        (["semgrep", "rule-base", "synthetic.rule", "--kind", "sast", "-o", "r.yaml"], "kind", "sast"),
        (["sctask", "avits", TASK], "sctask_command", "avits"),
        (["sctask", "close", TASK, "--leave-open"], "leave_open", True),
    ],
)
def test_original_parser_surfaces_keep_subcommands_flags_and_defaults(parser, arguments, field, expected):
    args = parser.parse_args(arguments)
    assert getattr(args, field) == expected


def test_fetch_dispatch_uses_original_collaborators(monkeypatch, tmp_path, capsys):
    output = tmp_path / "findings.md"
    args = SimpleNamespace(avit_command="fetch", numbers=[AVIT], avit=[], output=str(output))
    monkeypatch.setattr(sn, "requested_avits", lambda args: args.avit)
    monkeypatch.setattr(sn, "collect_avits", lambda args, numbers: ("synthetic", "\n".join(numbers)))
    assert sn.cmd_avit(args) == 0
    assert output.read_text() == AVIT
    assert "AVIT findings written" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("command", "handler"),
    [("checkout", "cmd_checkout"), ("resolve", "cmd_resolve"), ("semgrep", "cmd_semgrep"),
     ("note", "cmd_note"), ("close-removed", "cmd_close_removed")],
)
def test_dispatch_resolves_patched_original_handlers(monkeypatch, command, handler):
    sentinel = lambda args: 17
    monkeypatch.setattr(ar, handler, sentinel)
    monkeypatch.setattr(ar, "run", lambda selected, args: selected(args))
    assert sn.cmd_avit(SimpleNamespace(avit_command=command)) == 17


def test_collection_uses_the_original_interactive_fallback(monkeypatch):
    def missing(profile):
        raise sn.ServiceNowError("synthetic unavailable")

    seen = []
    monkeypatch.setattr(sn, "resolve_credentials", missing)
    monkeypatch.setattr(sn, "_prompt_credentials", lambda reason: ("synthetic-id", "synthetic-secret"))
    monkeypatch.setattr(sn, "load_avits", lambda *args: seen.append(args) or ("report", 1, [], []))
    args = SimpleNamespace(snow_instance=INSTANCE, aws_profile=None)
    assert sn.collect_avits(args, [AVIT]) == (f"ServiceNow AVITs ({AVIT})", "report")
    assert seen == [(INSTANCE, [AVIT], "synthetic-id", "synthetic-secret")]


def test_semgrep_login_keeps_stdin_and_deployment_storage_seams(monkeypatch):
    token = "synthetic-token-value-123456"
    monkeypatch.setattr(sp.sys, "stdin", io.StringIO(token + "\n"))
    monkeypatch.setattr(sp, "deployment", lambda value, wanted: {"id": 7, "name": wanted})
    seen = []
    monkeypatch.setattr(sp, "save_token", lambda *args: seen.append(args) or "synthetic store")
    assert sp.login(deployment_slug="synthetic", from_stdin=True) == "synthetic store (deployment synthetic)"
    assert seen == [(token, "7")]


def test_semgrep_status_without_a_token_still_succeeds(monkeypatch, capsys):
    def missing():
        raise sp.SemgrepError("synthetic missing")

    monkeypatch.setattr(sp, "resolve_token", missing)
    assert sp.cmd_semgrep(SimpleNamespace(semgrep_command="status")) == 0
    assert capsys.readouterr().out == "synthetic missing\n"


def test_semgrep_rule_base_keeps_original_api_seams(monkeypatch, tmp_path):
    output = tmp_path / "rule.yaml"
    monkeypatch.setattr(sp, "resolve_token", lambda profile: ("synthetic", "fixture"))
    monkeypatch.setattr(sp, "deployment", lambda token: {"id": 7})
    monkeypatch.setattr(sp, "rule_base", lambda *args: ("rules: []\n", "synthetic base"))
    args = SimpleNamespace(semgrep_command="rule-base", aws_profile=None, rule="r", kind="sast", output=str(output))
    assert sp.cmd_semgrep(args) == 0
    assert output.read_text() == "# Tuning base: synthetic base\nrules: []\n"


def test_logout_removes_the_file_even_when_keyring_deletion_fails(monkeypatch, tmp_path):
    store = tmp_path / "semgrep.json"
    store.write_text("{}")

    def unavailable(*args):
        raise RuntimeError("synthetic keyring failure")

    monkeypatch.setattr(sp, "_keyring", lambda: SimpleNamespace(delete_password=unavailable))
    monkeypatch.setattr(sp, "store_path", lambda: store)
    assert sp.cmd_semgrep(SimpleNamespace(semgrep_command="logout")) == 0
    assert not store.exists()


def test_sctask_listing_keeps_session_fetch_and_extraction_seams(monkeypatch, capsys):
    monkeypatch.setattr(sctask, "_session", lambda args: (INSTANCE, "synthetic"))
    monkeypatch.setattr(sctask, "fetch", lambda *args: {"description": AVIT, "state": "1"})
    assert sctask.cmd_sctask(SimpleNamespace(number=TASK, sctask_command="avits")) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines[0] == AVIT
    assert json.loads(lines[1]) == {"sctask": TASK, "state": "1", "avits": [AVIT]}


def test_sctask_close_keeps_the_original_close_seam(monkeypatch):
    monkeypatch.setattr(sctask, "_session", lambda args: (INSTANCE, "synthetic"))
    seen = []
    monkeypatch.setattr(sctask, "close", lambda *args, **kwargs: seen.append((args, kwargs)))
    args = SimpleNamespace(number=TASK, sctask_command="close", yes=True, leave_open=True)
    assert sctask.cmd_sctask(args) == 0
    assert seen == [((INSTANCE, "synthetic", TASK, True), {"leave_open": True})]


@pytest.mark.parametrize("fails", [False, True])
@pytest.mark.parametrize("keep", [False, True])
def test_avit_dispatch_cleanup_uses_the_original_cleanup_seam(monkeypatch, fails, keep):
    seen = []
    monkeypatch.setattr(ar, "remove_checkout", lambda path: seen.append(path) or True)

    def handler(args):
        if fails:
            raise ar.ResolveError("synthetic failure")
        return 9

    args = SimpleNamespace(avit_command="resolve", checkout="synthetic checkout", keep_checkout=keep)
    assert ar.run(handler, args) == (1 if fails else 9)
    assert seen == ([] if keep else ["synthetic checkout"])
