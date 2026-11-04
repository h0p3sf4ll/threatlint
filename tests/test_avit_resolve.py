"""AVIT -> repository/branch/file context, checkout, and resolve (upload, close FP, tune Semgrep)."""

import io
import os
import json
import types
import urllib.parse

import pytest

from threatlint import avit_resolve as ar
from threatlint import servicenow as sn

AVIT = "AVIT000000095938462"
INSTANCE = "https://example.service-now.com"
SYS_ID = "a" * 32
# Shaped like the AVIT form: custom u_ columns, labels from sys_documentation.
ROW = {"sys_id": {"value": SYS_ID}, "number": {"value": AVIT}, "state": {"value": "1"},
       "u_scm_tool": {"display_value": "ADO"}, "u_organization_name": {"display_value": "contoso"},
       "u_project_name": {"display_value": "Platform"}, "u_repository": {"display_value": "infra-terraform"},
       "u_project_branch": {"display_value": "feature-branch"},
       "u_file_path": {"display_value": "src/aisp/nonprod/resources/ap-south-1/s3/kubecost-aps1-metricsbucket/terraform.tfvars"},
       "u_security_finding_source": {"display_value": "Secret"}, "u_line_number": {"display_value": "12"},
       "vulnerability": {"display_value": "generic.secrets.aws-access-key"}}
LABELS = [{"name": sn.AVIT_TABLE, "element": element, "label": label} for element, label in [
    ("u_scm_tool", "SCM Tool"), ("u_organization_name", "Organization Name"), ("u_project_name", "Project Name"),
    ("u_repository", "Repository"), ("u_project_branch", "Project Branch"), ("u_file_path", "File Path"),
    ("u_security_finding_source", "Security Finding Source")]]
REPORT = f"""# FP Review

#### [FP-001] — AWS key placeholder in terraform.tfvars

**Original finding**: {AVIT}; generic.secrets.aws-access-key; Semgrep Secrets; src/aisp/nonprod/resources/ap-south-1/s3/kubecost-aps1-metricsbucket/terraform.tfvars:12
**Disposition**: FALSE POSITIVE
**Severity**: INFO
**Confidence**: CONFIRMED
"""


@pytest.fixture(autouse=True)
def isolate_operation_audits(monkeypatch, tmp_path):
    monkeypatch.setenv("THREATLINT_HOME", str(tmp_path / "threatlint-home"))


def test_avit_numbers_are_avit_plus_7_to_15_digits():
    assert sn.parse_avit_numbers(f"{AVIT.lower()}, AVIT0042599") == [AVIT, "AVIT0042599"]
    for bad in ("AVIT123456", "AVIT0000000959384621", "AVIT00000009593846X"):
        with pytest.raises(sn.ServiceNowError, match="7 to 15 digits"):
            sn.parse_avit_numbers(bad)

def test_context_comes_from_form_labels_and_targets_the_ado_repo_branch_and_file():
    fields = sn._flatten(ROW)
    labels = {row["label"].lower(): row["element"] for row in LABELS}
    context = sn.avit_context(fields, labels)
    assert context["branch"] == "feature-branch" and context["file_path"].endswith("terraform.tfvars")
    target = sn.repository_target(context)
    assert target["clone_url"] == "https://dev.azure.com/contoso/Platform/_git/infra-terraform"
    assert target["branch"] == "feature-branch"
    assert sn.finding_kind({"fields": fields, "context": context}) == "secrets"
    # Without readable labels, column names still resolve.
    assert sn.avit_context(fields)["repository"] == "infra-terraform"


def test_finding_source_only_selects_the_semgrep_product():
    kind = lambda source: sn.finding_kind({"fields": {}, "context": {"finding_source": source}})
    assert (kind("SAST"), kind("SCA"), kind("Secrets"), kind("Secret"), kind("")) == ("sast", "sca", "secrets", "secrets", "sast")
    assert sn.in_code_security_view({"in_view": False, "context": {"scm_tool": "ADO", "repository": "r"}}) is False
    assert sn.in_code_security_view({"in_view": None, "context": {"scm_tool": "ADO", "repository": "r"}}) is True


def test_unsafe_repository_values_are_refused():
    base = {"scm_tool": "ADO", "organization": "contoso", "project": "EIP", "repository": "repo"}
    for change in ({"branch": "-c core.sshCommand=x"}, {"branch": "a..b"}, {"organization": "evil.com/x"}, {"scm_tool": "Bitbucket"}):
        with pytest.raises(sn.ServiceNowError):
            sn.repository_target({**base, **change})
    assert sn.repository_target({"scm_tool": "GitHub", "organization": "acme", "repository": "web"})["clone_url"] == "https://github.com/acme/web.git"


def test_checkout_clones_only_the_avit_branch_with_credentials_out_of_argv(monkeypatch, tmp_path):
    seen = {}
    monkeypatch.setenv("THREATLINT_ADO_PAT", "pat-value")
    monkeypatch.setattr(sn.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(sn.subprocess, "run", lambda command, **kw: seen.update(command=command, env=kw["env"]) or types.SimpleNamespace(returncode=0, stderr=""))
    target = sn.repository_target({"scm_tool": "ADO", "organization": "contoso", "project": "Platform", "repository": "r", "branch": "feature-branch"})
    sn.checkout_repository(target, str(tmp_path / "co"))
    assert seen["command"][0] == "/usr/bin/git" and seen["command"][-2:] == [target["clone_url"], str(tmp_path / "co")]
    assert ["--branch", "feature-branch"] == seen["command"][seen["command"].index("--branch"):seen["command"].index("--branch") + 2]
    assert "pat-value" not in " ".join(seen["command"])
    assert seen["env"]["GIT_CONFIG_KEY_0"] == "http.https://dev.azure.com/.extraHeader"


def test_verdict_is_read_from_the_original_finding_line():
    assert ar.verdict_for(REPORT, AVIT)["disposition"] == "FALSE POSITIVE"
    with pytest.raises(ar.ResolveError, match="no finding"):
        ar.verdict_for(REPORT, "AVIT000000000000001")


class FakeServiceNow:
    def __init__(self):
        self.calls = []

    def __call__(self, url, *, data=None, headers, method=None):
        self.calls.append((method or ("POST" if data is not None else "GET"), url.split("?")[0], data))
        if url.endswith("/oauth_token.do"):
            return {"access_token": "t"}
        if "/sys_documentation" in url:
            return {"result": LABELS}
        if "/sysrule_view" in url:
            return {"result": [{"condition": "u_scm_toolISNOTEMPTY"}]}
        if "u_scm_toolISNOTEMPTY" in url:
            return {"result": [{"number": AVIT}]}
        if "/sys_choice" in url:
            return {"result": [{"name": sn.AVIT_TABLE, "element": "state", "value": "3", "label": "Closed"},
                               {"name": sn.AVIT_TABLE, "element": "substate", "value": "6", "label": "False Positive"}]}
        if url.split("?")[0].endswith("/api/now/attachment"):
            return {"result": []}
        if "/attachment/file" in url:
            return {"result": {"sys_id": "b" * 32}}
        if method == "PATCH":
            body = json.loads(data)
            return {"result": {"state": body.get("state", "1"), "substate": body.get("substate", "")}}
        return {"result": [ROW]}


def _args(tmp_path, report, **extra):
    path, docx = tmp_path / "report.md", tmp_path / "report.docx"
    path.write_text(report, encoding="utf-8")
    docx.write_bytes(b"PK-docx")
    return types.SimpleNamespace(number=AVIT, report=str(path), docx=str(docx), snow_instance=INSTANCE, aws_profile=None,
                                 semgrep_deployment=None, semgrep_rule_hash_id="synthetic-hash", skip_semgrep=False,
                                 skip_rule_tuning=True, checkout=None, yes=True, **extra)


@pytest.mark.parametrize("command", ["resolve", "semgrep"])
@pytest.mark.parametrize(
    ("scm_context", "canonical"),
    [
        ({"scm_tool": "GitHub", "organization": "synthetic-owner", "repository": "repo"}, "synthetic-owner/repo"),
        ({"scm_tool": "ADO", "organization": "synthetic-org", "project": "Project Name", "repository": "repo"}, "synthetic-org/Project Name/repo"),
    ],
)
@pytest.mark.parametrize("matched", [False, True])
def test_tuning_commands_pass_the_exact_project_name(monkeypatch, tmp_path, command, scm_context, canonical, matched):
    from threatlint import semgrep_platform as sp

    context = {**scm_context, "file_path": "file.py", "line": "12", "rule": "synthetic.rule", "finding_source": "SAST"}
    record = {"sys_id": "a" * 32, "fields": {"state": "Closed", "work_notes": ar.CLOSING_COMMENT},
              "context": context, "in_view": True}
    matches = [{"id": 1, "rule": "synthetic.rule", "path": "file.py", "line": 12, "ref": "feature",
                "project": canonical, "product": "sast"}] if matched else []
    monkeypatch.setattr(ar, "_session", lambda args: (INSTANCE, "synthetic"))
    monkeypatch.setattr(ar, "_record", lambda *args: record)
    monkeypatch.setattr(ar, "attachment_names", lambda *args: set())
    monkeypatch.setattr(ar, "attach", lambda *args: None)
    monkeypatch.setattr(ar, "update", lambda *args: {"state": "3", "substate": "3"})
    monkeypatch.setattr(ar, "semgrep_token", lambda *args: "synthetic")
    monkeypatch.setattr(ar, "semgrep_matches", lambda *args: ({"id": 7, "slug": "synthetic"}, matches))
    monkeypatch.setattr(ar, "semgrep_ignore", lambda *args, **kwargs: len(matches))
    calls = []
    monkeypatch.setattr(sp, "tune_rule", lambda *args, **kwargs: calls.append(kwargs) or [])
    (tmp_path / "file.py").write_text("synthetic = True\n", encoding="utf-8")
    args = _args(tmp_path, REPORT)
    args.checkout, args.skip_rule_tuning, args.line = str(tmp_path), False, None
    assert (ar.cmd_resolve(args) if command == "resolve" else ar.cmd_semgrep(args)) == 0
    assert calls == [{"project": canonical, "verified_finding": False}]


def test_rule_tuning_fetches_the_exact_avit_branch_when_checkout_is_missing(monkeypatch):
    from pathlib import Path
    from threatlint import semgrep_platform as sp

    target = {"organization": "synthetic-org", "project": "P", "name": "repo", "branch": "develop"}
    context = {"rule": "synthetic.rule", "file_path": "src/flagged.py", "line": "2"}
    checked_out = []
    tuned = []

    def checkout(requested, directory, path):
        checked_out.append((requested.copy(), path))
        flagged = Path(directory) / path
        flagged.parent.mkdir(parents=True)
        flagged.write_text("first\nflagged()\n", encoding="utf-8")

    monkeypatch.setattr(sn, "checkout_repository", checkout)
    monkeypatch.setattr(sp, "tune_rule", lambda _report, _kind, _rule, file, line, *_rest, **_kw:
                        tuned.append((file, line, Path(file).read_text(encoding="utf-8"))))
    ar._tune_verified_rule(types.SimpleNamespace(checkout=None), REPORT, AVIT, "sast", context,
                           "synthetic-token", {"id": 7, "slug": "synthetic"}, target,
                           [{"project": "synthetic-org/P/repo"}])
    assert checked_out == [(target, "src/flagged.py")]
    assert tuned[0][1:] == (2, "first\nflagged()\n")
    assert not Path(tuned[0][0]).exists(), "temporary repository must be removed"


def test_rule_tuning_rejects_flagged_path_escape_before_checkout(monkeypatch):
    monkeypatch.setattr(sn, "checkout_repository", lambda *_args: pytest.fail("unsafe path must not be checked out"))
    with pytest.raises(ar.ResolveError, match="escapes"):
        ar._tune_verified_rule(types.SimpleNamespace(checkout=None), REPORT, AVIT, "sast",
                               {"rule": "synthetic.rule", "file_path": "../outside.py", "line": "2"},
                               "synthetic-token", {"id": 7, "slug": "synthetic"},
                               {"branch": "develop"}, [])


def test_ruleset_tuning_requires_an_exact_open_semgrep_finding():
    target = {"organization": "synthetic-org", "project": "P", "name": "repo", "branch": "develop"}
    context = {"rule": "synthetic.rule", "file_path": "src/flagged.py"}
    found = {"status": "open", "product": "sast", "project": "synthetic-org/P/repo",
             "ref": "develop", "rule": "synthetic.rule", "path": "src/flagged.py", "line": 2}
    assert ar._verified_tuning_match(target, context, "sast", 2, [found])
    for change in ({"ref": "main"}, {"line": 3}, {"path": "src/other.py"},
                   {"status": "ignored"}, {"project": "another/P/repo"}, {"rule": "other.rule"}):
        assert not ar._verified_tuning_match(target, context, "sast", 2, [{**found, **change}])


def test_false_positive_attaches_then_closes_with_the_threatlint_comment_and_ignores_semgrep(monkeypatch, tmp_path):
    fake, semgrep_calls = FakeServiceNow(), []
    ignored = set()
    monkeypatch.setattr(sn, "_request_json", fake)
    monkeypatch.setattr(sn, "resolve_credentials", lambda _p: ("id", "secret"))
    monkeypatch.setattr(ar, "semgrep_token", lambda _p: "sg")

    def semgrep(path, token, *, body=None):
        semgrep_calls.append((path, body))
        if path == "/deployments":
            return {"deployments": [{"id": 12345, "slug": "example_org"}]}
        if "/projects" in path:
            return {"projects": []}
        if "/findings?" in path:
            return {"findings": []}
        if "/secrets" in path:
            assert path.startswith("/deployments/12345/secrets") and "repo=contoso%2FPlatform%2Finfra-terraform" in path
            common = {"type": "AWS", "ruleHashId": "synthetic-hash", "repository": {"name": "contoso/Platform/infra-terraform"},
                      "ref": "feature-branch"}
            return {"findings": [{"id": str(identifier), **common, "findingPath": path,
                                 "status": "FINDING_STATUS_IGNORED" if identifier in ignored else "FINDING_STATUS_OPEN"}
                                for identifier, path in [(55, "src/aisp/nonprod/resources/ap-south-1/s3/kubecost-aps1-metricsbucket/terraform.tfvars:12"),
                                                         (56, "src/other.tfvars:12")]]}
        ignored.update(body["issue_ids"])
        return {"num_triaged": len(body["issue_ids"]), "triaged_issues": body["issue_ids"]}
    monkeypatch.setattr(ar, "_semgrep", semgrep)
    monkeypatch.setattr("threatlint.semgrep_platform.deployment", lambda token, wanted="": {"id": 12345, "slug": "example_org"})
    out = io.StringIO()
    monkeypatch.setattr("sys.stdout", out)
    assert ar.cmd_resolve(_args(tmp_path, REPORT)) == 0
    methods = [(m, u.rsplit("/api/now/", 1)[-1]) for m, u, _d in fake.calls if "/api/now/" in u]
    attach = methods.index(("POST", "attachment/file"))
    patch = next(i for i, (m, _u) in enumerate(methods) if m == "PATCH")
    assert attach < patch, "the report is attached before the AVIT is closed"
    body = json.loads(next(d for m, _u, d in fake.calls if m == "PATCH"))
    assert (body["state"], body["substate"]) == ("3", "3")
    assert body["work_notes"] == "Closed by Threatlint as a false positive, see attached report."
    uploads = [u for m, u, _d in fake.calls if u.endswith("/attachment/file")]
    assert len(uploads) == 1, "only the Word report is attached"
    triage = next(body for _path, body in semgrep_calls if body is not None)
    assert triage["issue_type"] == "secrets" and triage["issue_ids"] == [55] and triage["new_triage_reason"] == "false_positive"
    assert "Closed as false positive" in out.getvalue()


def test_headless_false_positive_still_tunes_rule_without_semgrep_match_and_reports_partial_completion(monkeypatch, tmp_path):
    fake = FakeServiceNow()
    monkeypatch.setattr(sn, "_request_json", fake)
    monkeypatch.setattr(sn, "resolve_credentials", lambda _p: ("id", "secret"))
    monkeypatch.setattr(ar, "semgrep_token", lambda _p: "sg")
    monkeypatch.setattr(ar, "semgrep_matches", lambda *_args: ({"id": 7, "slug": "synthetic"}, []))
    tuned = []
    monkeypatch.setattr("threatlint.semgrep_platform.tune_rule", lambda *_args, **_kwargs: tuned.append(True))
    args = _args(tmp_path, REPORT)
    args.require_complete_semgrep = True
    args.skip_rule_tuning = False
    path = sn._flatten(ROW)["u_file_path"]
    flagged = tmp_path / path
    flagged.parent.mkdir(parents=True)
    flagged.write_text("flagged\n", encoding="utf-8")
    args.checkout = str(tmp_path)
    assert ar.cmd_resolve(args) == 1
    assert tuned == [True], "missing triage match must not suppress a proven rule update"
    assert any(method == "PATCH" for method, _url, _data in fake.calls)
    assert any("/attachment/file" in url for _method, url, _data in fake.calls)


def test_true_positive_attaches_the_report_and_leaves_the_avit_open(monkeypatch, tmp_path):
    fake = FakeServiceNow()
    monkeypatch.setattr(sn, "_request_json", fake)
    monkeypatch.setattr(sn, "resolve_credentials", lambda _p: ("id", "secret"))
    monkeypatch.setattr(ar, "_semgrep", lambda *a, **k: pytest.fail("Semgrep must not change for a true positive"))
    monkeypatch.setattr("sys.stdout", io.StringIO())
    assert ar.cmd_resolve(_args(tmp_path, REPORT.replace("FALSE POSITIVE", "TRUE POSITIVE"))) == 0
    body = json.loads(next(d for m, _u, d in fake.calls if m == "PATCH"))
    assert "state" not in body and body["work_notes"] == "True positive, see attached report."
    assert any("attachment/file" in u for _m, u, _d in fake.calls)


def test_ambiguous_attaches_the_report_with_a_note_and_leaves_the_avit_open(monkeypatch, tmp_path):
    fake = FakeServiceNow()
    monkeypatch.setattr(sn, "_request_json", fake)
    monkeypatch.setattr(sn, "resolve_credentials", lambda _p: ("id", "secret"))
    monkeypatch.setattr(ar, "_semgrep", lambda *a, **k: pytest.fail("Semgrep must not change for an ambiguous finding"))
    monkeypatch.setattr("sys.stdout", io.StringIO())
    assert ar.cmd_resolve(_args(tmp_path, REPORT.replace("FALSE POSITIVE", "AMBIGUOUS"))) == 0
    body = json.loads(next(d for m, _u, d in fake.calls if m == "PATCH"))
    assert "state" not in body and body["work_notes"] == ar.AMBIGUOUS_COMMENT
    assert any("attachment/file" in u for _m, u, _d in fake.calls)


def test_note_adds_a_work_note_without_changing_state(monkeypatch):
    fake = FakeServiceNow()
    monkeypatch.setattr(sn, "_request_json", fake)
    monkeypatch.setattr(sn, "resolve_credentials", lambda _p: ("id", "secret"))
    monkeypatch.setattr("sys.stdout", io.StringIO())
    args = types.SimpleNamespace(number=AVIT, message="Not reviewed: repository not found.", snow_instance=INSTANCE, aws_profile=None, yes=True)
    assert ar.cmd_note(args) == 0
    patches = [json.loads(d) for m, _u, d in fake.calls if m == "PATCH"]
    assert patches == [{"work_notes": "Not reviewed: repository not found."}]
    assert not any("attachment" in u for _m, u, _d in fake.calls)


def test_a_clone_that_times_out_retries_as_a_sparse_checkout(monkeypatch, tmp_path):
    import subprocess
    calls = []
    def run(command, **kwargs):
        calls.append(command)
        if "--depth" in command and "50" in command:
            raise subprocess.TimeoutExpired(command, 600)
        return subprocess.CompletedProcess(command, 0, "", "")
    monkeypatch.setattr(sn.subprocess, "run", run)
    monkeypatch.setattr(sn.shutil, "which", lambda name: "/usr/bin/git")
    monkeypatch.setattr(sn, "_git_auth_env", lambda *a: {})
    monkeypatch.setattr("sys.stdout", io.StringIO())
    target = {"scm": "github", "clone_url": "https://github.com/o/r.git", "web_url": "u", "branch": "b", "organization": "o"}
    sn.checkout_repository(target, str(tmp_path / "co"), "force-app/classes/A.cls")
    assert "--filter=blob:none" in calls[1] and calls[2][-2:] == ["--no-cone", "/force-app/classes/"]
    assert calls[3][-3:] == ["read-tree", "-mu", "HEAD"], "a --no-checkout clone needs read-tree to populate the sparse tree"


def test_sca_false_positive_ignores_the_supply_chain_finding(monkeypatch, tmp_path):
    row = {key: value for key, value in ROW.items() if key != "u_line_number"}
    row.update({"u_security_finding_source": {"display_value": "SCA"}, "u_file_path": {"display_value": "package-lock.json"},
                "vulnerability": {"display_value": "ssc-dc3aa06a"}})
    fake = FakeServiceNow()
    original = fake.__call__
    monkeypatch.setattr(sn, "_request_json", lambda url, **kw: {"result": [row]} if "sysparm_query=number%3D" in url else original(url, **kw))
    monkeypatch.setattr(sn, "resolve_credentials", lambda _p: ("id", "secret"))
    monkeypatch.setattr(ar, "semgrep_token", lambda _p: "sg")
    calls, ignored = [], set()
    def semgrep(path, token, *, body=None):
        calls.append((path, body))
        if path == "/deployments":
            return {"deployments": [{"id": 12345, "slug": "example_org"}]}
        if "/projects" in path:
            return {"projects": []}
        if "/findings?" in path:
            assert "issue_type=sca" in path and path.startswith("/deployments/example_org/findings") and "Platform%2Finfra-terraform" in path
            page = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)["page"][0]
            return {"findings": [{"id": 91, "rule": {"name": "ssc-dc3aa06a"}, "repository": {"name": "contoso/Platform/infra-terraform"},
                                  "ref": "feature-branch", "status": "ignored" if 91 in ignored else "open",
                                  "location": {"file_path": "package-lock.json", "line": 40}}] if page == "0" else []}
        ignored.update(body["issue_ids"])
        return {"num_triaged": len(body["issue_ids"]), "triaged_issues": body["issue_ids"]}
    monkeypatch.setattr(ar, "_semgrep", semgrep)
    monkeypatch.setattr("threatlint.semgrep_platform.deployment", lambda token, wanted="": {"id": 12345, "slug": "example_org"})
    monkeypatch.setattr("sys.stdout", io.StringIO())
    report = REPORT.replace("src/aisp/nonprod/resources/ap-south-1/s3/kubecost-aps1-metricsbucket/terraform.tfvars:12", "package-lock.json:40")
    assert ar.cmd_resolve(_args(tmp_path, report)) == 0
    triage = next(body for _path, body in calls if body is not None)
    assert triage["issue_type"] == "sca" and triage["issue_ids"] == [91]


def test_an_already_attached_report_is_not_attached_twice(monkeypatch, tmp_path):
    fake = FakeServiceNow()
    original = fake.__call__
    def existing(url, **kw):
        if url.split("?")[0].endswith("/api/now/attachment"):
            return {"result": [{"file_name": f"{AVIT}-threatlint-fp-review.docx"}]}
        return original(url, **kw)
    monkeypatch.setattr(sn, "_request_json", existing)
    monkeypatch.setattr(sn, "resolve_credentials", lambda _p: ("id", "secret"))
    monkeypatch.setattr("sys.stdout", io.StringIO())
    args = _args(tmp_path, REPORT.replace("FALSE POSITIVE", "TRUE POSITIVE"))
    assert ar.cmd_resolve(args) == 0
    assert not any(u.endswith("/attachment/file") for _m, u, _d in fake.calls)


def test_headless_repeat_attaches_new_version_beside_existing_report(monkeypatch, tmp_path):
    fake = FakeServiceNow()
    original = fake.__call__

    def existing(url, **kwargs):
        if url.split("?")[0].endswith("/api/now/attachment"):
            return {"result": [{"file_name": f"{AVIT}-threatlint-fp-review.docx"}]}
        return original(url, **kwargs)

    monkeypatch.setattr(sn, "_request_json", existing)
    monkeypatch.setattr(sn, "resolve_credentials", lambda _p: ("id", "secret"))
    monkeypatch.setattr("sys.stdout", io.StringIO())
    args = _args(tmp_path, REPORT.replace("FALSE POSITIVE", "TRUE POSITIVE"))
    args.attachment_name = f"{AVIT}-threatlint-fp-review-20261104T180000123456Z.docx"
    assert ar.cmd_resolve(args) == 0
    uploads = [u for _m, u, _d in fake.calls if u.endswith("/attachment/file")]
    assert len(uploads) == 1

    args.attachment_name = f"{AVIT}-other.docx"
    with pytest.raises(ar.ResolveError, match="attachment name is invalid"):
        ar.cmd_resolve(args)


def test_attachment_listing_failure_prevents_avit_update(monkeypatch, tmp_path):
    fake = FakeServiceNow()
    original = fake.__call__

    def failing(url, **kwargs):
        if url.split("?")[0].endswith("/api/now/attachment"):
            raise sn.ServiceNowError("Attachment list unavailable")
        return original(url, **kwargs)

    monkeypatch.setattr(sn, "_request_json", failing)
    monkeypatch.setattr(sn, "resolve_credentials", lambda _p: ("id", "secret"))
    args = _args(tmp_path, REPORT.replace("FALSE POSITIVE", "TRUE POSITIVE"))
    with pytest.raises(sn.ServiceNowError, match="Attachment list unavailable"):
        ar.cmd_resolve(args)
    assert not any(method == "PATCH" or "/attachment/file" in url for method, url, _data in fake.calls)


def test_malformed_attachment_listing_prevents_avit_update(monkeypatch, tmp_path):
    fake = FakeServiceNow()
    original = fake.__call__

    def malformed(url, **kwargs):
        if url.split("?")[0].endswith("/api/now/attachment"):
            return {"result": {"file_name": "not a list"}}
        return original(url, **kwargs)

    monkeypatch.setattr(sn, "_request_json", malformed)
    monkeypatch.setattr(sn, "resolve_credentials", lambda _p: ("id", "secret"))
    with pytest.raises(ar.ResolveError, match="readable AVIT attachment list"):
        ar.cmd_resolve(_args(tmp_path, REPORT.replace("FALSE POSITIVE", "TRUE POSITIVE")))
    assert not any(method == "PATCH" or "/attachment/file" in url for method, url, _data in fake.calls)


def test_true_positive_on_previously_closed_avit_attaches_but_reports_not_open(monkeypatch, tmp_path):
    fake = FakeServiceNow()
    old_row = {**ROW, "state": {"display_value": "Closed", "value": "3"}}
    original = fake.__call__

    def previously_closed(url, **kwargs):
        if "sysparm_query=number%3D" in url:
            return {"result": [old_row]}
        if kwargs.get("method") == "PATCH":
            fake.calls.append(("PATCH", url.split("?")[0], kwargs.get("data")))
            return {"result": {"state": "3", "substate": "3"}}
        return original(url, **kwargs)

    monkeypatch.setattr(sn, "_request_json", previously_closed)
    monkeypatch.setattr(sn, "resolve_credentials", lambda _p: ("id", "secret"))
    output = io.StringIO()
    monkeypatch.setattr("sys.stdout", output)
    assert ar.cmd_resolve(_args(tmp_path, REPORT.replace("FALSE POSITIVE", "TRUE POSITIVE"))) == 1
    assert any("/attachment/file" in url for _m, url, _d in fake.calls)
    assert "could not be confirmed" in output.getvalue()
    assert "AVIT left open" not in output.getvalue()


def test_true_positive_uses_stored_open_state_when_business_rule_reopens_avit(monkeypatch, tmp_path):
    fake = FakeServiceNow()
    old_row = {**ROW, "state": {"display_value": "Closed", "value": "3"}}
    original = fake.__call__

    def reopened(url, **kwargs):
        if "sysparm_query=number%3D" in url:
            return {"result": [old_row]}
        return original(url, **kwargs)

    monkeypatch.setattr(sn, "_request_json", reopened)
    monkeypatch.setattr(sn, "resolve_credentials", lambda _p: ("id", "secret"))
    output = io.StringIO()
    monkeypatch.setattr("sys.stdout", output)
    assert ar.cmd_resolve(_args(tmp_path, REPORT.replace("FALSE POSITIVE", "TRUE POSITIVE"))) == 0
    assert "AVIT left open" in output.getvalue()


def test_the_checkout_is_deleted_after_resolve_even_on_error(tmp_path, monkeypatch):
    checkout = tmp_path / "repo"
    (checkout / ".git" / "objects").mkdir(parents=True)
    (checkout / ".git" / "objects" / "pack").write_text("x", encoding="utf-8")
    os.chmod(checkout / ".git" / "objects" / "pack", 0o444)
    args = types.SimpleNamespace(avit_command="resolve", checkout=str(checkout), keep_checkout=False)
    monkeypatch.setattr("sys.stdout", io.StringIO())
    def fails(_args):
        raise ar.ResolveError("boom")
    assert ar.run(fails, args) == 1
    assert not checkout.exists()
    assert ar.remove_checkout(str(tmp_path)) is False, "only git checkouts are deleted"


def test_semgrep_rerun_requires_a_threatlint_false_positive_closure(monkeypatch):
    fake = FakeServiceNow()
    monkeypatch.setattr(sn, "_request_json", fake)
    monkeypatch.setattr(sn, "resolve_credentials", lambda _p: ("id", "secret"))
    monkeypatch.setattr(ar, "semgrep_token", lambda _p: pytest.fail("Semgrep must not be touched for an open AVIT"))
    args = types.SimpleNamespace(number=AVIT, snow_instance=INSTANCE, aws_profile=None, line=None, semgrep_deployment=None)
    with pytest.raises(ar.ResolveError, match="not closed as a false positive"):
        ar.cmd_semgrep(args)


def test_a_renamed_ado_repository_is_followed_through_its_guid(monkeypatch):
    target = sn.repository_target({"scm_tool": "ADO", "organization": "contoso", "project": "AI_Projects", "repository": "workflow-api", "branch": "b"})
    import threatlint.semgrep_platform as sp
    monkeypatch.setattr(sp, "resolve_token", lambda *_a: ("t", "x"))
    monkeypatch.setattr(sp, "deployment", lambda *_a: {"id": 12345, "slug": "example_org"})
    seen = {}
    def call(path, token, **_k):
        seen["path"] = path
        return {"project": {"url": "https://dev.azure.com/contoso/698f/_apis/git/repositories/b13a53cc-86f7-4d90-a055-b754186e580f"}}
    monkeypatch.setattr(sp, "call", call)
    monkeypatch.setattr("threatlint.ado_login.load", lambda organization="": ("pat", "x"))
    class Response(io.BytesIO):
        def __enter__(self): return self
        def __exit__(self, *a): return False
    monkeypatch.setattr(ar.urllib.request, "urlopen", lambda request, **_k: Response(b'{"name": "workflow-pro-api"}') if "b13a53cc" in request.full_url else pytest.fail(request.full_url))
    assert ar.renamed_ado_repository(target, types.SimpleNamespace(aws_profile=None)) == "workflow-pro-api"
    assert seen["path"].endswith("/projects/AI_Projects/workflow-api")


def test_semgrep_is_never_matched_without_a_line(monkeypatch):
    import threatlint.semgrep_platform as sp
    monkeypatch.setattr(sp, "deployment", lambda *_a: {"id": 12345, "slug": "example_org"})
    monkeypatch.setattr(ar, "_semgrep", lambda *a, **k: pytest.fail("no Semgrep query without a line"))
    target = {"name": "r", "project": "P", "organization": "O", "branch": "feature"}
    with pytest.raises(ar.ResolveError, match="flagged line"):
        ar.semgrep_matches("t", "sast", target, {"file_path": "a.js", "rule": "x.y"})
    report = "**Original finding**: AVIT000000000000001; x.y; Semgrep Code; a.js:268\n"
    def findings(path, token, **kwargs):
        page = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)["page"][0]
        return {"findings": [{"id": identifier, "rule_name": "x.y", "repository": {"name": "O/P/r"}, "ref": "feature",
                              "status": "open", "location": {"file_path": "a.js", "line": line}}
                             for identifier, line in [(1, 268), (2, 109)]] if page == "0" else []}
    monkeypatch.setattr(ar, "_semgrep", findings)
    _dep, matches = ar.semgrep_matches("t", "sast", target, {"file_path": "a.js", "rule": "x.y", "avit": "AVIT000000000000001"}, report_text=report)
    assert [m["id"] for m in matches] == [1]


def test_a_non_codesecurity_false_positive_closes_without_semgrep(monkeypatch, tmp_path):
    fake = FakeServiceNow()
    original = fake.__call__
    def outside_view(url, **kw):
        if "u_scm_toolISNOTEMPTY" in url:
            return {"result": []}
        return original(url, **kw)
    monkeypatch.setattr(sn, "_request_json", outside_view)
    monkeypatch.setattr(sn, "resolve_credentials", lambda _p: ("id", "secret"))
    monkeypatch.setattr(ar, "semgrep_token", lambda _p: pytest.fail("Semgrep must not be used outside CodeSecurity"))
    out = io.StringIO()
    monkeypatch.setattr("sys.stdout", out)
    assert ar.cmd_resolve(_args(tmp_path, REPORT)) == 0
    body = json.loads(next(d for m, _u, d in fake.calls if m == "PATCH"))
    assert (body["state"], body["substate"]) == ("3", "3")
    assert "Semgrep not applicable" in out.getvalue()


def test_a_huge_ado_repository_falls_back_to_downloading_the_flagged_folder(monkeypatch, tmp_path):
    import subprocess
    monkeypatch.setattr(sn.subprocess, "run", lambda command, **k: (_ for _ in ()).throw(subprocess.TimeoutExpired(command, 600)))
    monkeypatch.setattr(sn.shutil, "which", lambda name: "/usr/bin/git")
    monkeypatch.setattr(sn, "_git_auth_env", lambda *a: {})
    monkeypatch.setattr(sn, "git_credential", lambda *a: ("Basic x", "store"))
    monkeypatch.setattr("sys.stdout", io.StringIO())
    seen = []
    class Response(io.BytesIO):
        def __enter__(self): return self
        def __exit__(self, *a): return False
    def urlopen(request, timeout, context):
        seen.append(request.full_url)
        if "scopePath" in request.full_url:
            return Response(json.dumps({"value": [{"path": "/force-app/classes", "isFolder": True}, {"path": "/force-app/classes/A.cls"}, {"path": "/force-app/classes/B.cls"}]}).encode())
        return Response(b"public class A {}")
    monkeypatch.setattr(sn.urllib.request, "urlopen", urlopen)
    target = {"scm": "azure-devops", "clone_url": "https://dev.azure.com/o/p/_git/r", "web_url": "u", "branch": "feat/x", "organization": "o"}
    out = sn.checkout_repository(target, str(tmp_path / "co"), "force-app/classes/A.cls")
    assert (tmp_path / "co/force-app/classes/A.cls").read_text(encoding="utf-8") == "public class A {}" and (tmp_path / "co/force-app/classes/B.cls").exists()
    assert out == str(tmp_path / "co") and all("versionDescriptor.version=feat%2Fx" in url for url in seen)


def test_close_removed_closes_only_after_azure_devops_confirms_the_repository_is_gone(monkeypatch):
    fake = FakeServiceNow()
    monkeypatch.setattr(sn, "_request_json", fake)
    monkeypatch.setattr(sn, "resolve_credentials", lambda _p: ("id", "secret"))
    monkeypatch.setattr(sn, "git_credential", lambda *a: ("Basic x", "store"))
    monkeypatch.setattr(ar, "renamed_ado_repository", lambda *a: None)
    monkeypatch.setattr("sys.stdout", io.StringIO())
    listing = {"value": [{"name": "other-repo"}]}
    class Response(io.BytesIO):
        def __enter__(self): return self
        def __exit__(self, *a): return False
    monkeypatch.setattr(ar.urllib.request, "urlopen", lambda *a, **k: Response(json.dumps(listing).encode()))
    args = types.SimpleNamespace(number=AVIT, snow_instance=INSTANCE, aws_profile=None, yes=True)
    assert ar.cmd_close_removed(args) == 0
    body = json.loads(next(d for m, _u, d in fake.calls if m == "PATCH"))
    assert body["state"] == "3" and body["work_notes"] == "Closed by Threatlint, repo removed."
    assert not any("attachment/file" in u for _m, u, _d in fake.calls), "no report is attached"
    listing["value"].append({"name": "infra-terraform"})
    with pytest.raises(ar.ResolveError, match="still exists"):
        ar.cmd_close_removed(args)


def test_a_renamed_repository_whose_branch_was_deleted_falls_back_to_the_default_branch(tmp_path, monkeypatch):
    clones = []
    def checkout(target, directory, path):
        clones.append((target["clone_url"].rsplit("/", 1)[-1], target["branch"]))
        if not target["clone_url"].endswith("new-name"):
            raise sn.ServiceNowError(f"Could not clone: repository '{target['name']}' not found")
        if target["branch"]:
            raise sn.ServiceNowError("fatal: Remote branch feat/x not found in upstream origin")
        os.makedirs(os.path.join(directory, "src"), exist_ok=True)
        open(os.path.join(directory, path), "w", encoding="utf-8").close()
    monkeypatch.setattr(sn, "checkout_repository", checkout)
    monkeypatch.setattr(ar, "renamed_ado_repository", lambda *a: "new-name")
    target = {"scm": "azure-devops", "clone_url": "https://dev.azure.com/o/p/_git/old", "web_url": "u", "branch": "feat/x", "organization": "o", "project": "p", "name": "old"}
    monkeypatch.setattr(ar, "_session", lambda args: (INSTANCE, "t"))
    monkeypatch.setattr(ar, "_record", lambda *a: {"context": {"file_path": "src/a.js"}})
    monkeypatch.setattr(sn, "finding_kind", lambda record: "sca")
    monkeypatch.setattr(sn, "repository_target", lambda context: dict(target))
    monkeypatch.setattr(sn, "git_credential", lambda *a: ("Basic x", "store"))
    out = io.StringIO()
    monkeypatch.setattr("sys.stdout", out)
    assert ar.cmd_checkout(types.SimpleNamespace(number=AVIT, dir=str(tmp_path / "co"), aws_profile=None)) == 0
    assert clones == [("old", "feat/x"), ("new-name", "feat/x"), ("new-name", "")]
    result = json.loads(out.getvalue().strip().splitlines()[-1])
    assert result["renamed_to"] == "new-name" and result["branch_deleted"] == "feat/x"


def test_verdict_is_found_under_an_unbracketed_finding_heading():
    report = REPORT.replace("#### [FP-001] —", "## FP-001 —")
    verdict = ar.verdict_for(report, AVIT)
    assert (verdict["id"], verdict["disposition"], verdict["title"]) == ("FP-001", "FALSE POSITIVE", "AWS key placeholder in terraform.tfvars")


def test_a_single_finding_report_without_a_finding_id_heading_uses_its_original_finding_line():
    report = REPORT.replace("#### [FP-001] — AWS key placeholder in terraform.tfvars", "## Finding")
    assert ar.verdict_for(report, AVIT)["disposition"] == "FALSE POSITIVE"
    two = report + "\n**Original finding**: AVIT0042599; r; Semgrep Secrets; a:1\n**Disposition**: TRUE POSITIVE\n"
    with pytest.raises(ar.ResolveError):
        ar.verdict_for(two, AVIT)  # several findings without headings are not guessed apart
