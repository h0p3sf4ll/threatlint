"""AVIT -> repository/branch/file context, checkout, and resolve (upload, close FP, tune Semgrep)."""

import io
import os
import json
import types

import pytest

from threatlint import avit_resolve as ar
from threatlint import servicenow as sn

AVIT = "AVIT000000095938462"
INSTANCE = "https://example.service-now.com"
SYS_ID = "a" * 32
# Shaped like the AVIT form: custom u_ columns, labels from sys_documentation.
ROW = {"sys_id": {"value": SYS_ID}, "number": {"value": AVIT}, "state": {"value": "1"},
       "u_scm_tool": {"display_value": "ADO"}, "u_organization_name": {"display_value": "PepsiCoIT"},
       "u_project_name": {"display_value": "EIP-Infrastructure"}, "u_repository": {"display_value": "eip-infra-aws-terraform-support"},
       "u_project_branch": {"display_value": "pepgenx-troubleshooting"},
       "u_file_path": {"display_value": "src/aisp/nonprod/resources/ap-south-1/s3/kubecost-aps1-metricsbucket/terraform.tfvars"},
       "u_security_finding_source": {"display_value": "Secret"}, "u_line_number": {"display_value": "12"}}
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


def test_avit_numbers_are_avit_plus_7_to_15_digits():
    assert sn.parse_avit_numbers(f"{AVIT.lower()}, AVIT0042599") == [AVIT, "AVIT0042599"]
    for bad in ("AVIT123456", "AVIT0000000959384621", "AVIT00000009593846X"):
        with pytest.raises(sn.ServiceNowError, match="7 to 15 digits"):
            sn.parse_avit_numbers(bad)

def test_context_comes_from_form_labels_and_targets_the_ado_repo_branch_and_file():
    fields = sn._flatten(ROW)
    labels = {row["label"].lower(): row["element"] for row in LABELS}
    context = sn.avit_context(fields, labels)
    assert context["branch"] == "pepgenx-troubleshooting" and context["file_path"].endswith("terraform.tfvars")
    target = sn.repository_target(context)
    assert target["clone_url"] == "https://dev.azure.com/PepsiCoIT/EIP-Infrastructure/_git/eip-infra-aws-terraform-support"
    assert target["branch"] == "pepgenx-troubleshooting"
    assert sn.finding_kind({"fields": fields, "context": context}) == "secrets"
    # Without readable labels, column names still resolve.
    assert sn.avit_context(fields)["repository"] == "eip-infra-aws-terraform-support"


def test_finding_source_only_selects_the_semgrep_product():
    kind = lambda source: sn.finding_kind({"fields": {}, "context": {"finding_source": source}})
    assert (kind("SAST"), kind("SCA"), kind("Secrets"), kind("Secret"), kind("")) == ("sast", "sca", "secrets", "secrets", "sast")
    assert sn.in_code_security_view({"in_view": False, "context": {"scm_tool": "ADO", "repository": "r"}}) is False
    assert sn.in_code_security_view({"in_view": None, "context": {"scm_tool": "ADO", "repository": "r"}}) is True


def test_unsafe_repository_values_are_refused():
    base = {"scm_tool": "ADO", "organization": "PepsiCoIT", "project": "EIP", "repository": "repo"}
    for change in ({"branch": "-c core.sshCommand=x"}, {"branch": "a..b"}, {"organization": "evil.com/x"}, {"scm_tool": "Bitbucket"}):
        with pytest.raises(sn.ServiceNowError):
            sn.repository_target({**base, **change})
    assert sn.repository_target({"scm_tool": "GitHub", "organization": "acme", "repository": "web"})["clone_url"] == "https://github.com/acme/web.git"


def test_checkout_clones_only_the_avit_branch_with_credentials_out_of_argv(monkeypatch, tmp_path):
    seen = {}
    monkeypatch.setenv("THREATLINT_ADO_PAT", "pat-value")
    monkeypatch.setattr(sn.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(sn.subprocess, "run", lambda command, **kw: seen.update(command=command, env=kw["env"]) or types.SimpleNamespace(returncode=0, stderr=""))
    target = sn.repository_target({"scm_tool": "ADO", "organization": "PepsiCoIT", "project": "EIP-Infrastructure", "repository": "r", "branch": "pepgenx-troubleshooting"})
    sn.checkout_repository(target, str(tmp_path / "co"))
    assert seen["command"][0] == "/usr/bin/git" and seen["command"][-2:] == [target["clone_url"], str(tmp_path / "co")]
    assert ["--branch", "pepgenx-troubleshooting"] == seen["command"][seen["command"].index("--branch"):seen["command"].index("--branch") + 2]
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
    path.write_text(report)
    docx.write_bytes(b"PK-docx")
    return types.SimpleNamespace(number=AVIT, report=str(path), docx=str(docx), snow_instance=INSTANCE, aws_profile=None,
                                 semgrep_deployment=None, skip_semgrep=False, skip_rule_tuning=True, checkout=None, yes=True, **extra)


def test_false_positive_attaches_then_closes_with_the_threatlint_comment_and_ignores_semgrep(monkeypatch, tmp_path):
    fake, semgrep_calls = FakeServiceNow(), []
    monkeypatch.setattr(sn, "_request_json", fake)
    monkeypatch.setattr(sn, "resolve_credentials", lambda _p: ("id", "secret"))
    monkeypatch.setattr(ar, "semgrep_token", lambda _p: "sg")

    def semgrep(path, token, *, body=None):
        semgrep_calls.append((path, body))
        if path == "/deployments":
            return {"deployments": [{"id": 26306, "slug": "pepsico_poc"}]}
        if "/projects" in path:
            return {"projects": []}
        if "/secrets" in path:
            assert path.startswith("/deployments/26306/secrets") and "repo=EIP-Infrastructure%2Feip-infra-aws-terraform-support" in path
            return {"findings": [{"id": "55", "type": "AWS", "findingPath": "src/aisp/nonprod/resources/ap-south-1/s3/kubecost-aps1-metricsbucket/terraform.tfvars:12", "status": "FINDING_STATUS_OPEN"},
                                 {"id": "56", "type": "AWS", "findingPath": "src/other.tfvars:12", "status": "FINDING_STATUS_OPEN"}]}
        return {"num_triaged": len(body["issue_ids"])}
    monkeypatch.setattr(ar, "_semgrep", semgrep)
    monkeypatch.setattr("threatlint.semgrep_platform.deployment", lambda token, wanted="": {"id": 26306, "slug": "pepsico_poc"})
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
    triage = semgrep_calls[-1][1]
    assert triage["issue_type"] == "secrets" and triage["issue_ids"] == [55] and triage["new_triage_reason"] == "false_positive"
    assert "Closed as false positive" in out.getvalue()


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


def test_ambiguous_changes_nothing(monkeypatch, tmp_path):
    monkeypatch.setattr(sn, "_request_json", lambda *a, **k: pytest.fail("no ServiceNow call for AMBIGUOUS"))
    monkeypatch.setattr("sys.stdout", io.StringIO())
    assert ar.cmd_resolve(_args(tmp_path, REPORT.replace("FALSE POSITIVE", "AMBIGUOUS"))) == 0


def test_sca_false_positive_ignores_the_supply_chain_finding(monkeypatch, tmp_path):
    row = {key: value for key, value in ROW.items() if key != "u_line_number"}
    row.update({"u_security_finding_source": {"display_value": "SCA"}, "u_file_path": {"display_value": "package-lock.json"}})
    fake = FakeServiceNow()
    original = fake.__call__
    monkeypatch.setattr(sn, "_request_json", lambda url, **kw: {"result": [row]} if "sysparm_query=number%3D" in url else original(url, **kw))
    monkeypatch.setattr(sn, "resolve_credentials", lambda _p: ("id", "secret"))
    monkeypatch.setattr(ar, "semgrep_token", lambda _p: "sg")
    calls = []
    def semgrep(path, token, *, body=None):
        calls.append((path, body))
        if path == "/deployments":
            return {"deployments": [{"id": 26306, "slug": "pepsico_poc"}]}
        if "/projects" in path:
            return {"projects": []}
        if "/findings?" in path:
            assert "issue_type=sca" in path and path.startswith("/deployments/pepsico_poc/findings") and "EIP-Infrastructure%2Feip-infra-aws-terraform-support" in path
            return {"findings": [{"id": 91, "rule": {"name": "ssc-dc3aa06a"}, "location": {"file_path": "package-lock.json", "line": 40}}]}
        return {"num_triaged": len(body["issue_ids"])}
    monkeypatch.setattr(ar, "_semgrep", semgrep)
    monkeypatch.setattr("threatlint.semgrep_platform.deployment", lambda token, wanted="": {"id": 26306, "slug": "pepsico_poc"})
    monkeypatch.setattr("sys.stdout", io.StringIO())
    report = REPORT.replace("src/aisp/nonprod/resources/ap-south-1/s3/kubecost-aps1-metricsbucket/terraform.tfvars:12", "package-lock.json:40")
    assert ar.cmd_resolve(_args(tmp_path, report)) == 0
    assert calls[-1][1]["issue_type"] == "sca" and calls[-1][1]["issue_ids"] == [91]


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


def test_the_checkout_is_deleted_after_resolve_even_on_error(tmp_path, monkeypatch):
    checkout = tmp_path / "repo"
    (checkout / ".git" / "objects").mkdir(parents=True)
    (checkout / ".git" / "objects" / "pack").write_text("x")
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
    target = sn.repository_target({"scm_tool": "ADO", "organization": "PepsiCoIT", "project": "EIAP_Projects", "repository": "pepgpt-workflow-api", "branch": "b"})
    import threatlint.semgrep_platform as sp
    monkeypatch.setattr(sp, "resolve_token", lambda *_a: ("t", "x"))
    monkeypatch.setattr(sp, "deployment", lambda *_a: {"id": 26306, "slug": "pepsico_poc"})
    seen = {}
    def call(path, token, **_k):
        seen["path"] = path
        return {"project": {"url": "https://dev.azure.com/PepsiCoIT/698f/_apis/git/repositories/b13a53cc-86f7-4d90-a055-b754186e580f"}}
    monkeypatch.setattr(sp, "call", call)
    monkeypatch.setattr("threatlint.ado_login.load", lambda: ("pat", "x"))
    class Response(io.BytesIO):
        def __enter__(self): return self
        def __exit__(self, *a): return False
    monkeypatch.setattr(ar.urllib.request, "urlopen", lambda request, **_k: Response(b'{"name": "pepgpt-pro-api"}') if "b13a53cc" in request.full_url else pytest.fail(request.full_url))
    assert ar.renamed_ado_repository(target, types.SimpleNamespace(aws_profile=None)) == "pepgpt-pro-api"
    assert seen["path"].endswith("/projects/EIAP_Projects/pepgpt-workflow-api")


def test_semgrep_is_never_matched_without_a_line(monkeypatch):
    import threatlint.semgrep_platform as sp
    monkeypatch.setattr(sp, "deployment", lambda *_a: {"id": 26306, "slug": "pepsico_poc"})
    monkeypatch.setattr(ar, "_semgrep", lambda *a, **k: pytest.fail("no Semgrep query without a line"))
    target = {"name": "r", "project": "P", "organization": "O"}
    with pytest.raises(ar.ResolveError, match="flagged line"):
        ar.semgrep_matches("t", "sast", target, {"file_path": "a.js", "rule": "x.y"})
    report = "**Original finding**: AVIT000000000000001; x.y; Semgrep Code; a.js:268\n"
    monkeypatch.setattr(ar, "_semgrep", lambda path, token, **k: {"findings": [
        {"id": 1, "rule_name": "x.y", "location": {"file_path": "a.js", "line": 268}}, {"id": 2, "rule_name": "x.y", "location": {"file_path": "a.js", "line": 109}}]})
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
