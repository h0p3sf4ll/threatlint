"""Invicti DAST AVIT validation: AVIT loading, bounded checks, evidence, sandbox isolation, teardown, and resolve."""

import io
import json
import os
import re
import subprocess
import types
from pathlib import Path

import pytest

from threatlint import avit_resolve as ar
from threatlint import dast
from threatlint import runtime_env as rt
from threatlint import servicenow as sn

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).parent / "fixtures" / "dast"
INSTANCE = "https://example.service-now.com"


def finding(name="invicti-xss-search.json"):
    return dast.invicti_finding(dast.load_avit_file(str(FIXTURES / name)))


# ── AVIT loading ─────────────────────────────────────────────────────────────

def test_avit_files_load_from_table_api_json_flat_json_and_markdown():
    tp, fp, sqli = finding(), finding("invicti-xss-greet.json"), finding("invicti-sqli-items.md")
    assert (tp["avit"], tp["kind"], tp["method"], tp["path"], tp["query"], tp["parameter"]) == ("AVIT0000000900001", "xss", "GET", "/search", "q=kettle", "q")
    assert tp["scanned_origin"] == "https://shop.example.test" and tp["issue_id"] == "synthetic-issue-0001"
    assert (fp["avit"], fp["kind"], fp["path"], fp["parameter"]) == ("AVIT0000000900002", "xss", "/greet", "name")
    assert (sqli["avit"], sqli["kind"], sqli["path"], sqli["parameter"]) == ("AVIT0000000900003", "sqli", "/items", "id")


def test_only_invicti_dynamic_avits_are_accepted(tmp_path):
    record = json.loads((FIXTURES / "invicti-xss-greet.json").read_text())
    for change, message in (({"source": "Semgrep"}, "not an Invicti dynamic finding"), ({"scan_type": "Static"}, "not an Invicti dynamic finding"),
                            ({"u_vulnerable_url": "/relative"}, "no absolute vulnerable URL"), ({"u_http_method": "DELETE"}, "Unsupported HTTP method")):
        with pytest.raises(ar.ResolveError, match=message):
            dast.invicti_finding({**record, **change})
    with pytest.raises(ar.ResolveError, match="not AVIT0000000900009"):
        dast.invicti_finding(record, "AVIT0000000900009")
    bad = tmp_path / "two.json"
    bad.write_text(json.dumps({"result": [record, record]}))
    with pytest.raises(ar.ResolveError, match="exactly one record"):
        dast.load_avit_file(str(bad))


def test_check_kinds_follow_the_invicti_vulnerability_name():
    kinds = {name: dast.check_kind(name) for name in ("Cross-site Scripting", "Blind SQL Injection", "Open Redirection", "Open Redirect",
                                                      "Missing X-Frame-Options Header", "HSTS Policy Not Enabled", "Cookie Not Marked as HttpOnly",
                                                      "Directory Listing", "Version Disclosure (nginx)", "Weak Ciphers Enabled")}
    assert kinds["Cross-site Scripting"] == "xss" and kinds["Blind SQL Injection"] == "sqli" and kinds["Open Redirect"] == "redirect"
    assert kinds["Missing X-Frame-Options Header"] == kinds["HSTS Policy Not Enabled"] == "headers"
    assert kinds["Cookie Not Marked as HttpOnly"] == "cookie" and kinds["Directory Listing"] == "dirlist" and kinds["Weak Ciphers Enabled"] == "generic"


# ── Bounded checks ───────────────────────────────────────────────────────────

@pytest.mark.parametrize("name", ["invicti-xss-search.json", "invicti-xss-greet.json", "invicti-sqli-items.md"])
def test_requests_are_origin_relative_bounded_and_never_name_the_scanned_host(name):
    item = finding(name)
    requests = dast.plan_requests(item, "abcd1234")
    assert 2 <= len(requests) <= 8 and requests[0]["id"] == "baseline"
    for request in requests:
        assert request["path"].startswith(item["path"]) and not request["path"].startswith("//")
        assert "shop.example.test" not in json.dumps(request)
        assert request["method"] in ("GET", "POST", "HEAD")


def test_injection_checks_need_the_vulnerable_parameter():
    item = {**finding(), "parameter": ""}
    with pytest.raises(ar.ResolveError, match="names no vulnerable parameter"):
        dast.plan_requests(item)


def _response(identifier, status=200, body="", ctype="text/html", headers=()):
    return {"id": identifier, "status": status, "headers": [["Content-Type", ctype], *headers], "body": body}


def test_xss_is_observed_only_when_the_marker_comes_back_unencoded_in_html():
    item, marker = finding(), "abcd1234"
    requests = dast.plan_requests(item, marker)
    raw = dast.assess(item, requests, [_response("baseline", body="ok"), _response("marker", body=f"<h1>tl{marker}\"'<tl{marker}></h1>")], marker)
    encoded = dast.assess(item, requests, [_response("baseline", body="ok"), _response("marker", body=f"<p>tl{marker}&quot;&#x27;&lt;tl{marker}&gt;</p>")], marker)
    json_raw = dast.assess(item, requests, [_response("baseline", body="ok"), _response("marker", ctype="application/json", body=f'"<tl{marker}>"')], marker)
    assert (raw["observed"], encoded["observed"], json_raw["observed"]) == (True, False, False)
    assert any("HTML-encoded" in signal for signal in encoded["signals"]) and any("not HTML" in signal for signal in json_raw["signals"])


def test_sqli_needs_a_new_database_error_or_a_boolean_differential():
    item = finding("invicti-sqli-items.md")
    requests = dast.plan_requests(item)
    rows = '[{"id": 1, "name": "kettle"}]'
    vulnerable = [_response("baseline", body=rows, ctype="application/json"), _response("quote", 500, "sqlite3.OperationalError: unrecognized token", "text/plain"),
                  _response("true", 500, "x"), _response("false", 500, "x"), _response("num-true", body=rows), _response("num-false", body="[]")]
    safe = [_response(r["id"], body=rows, ctype="application/json") for r in requests]
    assert dast.assess(item, requests, vulnerable)["observed"] is True
    assert dast.assess(item, requests, safe)["observed"] is False
    assert dast.assess(item, requests, [{"id": "baseline", "error": "ConnectionRefusedError"}])["observed"] is None


def test_hsts_cannot_be_judged_from_the_plain_http_sandbox():
    item = {**finding(), "vulnerability": "HSTS Policy Not Enabled", "kind": "headers"}
    result = dast.assess(item, dast.plan_requests(item), [_response("baseline", body="<html></html>")])
    assert result["observed"] is None and any("HTTPS edge" in signal for signal in result["signals"])
    assert not [f for f in dast.passive_checks(_response("baseline"), "/") if f["rule"] == "RT-HDR-HSTS"]


def test_passive_checks_use_the_same_rule_ids_as_the_workbench_runtime_scanner():
    source = (ROOT / "web" / "lib" / "runtime.cjs").read_text(encoding="utf-8")
    passive = source[source.index("// ── Passive response checks"):source.index("// ── HTML report rendering")]
    workbench = set(re.findall(r"'(RT-[A-Z-]+)'", passive))
    python = {check["id"] for check in dast.HEADER_CHECKS} | {"RT-COOKIE-FLAGS", "RT-CORS-REFLECT", "RT-DISCLOSE-VERSION", "RT-DEBUG-LEAK"}
    assert python == workbench
    assert dast.PROBE_ORIGIN in source
    found = {f["rule"] for f in dast.passive_checks(_response("baseline", body="Traceback (most recent call last)", headers=(
        ["Set-Cookie", "sid=abc; Path=/"], ["Server", "nginx/1.25.3"], ["Access-Control-Allow-Origin", dast.PROBE_ORIGIN])), "/")}
    assert {"RT-HDR-CSP", "RT-HDR-XCTO", "RT-HDR-FRAME", "RT-COOKIE-FLAGS", "RT-DISCLOSE-VERSION", "RT-CORS-REFLECT", "RT-DEBUG-LEAK"} <= found


def test_evidence_is_redacted():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.c2lnbmF0dXJlLXZhbHVl"
    response = {"id": "baseline", "status": 200, "headers": [["Set-Cookie", "session=s3cr3t-value; HttpOnly"], ["Authorization", "Bearer abc"], ["X-Request-Id", "r1"]],
                "body": f"token={jwt} password=hunter22 db=postgres://app:pw123@db/app key=tl-synthetic-0123456789abcdef"}
    redacted = json.dumps(dast.redact_response(response))
    for value in (jwt, "s3cr3t-value", "hunter22", "pw123", "Bearer abc", "tl-synthetic-0123456789abcdef"):
        assert value not in redacted
    assert "session=<redacted>; HttpOnly" in redacted and "X-Request-Id" in redacted


# ── Environment detection ────────────────────────────────────────────────────

def test_sample_app_gets_a_generated_non_root_dockerfile_synthetic_config_and_its_tests(tmp_path):
    plan = rt.detect(str(FIXTURES / "sample-app"), str(tmp_path))
    app = plan.app_service()
    dockerfile = Path(app.build["dockerfile"]).read_text()
    assert plan.stack == "python (generated Dockerfile)" and plan.port == 8000 and "USER 10001" in dockerfile
    assert plan.test_command == "python -m unittest discover -s tests -v"
    assert app.env["SHOP_NAME"] == "Sample Shop" and app.env["SESSION_SECRET"].startswith("tl-synthetic-")


def test_backing_services_come_from_dependencies_with_synthetic_credentials(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask==3.0.0\npsycopg2-binary==2.9.9\nredis==5.0.0\n")
    (tmp_path / "app.py").write_text("")
    plan = rt.detect(str(tmp_path), str(tmp_path))
    names = [s.name for s in plan.services]
    assert names == ["postgres", "redis", "app"]
    password = plan.services[0].env["POSTGRES_PASSWORD"]
    assert password.startswith("tl-synthetic-") and password in plan.app_service().env["DATABASE_URL"]


def test_compose_host_settings_are_dropped_and_builds_outside_the_repo_refused(monkeypatch, tmp_path):
    config = {"services": {"web": {"build": {"context": ".", "dockerfile": "Dockerfile"}, "ports": [{"target": 5000, "published": "5000"}],
                                   "volumes": [{"type": "bind", "source": "/", "target": "/host"}], "privileged": True,
                                   "environment": {"DB_PASSWORD": "${DB_PASSWORD:-devpass}", "DB_HOST": "db"}},
                           "db": {"image": "postgres:17", "environment": {"POSTGRES_PASSWORD": "devpass"}}}}
    (tmp_path / "docker-compose.yml").write_text("services: {}\n")
    monkeypatch.setattr(rt.shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(rt.subprocess, "run", lambda *a, **k: types.SimpleNamespace(returncode=0, stdout=json.dumps(config), stderr=""))
    plan = rt.detect(str(tmp_path), str(tmp_path))
    web, db = plan.app_service(), next(s for s in plan.services if s.name == "db")
    assert plan.app == "web" and plan.port == 5000 and set(web.dropped) == {"ports", "volumes", "privileged"}
    assert web.env["DB_PASSWORD"] == db.env["POSTGRES_PASSWORD"] and web.env["DB_PASSWORD"].startswith("tl-synthetic-")
    config["services"]["web"]["build"]["context"] = "../elsewhere"
    with pytest.raises(rt.EnvError, match="outside the repository"):
        rt.detect(str(tmp_path), str(tmp_path))


# ── Docker provider isolation ────────────────────────────────────────────────

class FakeDocker:
    def __init__(self, routes=("0000FEA9",)):
        self.calls, self.routes = [], list(routes)

    def __call__(self, argv, **kw):
        args = argv[1:]
        self.calls.append(args)
        out = ""
        if args[:2] == ["image", "inspect"] and "--format" in args:
            out = "10001"
        elif args[0] == "run" and "-i" in args:
            payload = json.loads(kw["input"])
            results = [{"id": p, "status": 200} for p in payload.get("paths", [])] if payload["mode"] == "health" else \
                      [{"id": r["id"], "status": 200, "headers": [], "body": ""} for r in payload["requests"]]
            out = json.dumps({"routes": self.routes, "results": results, **({"healthy": "/health"} if payload["mode"] == "health" else {})})
        elif args[0] in ("ps", "images") or args[:2] in (["network", "ls"], ["volume", "ls"]):
            removal = {"ps": ["rm"], "images": ["rmi"], "network": ["network", "rm"], "volume": ["volume", "rm"]}[args[0]]
            out = "" if any(c[:len(removal)] == removal for c in self.calls[:-1]) else "abc123"
        return types.SimpleNamespace(returncode=0, stdout=out, stderr="")


def _provisioned(tmp_path, fake):
    env = rt.DockerProvider(runner=fake)
    state = {"work": str(tmp_path), "run_id": "tl-dast-0123456789"}
    env.provision(state, rt.detect(str(FIXTURES / "sample-app"), str(tmp_path)))
    return env, state


def test_sandbox_is_an_internal_network_with_limits_labels_and_no_host_mounts(tmp_path):
    fake = FakeDocker()
    env, state = _provisioned(tmp_path, fake)
    env.deploy(state)
    env.run_tests(state)
    env.probe(state, dast.plan_requests(finding()))
    assert ["network", "create", "--internal", "--label", "threatlint.dast.run=tl-dast-0123456789", "tl-dast-0123456789-net"] in fake.calls
    runs = [c for c in fake.calls if c[0] == "run"]
    assert len(runs) == 4  # app, health probe, tests, probe
    for run in runs:
        joined = " ".join(run)
        assert "--network tl-dast-0123456789-net" in joined and "threatlint.dast.run=tl-dast-0123456789" in joined
        assert "--cpus" in run and "--memory" in run and "--pids-limit" in run and "no-new-privileges" in run and "ALL" in run
        assert not {"-v", "--volume", "--mount", "-p", "--publish", "--privileged", "--network=host"} & set(run)
    assert state["health"]["healthy"] and not state["health"]["default_route"] and state["tests"]["status"] == "PASSED"


def test_probe_refuses_a_network_with_a_default_route(tmp_path):
    fake = FakeDocker(routes=("00000000",))
    env, state = _provisioned(tmp_path, fake)
    env.deploy(state)
    assert state["health"]["default_route"]
    with pytest.raises(rt.EnvError, match="default route"):
        env.probe(state, dast.plan_requests(finding()))
    with pytest.raises(ar.ResolveError, match="default route"):
        dast.step_deploy(None, {**state, "work": str(tmp_path)}, types.SimpleNamespace(deploy=lambda s: s))


def test_teardown_removes_only_this_runs_labelled_resources(tmp_path):
    fake = FakeDocker()
    env, state = _provisioned(tmp_path, fake)
    env.teardown(state)
    filters = [c for c in fake.calls if "--filter" in c]
    assert filters and all(c[c.index("--filter") + 1] == "label=threatlint.dast.run=tl-dast-0123456789" for c in filters)
    assert ["rm", "-f", "-v", "abc123"] in fake.calls and ["network", "rm", "abc123"] in fake.calls and ["rmi", "-f", "abc123"] in fake.calls
    assert ["volume", "rm", "-f", "abc123"] in fake.calls
    assert state["teardown"]["remaining"] == []
    with pytest.raises(rt.EnvError, match="Invalid run id"):
        env.teardown({"work": str(tmp_path), "run_id": "anything; rm -rf /"})


# ── Flow ─────────────────────────────────────────────────────────────────────

class FakeProvider:
    name = "docker"

    def __init__(self, fail_at=""):
        self.fail_at, self.steps = fail_at, []

    def _step(self, name, state):
        self.steps.append(name)
        if name == self.fail_at:
            raise rt.EnvError(f"{name} failed")
        return state

    def provision(self, state, plan):
        state.update(network="n", built=["i"], app_user="10001", plan=rt.plan_dict(plan))
        return self._step("provision", state)

    def deploy(self, state):
        state["health"] = {"healthy": True, "path": "/health", "default_route": False, "responses": []}
        return self._step("deploy", state)

    def run_tests(self, state):
        state["tests"] = {"status": "PASSED", "command": "t", "exit": 0, "tail": "OK"}
        return self._step("tests", state)

    def probe(self, state, requests):
        self._step("probe", state)
        return [{"id": r["id"], "status": 200, "headers": [["Content-Type", "text/html"]], "body": "<p>hi</p>"} for r in requests]

    def teardown(self, state):
        self.steps.append("teardown")
        state["teardown"] = {"containers": 1, "networks": 1, "volumes": 0, "images": 1, "remaining": []}
        return state


def _git_repo(tmp_path):
    repo = tmp_path / "shop"
    subprocess.run(["cp", "-R", str(FIXTURES / "sample-app"), str(repo)], check=True)
    git = lambda *a: subprocess.run(["git", "-C", str(repo), "-c", "user.email=t@example.test", "-c", "user.name=t", *a], check=True, capture_output=True)
    git("init", "-q", "-b", "main")
    git("add", "-A")
    git("commit", "-qm", "init")
    git("checkout", "-qb", "release/1.0")
    return repo


def _dast_args(tmp_path, repo, **extra):
    values = dict(number=None, avit_file=str(FIXTURES / "invicti-xss-search.json"), repo=str(repo), branch="release/1.0", work=str(tmp_path / "run"), step=None,
                  env_provider="docker", service=None, port=None, health_path=None, test_command=None, start_command=None, keep_env=False, review_provider=None,
                  model=None, base_url="", api_key=None, resolve=False, report=None, docx=None, yes=True, snow_instance=INSTANCE, aws_profile=None)
    return types.SimpleNamespace(**{**values, **extra})


def test_full_run_writes_evidence_and_review_request_and_always_tears_down(monkeypatch, tmp_path):
    monkeypatch.setattr("sys.stdout", io.StringIO())
    provider = FakeProvider()
    args = _dast_args(tmp_path, _git_repo(tmp_path))
    assert dast.cmd_dast(args, provider) == 0
    assert provider.steps == ["provision", "deploy", "tests", "probe", "teardown"]
    request = (tmp_path / "run" / "review-request.md").read_text()
    assert "**Original finding**: AVIT0000000900001; Cross-site Scripting (Reflected); Invicti DAST; GET /search (q)" in request
    assert "#### [FP-001]" in request and "not a verified vulnerability" in request and "Observed: NO" in request
    assert os.path.isdir(tmp_path / "run" / "repo"), "the checkout stays for the reviewer until resolve"


@pytest.mark.parametrize("fail_at", ["deploy", "tests", "probe"])
def test_a_failed_step_still_tears_down_and_deletes_the_checkout(monkeypatch, tmp_path, fail_at):
    monkeypatch.setattr("sys.stdout", io.StringIO())
    provider = FakeProvider(fail_at)
    with pytest.raises(rt.EnvError):
        dast.cmd_dast(_dast_args(tmp_path, _git_repo(tmp_path)), provider)
    assert provider.steps[-1] == "teardown"
    assert not os.path.exists(tmp_path / "run" / "repo")


def test_steps_run_alone_against_the_saved_state(monkeypatch, tmp_path):
    monkeypatch.setattr("sys.stdout", io.StringIO())
    provider, repo = FakeProvider(), _git_repo(tmp_path)
    for step in ("provision", "deploy", "test", "probe", "teardown"):
        assert dast.cmd_dast(_dast_args(tmp_path, repo, step=step), provider) == 0
    state = dast.load_state(str(tmp_path / "run"))
    assert state["probe"]["assessment"]["kind"] == "xss" and state["checkout_deleted"]
    with pytest.raises(ar.ResolveError, match="needs --work"):
        dast.cmd_dast(_dast_args(tmp_path, repo, step="deploy", work=None), provider)


def test_repo_arguments_are_validated():
    for repo in ("http://github.com/a/b", "https://user:pw@github.com/a/b", "ssh://git@github.com/a/b"):
        with pytest.raises(ar.ResolveError, match="HTTPS Git URL"):
            dast.repository_target(repo, "main")
    with pytest.raises(ar.ResolveError, match="valid --branch"):
        dast.repository_target("https://github.com/a/b", "-c core.sshCommand=x")
    ado = dast.repository_target("https://dev.azure.com/contoso/Platform/_git/shop", "main")
    assert (ado["scm"], ado["organization"], ado["name"]) == ("azure-devops", "contoso", "shop")


# ── Resolve (mocked ServiceNow) ──────────────────────────────────────────────

ROW = {key: {"value": value["value"], "display_value": value["display_value"]} for key, value in
       json.loads((FIXTURES / "invicti-xss-search.json").read_text())["result"][0].items()}


class FakeServiceNow:
    def __init__(self):
        self.calls = []

    def __call__(self, url, *, data=None, headers, method=None):
        self.calls.append((method or ("POST" if data is not None else "GET"), url.split("?")[0], data))
        if url.endswith("/oauth_token.do"):
            return {"access_token": "t"}
        if "/sys_documentation" in url:
            return {"result": []}
        if "/sysrule_view" in url:
            return {"result": [{"condition": "u_scm_toolISNOTEMPTY"}]}
        if "u_scm_toolISNOTEMPTY" in url:
            return {"result": []}  # an Invicti AVIT is not in the CodeSecurity view
        if url.split("?")[0].endswith("/api/now/attachment"):
            return {"result": []}
        if "/attachment/file" in url:
            return {"result": {"sys_id": "b" * 32}}
        if method == "PATCH":
            body = json.loads(data)
            return {"result": {"state": body.get("state", "1"), "substate": body.get("substate", "")}}
        return {"result": [ROW]}


def _report(disposition):
    return f"""# FP Review — DAST

#### [FP-001] — Reflected XSS in /search

**Original finding**: AVIT0000000900001; Cross-site Scripting (Reflected); Invicti DAST; GET /search (q)
**Disposition**: {disposition}
**Severity**: HIGH
**Confidence**: CONFIRMED
"""


@pytest.mark.parametrize("disposition, note, closed", [("FALSE POSITIVE", ar.CLOSING_COMMENT, True), ("TRUE POSITIVE", ar.TRUE_POSITIVE_COMMENT, False)])
def test_resolve_uses_the_sast_path_without_semgrep(monkeypatch, tmp_path, disposition, note, closed):
    fake, hook = FakeServiceNow(), []
    monkeypatch.setattr(sn, "_request_json", fake)
    monkeypatch.setattr(sn, "resolve_credentials", lambda _p: ("id", "secret"))
    monkeypatch.setattr(ar, "_semgrep", lambda *a, **k: pytest.fail("Semgrep is never involved for an Invicti AVIT"))
    monkeypatch.setattr(ar, "semgrep_token", lambda *a: pytest.fail("Semgrep is never involved for an Invicti AVIT"))
    dast.set_invicti_hook(lambda item, verdict: hook.append((item["issue_id"], verdict["disposition"])) or "Invicti hook called")
    out = io.StringIO()
    monkeypatch.setattr("sys.stdout", out)
    work = tmp_path / "run"
    (work / "repo" / ".git").mkdir(parents=True)
    (work / dast.REPORT_FILE).write_text(_report(disposition))
    (work / "AVIT0000000900001-threatlint-fp-review.docx").write_bytes(b"PK-docx")
    state = {"work": str(work), "run_id": "tl-dast-0123456789", "avit": "AVIT0000000900001", "finding": finding(), "checkout": str(work / "repo")}
    try:
        dast.step_resolve(_dast_args(tmp_path, "unused", step="resolve"), state)
    finally:
        dast.set_invicti_hook(None)
    body = json.loads(next(d for m, _u, d in fake.calls if m == "PATCH"))
    assert body["work_notes"] == note and (body.get("state") == "3") is closed
    uploads = [u for m, u, _d in fake.calls if u.endswith("/attachment/file")]
    assert len(uploads) == 1
    assert hook == ([("synthetic-issue-0001", "FALSE POSITIVE")] if closed else [])
    assert ("Semgrep not applicable" in out.getvalue()) is closed
    assert not (work / "repo").exists(), "the checkout is deleted after resolving"


def test_the_invicti_hook_is_a_no_op_until_configured():
    assert "no Invicti integration configured" in dast.invicti_mark_false_positive(finding(), {"disposition": "FALSE POSITIVE"})


def test_cli_wires_avit_dast():
    from threatlint.cli import build_parser
    args = build_parser().parse_args(["avit", "dast", "--avit-file", "x.json", "--repo", "https://github.com/a/b", "--branch", "main", "--step", "probe", "--work", "w"])
    assert (args.avit_command, args.step, args.env_provider) == ("dast", "probe", "docker")
