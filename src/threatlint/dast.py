"""Validate dynamic-scan (Invicti DAST) AVITs against an ephemeral, isolated deployment of the application.

`threatlint avit dast <AVIT | --avit-file record.json> --repo URL --branch B` runs, in order:
  provision  clone the branch, detect the stack, build images, create an internal (no-egress) network
  deploy     start the app and backing services with synthetic config, wait for health
  test       run the repository's own test suite against the deployment
  probe      send the bounded checks for the AVIT's Invicti finding to the sandbox app only; record redacted evidence
  teardown   remove the run's containers, networks, volumes and built images (always, also on failure)
  review     write the review request for the FP reviewer (or run it with --review-provider); the reviewer writes
             fp_review.md with the same Original finding / Disposition / Severity / Confidence lines as SAST
  resolve    `threatlint avit resolve`: attach the report; close a false positive, add a work note to a true positive
Each step can run alone with `--step STEP --work DIR`; state is kept in DIR/dast-state.json.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import urllib.parse
from typing import Callable

from threatlint import avit_resolve as ar
from threatlint import runtime_env as rt
from threatlint import servicenow as sn
from threatlint.avit_resolve import ResolveError
from threatlint.dast_evidence import (
    _SECRET_VALUES, _SENSITIVE_HEADERS, _cell, _fence,
    evidence_markdown, redact_response, redact_text, review_request,
)
from threatlint.dast_requests import PROBE_ORIGIN, REDIRECT_PROBE, _request, plan_requests
from threatlint.dast_passive import DEBUG_SIGNATURES, HEADER_CHECKS, _headers, passive_checks
from threatlint.dast_records import _FIELDS, _INVICTI, _KINDS, _norm, check_kind, invicti_finding, load_avit_file
from threatlint.dast_probe import SQL_ERRORS, assess, collect_probe
from threatlint.dast_cli import STEPS, configure_parser

STATE_FILE = "dast-state.json"
REPORT_FILE = "fp_review.md"


def fetch_from_servicenow(args, avit: str) -> dict[str, str]:
    instance, token = ar._session(args)
    return ar._record(instance, token, avit)["fields"]


# ── State ────────────────────────────────────────────────────────────────────

def load_state(work: str) -> dict:
    try:
        with open(os.path.join(work, STATE_FILE), encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError) as exc:
        raise ResolveError(f"No DAST run state in {work}; run `--step provision` first") from exc


def save_state(state: dict) -> None:
    with open(os.path.join(state["work"], STATE_FILE), "w", encoding="utf-8") as handle:
        json.dump(state, handle, indent=1)


def repository_target(repo: str, branch: str) -> dict[str, str]:
    """Clone target for --repo / --branch: an HTTPS Git URL (credentials scoped to GitHub / Azure DevOps) or a local repository."""
    branch = re.sub(r"^refs/heads/", "", (branch or "").strip())
    if not branch or not sn._BRANCH.fullmatch(branch):
        raise ResolveError("Pass a valid --branch")
    if os.path.isdir(os.path.expanduser(repo)) or repo.startswith("file://"):
        path = os.path.realpath(os.path.expanduser(repo[7:] if repo.startswith("file://") else repo))
        return {"scm": "local", "clone_url": path, "web_url": path, "branch": branch, "name": os.path.basename(path), "organization": "", "project": ""}
    url = urllib.parse.urlsplit(repo)
    if url.scheme != "https" or not url.hostname or url.username or url.password or url.query or url.fragment:
        raise ResolveError("--repo must be an HTTPS Git URL without credentials, or a local repository path")
    host, parts = url.hostname.lower(), [urllib.parse.unquote(part) for part in url.path.strip("/").split("/") if part]
    if host == "dev.azure.com" and len(parts) >= 4 and parts[2] == "_git":
        scm, org, project = "azure-devops", parts[0], parts[1]
    else:
        scm, org, project = ("github" if host == "github.com" else "git"), parts[0] if parts else "", ""
    return {"scm": scm, "clone_url": repo, "web_url": re.sub(r"\.git$", "", repo), "branch": branch, "name": re.sub(r"\.git$", "", parts[-1] if parts else "repo"),
            "organization": org, "project": project}


def clone(target: dict[str, str], directory: str) -> None:
    if target["scm"] != "local":
        sn.checkout_repository(target, directory)
        return
    git = shutil.which("git") or "git"
    result = subprocess.run([git, "clone", "--depth", "1", "--single-branch", "--no-tags", "--branch", target["branch"], "--", "file://" + target["clone_url"], directory],
                            capture_output=True, text=True, timeout=600, check=False, env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})
    if result.returncode != 0:
        raise ResolveError(f"Could not clone {target['web_url']} branch {target['branch']}: {(result.stderr.strip().splitlines() or ['git clone failed'])[-1][:200]}")


# ── Steps ────────────────────────────────────────────────────────────────────

def step_provision(args, state: dict, env: rt.EnvironmentProvider) -> dict:
    if getattr(args, "avit_file", None):
        fields = load_avit_file(args.avit_file)
        origin = f"file {os.path.basename(args.avit_file)}"
    else:
        if not args.number:
            raise ResolveError("Pass an AVIT number or --avit-file")
        fields = fetch_from_servicenow(args, args.number.upper())
        origin = "ServiceNow"
    finding = invicti_finding(fields, (args.number or "").upper())
    if not args.repo or not args.branch:
        raise ResolveError("Pass --repo and --branch: an Invicti finding names a URL, not a repository")
    target = repository_target(args.repo, args.branch)
    state.update(avit=finding["avit"], finding=finding, fields={k: v[:2000] for k, v in fields.items()}, avit_origin=origin, target=target,
                 checkout=os.path.join(state["work"], "repo"), provider=env.name, started=datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"))
    save_state(state)
    print(f"  {finding['avit']} : {finding['vulnerability'] or 'unnamed'} · {finding['method']} {finding['path']}"
          f"{' · parameter ' + finding['parameter'] if finding['parameter'] else ''} · check {finding['kind']} ({origin})")
    clone(target, state["checkout"])
    print(f"  ✓ Checked out {target['web_url']} · branch {target['branch']}")
    plan = rt.detect(state["checkout"], state["work"], service=args.service or "", port=args.port or 0, health_path=args.health_path or "",
                     test_command=args.test_command, start_command=args.start_command or "")
    for note in plan.notes:
        print(f"    {note}")
    state["plan"] = rt.plan_dict(plan)
    save_state(state)
    print(f"  Building {plan.stack}: {', '.join(item.name for item in plan.services)} (egress allowed only while building)")
    try:
        env.provision(state, plan)
    finally:
        save_state(state)
    print(f"  ✓ Built {len(state.get('built', []))} image(s); internal network {state['network']} (no egress)"
          + ("" if state.get("app_user") not in ("", "root", "0") else " · ! the application image runs as root"))
    return state


def step_deploy(args, state: dict, env: rt.EnvironmentProvider) -> dict:
    env.deploy(state)
    save_state(state)
    health = state["health"]
    if health["default_route"]:
        raise ResolveError("The sandbox network has a default route; refusing to continue")
    if not health["healthy"]:
        raise ResolveError(f"The application did not become healthy within the start timeout ({health['responses']})")
    print(f"  ✓ Deployed; healthy on {health['path']} · no default route (egress blocked)")
    return state


def step_test(args, state: dict, env: rt.EnvironmentProvider) -> dict:
    env.run_tests(state)
    save_state(state)
    tests = state["tests"]
    print(f"  {'✓' if tests['status'] == 'PASSED' else '!'} Tests {tests['status']}" + (f": {tests['command']} (exit {tests['exit']})" if tests["command"] else f" ({tests['tail']})"))
    return state


def step_probe(args, state: dict, env: rt.EnvironmentProvider) -> dict:
    finding = state["finding"]
    state["probe"] = collect_probe(state, env, secrets.token_hex(4))
    result, requests = state["probe"]["assessment"], state["probe"]["requests"]
    save_state(state)
    with open(os.path.join(state["work"], "evidence.md"), "w", encoding="utf-8") as handle:
        handle.write(evidence_markdown(state))
    flag = {True: "observed", False: "not observed", None: "inconclusive"}[result["observed"]]
    print(f"  ✓ Probed with {len(requests)} request(s): {finding['kind']} behaviour {flag}")
    for signal in result["signals"]:
        print(f"    {signal}")
    print(f"  ✓ Evidence: {os.path.join(state['work'], 'evidence.md')}")
    return state


def step_teardown(args, state: dict, env: rt.EnvironmentProvider, *, checkout: bool = True) -> dict:
    env.teardown(state)
    done = state["teardown"]
    print(f"  ✓ Removed {done['containers']} container(s), {done['networks']} network(s), {done['volumes']} volume(s), {done['images']} image(s)"
          + (f" · ! still present: {', '.join(done['remaining'])}" if done["remaining"] else ""))
    if checkout and ar.remove_checkout(state.get("checkout")):
        state["checkout_deleted"] = True
        print(f"  ✓ Deleted the checkout {state['checkout']}")
    save_state(state)
    return state


def step_review(args, state: dict, env: rt.EnvironmentProvider | None = None) -> dict:
    path = os.path.join(state["work"], "review-request.md")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(review_request(state))
    report = os.path.join(state["work"], REPORT_FILE)
    state["review_request"] = path
    if not getattr(args, "review_provider", None):
        save_state(state)
        print(f"  ✓ Review request: {path}")
        print(f"    Next: have appsec-fp-reviewer (Claude Code `/fp-review {path}`) write {report}, then run `--step resolve --work {state['work']}`")
        return state
    from threatlint import cli  # noqa: PLC0415
    from threatlint.skills import agent_prompt, findings_text  # noqa: PLC0415
    resolved = cli._resolve_provider(argparse.Namespace(provider=args.review_provider, api_key=args.api_key or "", base_url=args.base_url))
    if resolved is None:
        raise ResolveError("The review model provider is not available")
    provider, base_url, api_key = resolved
    with open(path, encoding="utf-8") as handle:
        message = f"The repository to analyze is located at: {state['checkout']}\n" + findings_text(f"DAST evidence for {state['avit']}", handle.read())
    runner = cli._run_claude_api if provider == "claude" else cli._run_agent
    endpoint = f"{base_url}/messages" if provider == "claude" else base_url
    output = runner(endpoint, cli._default_run_model(provider, args.model), agent_prompt("appsec-fp-reviewer"),
                    message + "\nBegin your analysis now and produce the complete report as specified.", state["checkout"], api_key=api_key)
    if not output.strip():
        raise ResolveError("The reviewer produced no report")
    with open(report, "w", encoding="utf-8") as handle:
        handle.write(output)
    state["report"] = report
    save_state(state)
    print(f"  ✓ Report: {report}")
    return state


# Hook point for marking the issue false positive in Invicti. Nothing calls a live Invicti API: register a callable with
# set_invicti_hook(fn) (fn(finding, verdict) -> message) once an Invicti integration exists.
_INVICTI_HOOK: Callable[[dict, dict], str] | None = None


def set_invicti_hook(hook: Callable[[dict, dict], str] | None) -> None:
    global _INVICTI_HOOK
    _INVICTI_HOOK = hook


def invicti_mark_false_positive(finding: dict, verdict: dict) -> str:
    if _INVICTI_HOOK is None:
        return f"Invicti not updated (no Invicti integration configured){'; issue ' + finding['issue_id'] if finding.get('issue_id') else ''}"
    return _INVICTI_HOOK(finding, verdict)


def to_docx(markdown: str, docx: str) -> None:
    script = os.path.join(os.path.dirname(__file__), "data", "scripts", "md_to_docx.py")
    result = subprocess.run([sys.executable, script, markdown, docx], capture_output=True, text=True, timeout=180, check=False)
    if result.returncode != 0 or not os.path.isfile(docx):
        raise ResolveError(f"Could not convert the report to Word (python-docx installed?): {(result.stderr.strip().splitlines() or ['failed'])[-1][:200]}")


def step_resolve(args, state: dict, env: rt.EnvironmentProvider | None = None) -> dict:
    report = getattr(args, "report", None) or os.path.join(state["work"], REPORT_FILE)
    if not os.path.isfile(report):
        raise ResolveError(f"No FP review report at {report}; run the review first")
    with open(report, encoding="utf-8") as handle:
        verdict = ar.verdict_for(handle.read(), state["avit"])
    docx = getattr(args, "docx", None) or os.path.join(state["work"], f"{state['avit']}-threatlint-fp-review.docx")
    if not os.path.isfile(docx):
        to_docx(report, docx)
    # Same path as SAST: attach, close a false positive, note a true positive. Semgrep has nothing for an Invicti finding.
    resolve_args = argparse.Namespace(number=state["avit"], report=report, docx=docx, semgrep_deployment=None, skip_semgrep=True, skip_rule_tuning=True,
                                      checkout=None, keep_checkout=True, yes=args.yes, snow_instance=args.snow_instance, aws_profile=args.aws_profile, avit_command="resolve")
    code = ar.cmd_resolve(resolve_args)
    if code:
        raise ResolveError(f"avit resolve exited {code}")
    if verdict["disposition"] == "FALSE POSITIVE":
        print(f"  {invicti_mark_false_positive(state['finding'], verdict)}")
    state["resolved"] = verdict
    save_state(state)
    if ar.remove_checkout(state.get("checkout")):
        print(f"  ✓ Deleted the checkout {state['checkout']}")
    return state


# ── CLI ──────────────────────────────────────────────────────────────────────

def add_dast_parser(actions) -> None:
    configure_parser(actions, description=__doc__)


def cmd_dast(args, env: rt.EnvironmentProvider | None = None) -> int:
    env = env or rt.provider(args.env_provider)
    handlers = {"provision": step_provision, "deploy": step_deploy, "test": step_test, "probe": step_probe, "review": step_review, "resolve": step_resolve}
    if args.step:
        if not args.work:
            raise ResolveError("--step needs --work DIR")
        if args.step == "provision":
            os.makedirs(args.work, exist_ok=True)
            state = {"work": os.path.realpath(args.work), "run_id": rt.DockerProvider.new_run_id()}
        else:
            state = load_state(args.work)
        if args.step == "teardown":
            step_teardown(args, state, env)
        else:
            try:
                handlers[args.step](args, state, env)
            except BaseException:
                if args.step in ("provision", "deploy") and not args.keep_env:
                    print("  ! Step failed; tearing the environment down", file=sys.stderr)
                    step_teardown(args, state, env)
                raise
        return 0
    work = os.path.realpath(args.work) if args.work else rt.scratch_dir()
    os.makedirs(work, exist_ok=True)
    state = {"work": work, "run_id": rt.DockerProvider.new_run_id()}
    print(f"threatlint avit dast · run {state['run_id']} · {work}")
    ok = False
    try:
        for step in ("provision", "deploy", "test", "probe"):
            print(f"[{step}]")
            handlers[step](args, state, env)
        ok = True
    finally:
        print("[teardown]")
        if args.keep_env and ok:
            print(f"  Environment kept (--keep-env); remove it with `--step teardown --work {work}`")
        else:
            # On failure the checkout goes too; on success it stays only until the review reads it.
            step_teardown(args, state, env, checkout=not ok)
    print("[review]")
    step_review(args, state, env)
    if args.resolve and os.path.isfile(os.path.join(work, REPORT_FILE)):
        print("[resolve]")
        step_resolve(args, state, env)
    elif getattr(args, "review_provider", None) and ar.remove_checkout(state.get("checkout")):
        print(f"  ✓ Deleted the checkout {state['checkout']}")
    return 0
