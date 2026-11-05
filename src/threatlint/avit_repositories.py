"""Resolve AVIT repository renames, deleted branches, and verified removals."""

from __future__ import annotations

import base64
import json
import os
import re
import shutil
import sys
import urllib.error
import urllib.parse
import urllib.request

from threatlint import servicenow as sn
from threatlint.avit_report import ResolveError
from threatlint import tls


def cmd_checkout(args, *, session, read_record, checkout_branch, renamed_repository) -> int:
    [avit] = sn.parse_avit_numbers(args.number)
    instance, token = session(args)
    record = read_record(instance, token, avit)
    kind = sn.finding_kind(record)
    try:
        target = sn.repository_target(record["context"])
    except sn.ServiceNowError as exc:
        if sn.in_code_security_view(record):
            raise
        raise ResolveError(f"{avit} names no repository ({exc}); triage it from the AVIT evidence without a checkout") from exc
    if target["scm"] == "azure-devops" and not sn.git_credential("azure-devops", target["organization"])[0] and sys.stdin.isatty():
        from threatlint.ado_login import prompt_and_save
        print("  No Azure DevOps credential found; set up a PAT now (Code: Read).")
        print(f"  ✓ Saved to {prompt_and_save(target['organization'])}")
    print(f"  {avit} : {target['web_url']} · branch {target['branch'] or '(default)'} · {record['context'].get('file_path', 'no file path')}")
    path = record["context"].get("file_path", "")
    try:
        target = checkout_branch(target, args.dir, path)
    except sn.ServiceNowError as exc:
        renamed = renamed_repository(target, args) if target["scm"] == "azure-devops" and "not found" in str(exc) else None
        if not renamed:
            raise
        print(f"  ! {target['name']} was renamed in Azure DevOps to {renamed}; cloning it (Semgrep still uses the original project name)")
        quote = lambda value: urllib.parse.quote(value, safe="")
        url = f"https://dev.azure.com/{quote(target['organization'])}/{quote(target['project'])}/_git/{quote(renamed)}"
        shutil.rmtree(args.dir, ignore_errors=True)
        target = checkout_branch({**target, "clone_url": url, "web_url": url, "renamed_to": renamed}, args.dir, path)
    print(f"✓ Checked out to {args.dir}")
    print(json.dumps({"avit": avit, "kind": kind, "checkout": os.path.abspath(args.dir), **target, **{k: v for k, v in record["context"].items() if k in ("file_path", "line", "rule", "finding_source")}}))
    return 0


def checkout_branch(target: dict[str, str], directory: str, path: str) -> dict[str, str]:
    """Fall back to the default branch only when the named branch was deleted."""
    try:
        sn.checkout_repository(target, directory, path)
        return target
    except sn.ServiceNowError as exc:
        if not (target["branch"] and re.search(r"Remote branch .* not found", str(exc))):
            raise
        print(f"  ! Branch {target['branch']} no longer exists; checking out the default branch instead")
        shutil.rmtree(directory, ignore_errors=True)
        target = {**target, "branch_deleted": target["branch"], "branch": ""}
        sn.checkout_repository(target, directory, path)
        if path and not os.path.exists(os.path.join(directory, path)):
            raise ResolveError(f"Branch {target['branch_deleted']} was deleted and {path} is not on the default branch") from exc
        return target


def renamed_ado_repository(target: dict[str, str], args) -> str | None:
    """Resolve the repository GUID retained by Semgrep to its current ADO name."""
    from threatlint import semgrep_platform as sp
    from threatlint.ado_login import AdoLoginError, load
    try:
        token = sp.resolve_token(getattr(args, "aws_profile", None))[0]
        dep = sp.deployment(token)
        project = sp.call(f"/api/v1/deployments/{urllib.parse.quote(dep['slug'])}/projects/{urllib.parse.quote(target['project'] + '/' + target['name'], safe='/')}", token)
    except sp.SemgrepError:
        return None
    url = str((project.get("project") or project).get("url", ""))
    match = re.search(r"/_apis/git/repositories/([0-9a-f-]{36})", url)
    try:
        pat, _source = load(target["organization"], profile=getattr(args, "aws_profile", None))
    except AdoLoginError as exc:
        raise sn.ServiceNowError(str(exc)) from exc
    if not match or not pat:
        return None
    request = urllib.request.Request(f"https://dev.azure.com/{urllib.parse.quote(target['organization'])}/_apis/git/repositories/{match.group(1)}?api-version=7.1",
                                     headers={"Authorization": "Basic " + base64.b64encode(f":{pat}".encode()).decode(), "Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=30, context=tls.ssl_context()) as response:
            name = json.loads(response.read()).get("name")
    except (urllib.error.URLError, ValueError):
        return None
    return name if isinstance(name, str) and name and name != target["name"] else None


def repository_removed(target: dict[str, str]) -> bool:
    """Credential/network failures are never interpreted as repository removal."""
    if target.get("scm") != "azure-devops":
        raise ResolveError("Only Azure DevOps repositories can be checked for removal")
    header, _source = sn.git_credential("azure-devops", target["organization"])
    if not header:
        raise ResolveError(f"No Azure DevOps credential for {target['organization']}; cannot confirm the repository was removed")
    quote = lambda value: urllib.parse.quote(value, safe="")

    def get(url: str):
        request = urllib.request.Request(url, headers={"Authorization": header, "Accept": "application/json"})
        with urllib.request.urlopen(request, timeout=120, context=tls.ssl_context()) as response:
            body = response.read()
        if not body.lstrip().startswith(b"{"):
            raise ResolveError(f"Azure DevOps did not accept the credential for {target['organization']}; cannot confirm removal")
        return json.loads(body)

    try:
        repos = get(f"https://dev.azure.com/{quote(target['organization'])}/_apis/git/repositories?api-version=7.1").get("value", [])
    except urllib.error.URLError as exc:
        raise ResolveError(f"Could not list {target['organization']} repositories: {exc}") from exc
    if len(repos) == 0:
        raise ResolveError(f"The credential sees no repositories in {target['organization']}; cannot confirm removal")
    return not any(repo.get("name", "").lower() == target["name"].lower() for repo in repos)
