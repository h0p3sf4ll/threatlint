"""Publish a bounded reviewer proposal as an Azure DevOps or GitHub draft PR.

The reviewer remains read-only. This host workflow proves the diff against an
isolated Git index, then uses the configured credential for one branch and draft PR.
It never modifies the checkout, runs repository code, or merges a PR.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path, PurePosixPath

from . import servicenow as sn, tls
from .avit_report import ResolveError, verdict_for
from .finding_review import _structure, is_conservative, report_fields

FIX_PATCH_GUIDANCE = (
    "Use repository read/search tools to resolve evidence gaps before preparing a fix: inspect the "
    "full flagged function, actual callers, input/exposure path, relevant guards and configuration, "
    "and existing test patterns. For a supported TRUE POSITIVE, include **Evidence** with quoted "
    "file:line references, **Exploit path** explaining the concrete unsafe behavior and failed controls, "
    "**Fix rationale**, and **Regression assertions**. Set Confidence CONFIRMED only when the "
    "inspected evidence establishes the vulnerability; static proof does not require running an exploit. "
    "Provide the smallest concrete source fix under a line exactly "
    "**Proposed fix patch**:, followed immediately by one fenced diff block containing a complete "
    "git-style unified diff (diff --git, --- a/path, +++ b/path, and accurate context hunks) against "
    "the inspected checkout. Include relevant regression-test source when supported. Use only "
    "regular UTF-8 source/test files; do not change Git control files, symlinks, binary files, or "
    "file modes. Never include credential values, even in removed/context lines. Do not apply the "
    "patch or run tests. This proposal may be published by the authorized host as a draft PR; "
    "label test execution NOT RUN. Omit the patch when the decision is CONSERVATIVE DEFAULT, "
    "evidence is insufficient, or no safe concrete code change can be derived."
)

_MAX_PATCH = 256 * 1024
_MAX_FILE = 1024 * 1024
_MAX_FILES = 20
_SHA = re.compile(r"[a-f0-9]{40}")
_SECRET = re.compile(
    r"\b(?:sk-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16})\b"
    r"|-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----"
    r"|(?i:(?:password|passwd|secret|token|api[_-]?key|connection[_-]?string)[\w.-]*[\"']?\s*[:=]\s*[\"'][A-Za-z0-9+/=._~-]{16,}[\"'])"
)


def _skip(reason: str) -> dict:
    return {"status": "skipped", "reason": reason}


def _summary(value: str) -> str:
    text = " ".join(re.sub(r"[\x00-\x1f\x7f`*<>\[\]]", " ", str(value or "")).split())[:140]
    if not text or _SECRET.search(text) or re.search(r"[A-Za-z0-9_+/.=-]{24,}", text):
        return "Remediate the reviewed security finding"
    return text


def _git(repo: Path, args: list[str], *, data: bytes | None = None, extra: dict | None = None,
         allow_failure: bool = False) -> bytes:
    # Do not pass AWS, PAT, provider, or user Git configuration to child processes.
    env = {key: os.environ[key] for key in ("PATH", "SYSTEMROOT", "WINDIR", "TMP", "TEMP") if key in os.environ}
    env.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_NO_REPLACE_OBJECTS": "1", "GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0",
                "GIT_ATTR_NOSYSTEM": "1", "GIT_NO_LAZY_FETCH": "1"})
    env.update(extra or {})
    command = ["git", "--no-pager", "-C", str(repo), "-c", "core.fsmonitor=false",
               "-c", f"core.hooksPath={os.devnull}", "-c", f"core.attributesFile={os.devnull}", *args]
    try:
        result = subprocess.run(command, input=data, capture_output=True, timeout=30, check=False, env=env)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ResolveError("Could not validate the proposed fix with Git") from exc
    if result.returncode and not allow_failure:
        # Git diagnostics can echo source lines or repository credentials.
        raise ResolveError("The proposed fix could not be validated against the clean reviewed checkout")
    return result.stdout


def _patch(report: str) -> str:
    markers = list(re.finditer(
        r"(?im)^ {0,3}(?:[-*+][ \t]+)?(?:\*\*Proposed fix patch(?:\*\*[ \t]*:|[ \t]*:\*\*)"
        r"|#{2,6}[ \t]+Proposed fix patch[ \t]*:?)[ \t]*$", _structure(report),
    ))
    if not markers:
        return ""
    if len(markers) != 1:
        raise ResolveError("The report needs exactly one complete Proposed fix patch diff block")
    match = re.match(r"\n[ \t]*(?P<fence>`{3,}|~{3,})diff[ \t]*\n(?P<patch>.*?)^(?P=fence)[ \t]*$",
                     report[markers[0].end():], re.M | re.S)
    if not match:
        raise ResolveError("The report needs exactly one complete Proposed fix patch diff block")
    patch = match["patch"]
    if not patch.strip() or len(patch.encode()) > _MAX_PATCH or "\x00" in patch:
        raise ResolveError("The proposed fix patch is empty, binary, or too large")
    if _SECRET.search(patch) or "[REDACTED]" in patch:
        raise ResolveError("The proposed fix contains credential-like or redacted content; prepare a safe patch manually")
    return patch


def _path(value: str, repo: Path) -> str:
    path = PurePosixPath(value)
    if (not value or path.is_absolute() or str(path) != value or "\\" in value
            or any(ord(char) < 32 or ord(char) == 127 for char in value)
            or any(part in (".", "..") or part.casefold() in (".git", ".gitmodules", ".gitattributes", ".gitconfig", ".lfsconfig") for part in path.parts)):
        raise ResolveError("The proposed fix contains an unsupported file path")
    current = repo
    for part in path.parts:
        current /= part
        if current.is_symlink():
            raise ResolveError("The proposed fix cannot touch symlinks")
    if not current.resolve().is_relative_to(repo):
        raise ResolveError("The proposed fix escapes the reviewed checkout")
    return value


def _prepare(repo: Path, patch: str, head: str) -> tuple[list[dict], str]:
    headers = re.findall(r"(?m)^diff --git a/(.+) b/\1$", patch)
    if not headers or len(headers) > _MAX_FILES or len(headers) != len(set(headers)):
        raise ResolveError("The proposed fix must contain 1–20 distinct regular-file diffs")
    if len(headers) != len(re.findall(r"(?m)^diff --git ", patch)):
        raise ResolveError("The proposed fix cannot rename files or use quoted paths")
    paths = {_path(value, repo) for value in headers}
    if re.search(r"(?m)^(?:old mode|new mode|rename |copy |GIT binary patch|Binary files)", patch):
        raise ResolveError("Binary, rename, copy, and file-mode changes are not supported")
    for mode in re.findall(r"(?m)^(?:new file mode|deleted file mode) (\d+)$", patch):
        if mode != "100644":
            raise ResolveError("The proposed fix can only add or delete regular non-executable files")
    for value in re.findall(r"(?m)^(?:---|\+\+\+) (.+)$", patch):
        if value != "/dev/null" and (value[:2] not in ("a/", "b/") or _path(value[2:], repo) not in paths):
            raise ResolveError("The proposed fix has inconsistent file headers")
    with tempfile.TemporaryDirectory(prefix="threatlint-fix-") as temporary:
        objects = Path(temporary) / "objects"
        objects.mkdir()
        source_objects = _git(repo, ["rev-parse", "--git-path", "objects"]).decode().strip()
        extra = {"GIT_INDEX_FILE": str(Path(temporary) / "index"), "GIT_OBJECT_DIRECTORY": str(objects),
                 "GIT_ALTERNATE_OBJECT_DIRECTORIES": str((repo / source_objects).resolve())}
        _git(repo, ["read-tree", head], extra=extra)
        _git(repo, ["apply", "--cached", "--check", "--whitespace=nowarn", "-"], data=patch.encode(), extra=extra)
        _git(repo, ["apply", "--cached", "--whitespace=nowarn", "-"], data=patch.encode(), extra=extra)
        changed = _git(repo, ["diff", "--cached", "--name-status", "--no-renames", "--no-ext-diff", "--no-textconv", "-z", head, "--"], extra=extra).decode().split("\x00")[:-1]
        if len(changed) % 2 or not changed or len(changed) // 2 > _MAX_FILES:
            raise ResolveError("The proposed fix produced no valid file changes")
        changes = []
        for action, value in zip(changed[::2], changed[1::2]):
            if action not in ("A", "M", "D") or _path(value, repo) not in paths:
                raise ResolveError("The proposed fix produced unsupported file changes")
            old = _git(repo, ["ls-tree", head, "--", value]).decode().split()
            new = _git(repo, ["ls-files", "--stage", "--", value], extra=extra).decode().split()
            if (old and old[0] not in ("100644", "100755")) or (new and new[0] not in ("100644", "100755")) or (old and new and old[0] != new[0]):
                raise ResolveError("The proposed fix cannot change file modes or non-regular files")
            change = {"changeType": {"A": "add", "M": "edit", "D": "delete"}[action], "item": {"path": "/" + value}}
            if action != "D":
                if int(_git(repo, ["cat-file", "-s", new[1]], extra=extra)) > _MAX_FILE:
                    raise ResolveError("A proposed fix file exceeds the 1 MiB limit")
                raw = _git(repo, ["cat-file", "blob", new[1]], extra=extra)
                try:
                    content = raw.decode("utf-8")
                except UnicodeDecodeError as exc:
                    raise ResolveError("The proposed fix requires UTF-8 text files") from exc
                if "\x00" in content or _SECRET.search(content):
                    raise ResolveError("The proposed fix contains binary or credential-like content")
                change["newContent"] = {"content": content, "contentType": "rawtext"}
            changes.append(change)
        tree = _git(repo, ["write-tree"], extra=extra).decode().strip()
        return changes, tree


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _request(base: str, pat: str, path: str = "", *, params: dict | None = None, body: dict | None = None) -> dict:
    query = urllib.parse.urlencode({"api-version": "7.1", **(params or {})})
    encoded = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(f"{base}{path}?{query}", data=encoded,
                                    headers={"Authorization": "Basic " + base64.b64encode(f":{pat}".encode()).decode(),
                                             "Accept": "application/json", "Content-Type": "application/json"})
    opener = urllib.request.build_opener(_NoRedirect(), urllib.request.HTTPSHandler(context=tls.ssl_context()))
    try:
        with opener.open(request, timeout=45) as response:
            data = response.read(2 * 1024 * 1024 + 1)
        if len(data) > 2 * 1024 * 1024:
            raise ResolveError("Azure DevOps returned an oversized response")
        result = json.loads(data)
    except urllib.error.HTTPError as exc:
        raise ResolveError(f"Azure DevOps PR operation failed (HTTP {exc.code}); check service-account Code write and PR permissions") from None
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        raise ResolveError("Azure DevOps PR operation failed; check connectivity and service-account access") from None
    if not isinstance(result, dict):
        raise ResolveError("Azure DevOps returned an unreadable PR response")
    return result


def _ref(base: str, pat: str, name: str) -> str:
    rows = _request(base, pat, "/refs", params={"filter": name.removeprefix("refs/"), "$top": 100}).get("value")
    if not isinstance(rows, list):
        raise ResolveError("Azure DevOps did not return readable branch references")
    found = [row.get("objectId", "") for row in rows if isinstance(row, dict) and row.get("name") == name]
    if len(found) > 1 or (found and (not isinstance(found[0], str) or not _SHA.fullmatch(found[0]))):
        raise ResolveError("Azure DevOps returned an invalid branch revision")
    return found[0] if found else ""


def create_fix_pr(avit: str, report: str, checkout: str, target: dict, *, profile=None, instance="") -> dict:
    """Create/reuse one draft PR, or explain why this review has no publishable fix."""
    if not re.fullmatch(r"AVIT\d{7,15}", avit):
        raise ResolveError("A fix PR requires a valid AVIT number")
    verdict = verdict_for(report, avit)
    if verdict["disposition"] != "TRUE POSITIVE":
        return _skip("False positives do not require a source-fix PR")
    if is_conservative(verdict):
        return _skip("The report marks this TRUE POSITIVE as unverified (conservative default); no automatic fix PR was opened")
    originals = report_fields(report, "Original finding")
    if len(originals) != 1 or re.findall(r"(?i)(?<![A-Z0-9])AVIT\d{7,15}(?![A-Z0-9])", originals[0]) != [avit]:
        return _skip("Automatic fix PRs require a report for this AVIT alone")
    if target.get("scm") not in ("azure-devops", "github"):
        return _skip("Automatic fix PRs support Azure DevOps and GitHub repositories")
    if not target.get("branch") or target.get("branch_deleted"):
        return _skip("A fix PR requires the exact reviewed AVIT branch")
    patch = _patch(report)
    if not patch:
        return _skip("The report has no concrete proposed fix patch")
    repo = Path(checkout).resolve()
    if not (repo / ".git").is_dir() or (repo / ".git").is_symlink():
        return _skip("A fix PR requires a complete Git checkout")
    canonical = sn.repository_target({"scm_tool": "ado" if target["scm"] == "azure-devops" else "github", "organization": target.get("organization", ""),
                                      "project": target.get("project", ""), "repository": target.get("renamed_to") or target.get("name", ""),
                                      "branch": target["branch"]})
    if _git(repo, ["remote", "get-url", "origin"]).decode().strip().removesuffix(".git") != canonical["clone_url"].removesuffix(".git"):
        raise ResolveError("The checkout origin does not match the AVIT repository")
    target_ref = "refs/heads/" + canonical["branch"]
    if _git(repo, ["symbolic-ref", "HEAD"]).decode().strip() != target_ref:
        raise ResolveError("The checkout branch does not match the AVIT branch")
    # A local filter could execute repository code during status; fail before status.
    if _git(repo, ["config", "--get-regexp", r"^filter\."], allow_failure=True):
        raise ResolveError("A checkout with Git content filters requires manual PR preparation")
    if _git(repo, ["status", "--porcelain", "--untracked-files=all", "--ignore-submodules=all"]):
        raise ResolveError("The reviewed checkout must be clean before preparing a fix PR")
    head = _git(repo, ["rev-parse", "HEAD"]).decode().strip()
    if not _SHA.fullmatch(head):
        raise ResolveError("The reviewed checkout has an unsupported commit ID")
    changes, tree = _prepare(repo, patch, head)
    avit_label = avit
    if instance:
        origin = sn.validate_instance_url(instance)
        uri = f"{sn.AVIT_TABLE}.do?sysparm_query=number={avit}"
        avit_label = f"[{avit}]({origin}/nav_to.do?uri={urllib.parse.quote(uri, safe='')})"
    if canonical["scm"] == "github":
        from .avit_github_pr import publish
        return publish(avit, verdict, repo, canonical, patch, head, changes, tree, avit_label)
    from .ado_login import AdoLoginError, service_account_pat
    try:
        pat, _source = service_account_pat(canonical["organization"], profile)
    except AdoLoginError as exc:
        raise ResolveError(str(exc)) from None
    if pat in patch or pat in json.dumps(changes):
        raise ResolveError("The proposed fix contains the service-account credential")
    quote = lambda value: urllib.parse.quote(value, safe="")
    base = f"https://dev.azure.com/{quote(canonical['organization'])}/{quote(canonical['project'])}/_apis/git/repositories/{quote(canonical['name'])}"
    repository = _request(base, pat)
    repo_id = repository.get("id")
    if not isinstance(repo_id, str) or not re.fullmatch(r"[a-fA-F0-9-]{36}", repo_id):
        raise ResolveError("Azure DevOps did not identify the target repository")
    if _ref(base, pat, target_ref) != head:
        raise ResolveError("The target branch changed since review; review its current revision before opening a fix PR")
    fingerprint = hashlib.sha256(f"{target_ref}\n{head}\n{patch}".encode()).hexdigest()[:16]
    source_ref = f"refs/heads/threatlint/{avit.lower()}-{fingerprint}"
    pulls = _request(base, pat, "/pullrequests", params={"searchCriteria.sourceRefName": source_ref,
                     "searchCriteria.targetRefName": target_ref, "searchCriteria.status": "all", "$top": 100}).get("value")
    if not isinstance(pulls, list) or len(pulls) > 1 or any(not isinstance(pull, dict) for pull in pulls):
        raise ResolveError("Azure DevOps did not return an unambiguous fix PR lookup")
    branch_commit = _ref(base, pat, source_ref)
    if branch_commit:
        commit = _request(base, pat, f"/commits/{branch_commit}")
        if commit.get("parents") != [head] or commit.get("treeId") != tree:
            raise ResolveError("The existing fix branch differs from the reviewed proposal; it was not overwritten")
    if pulls:
        pull = pulls[0]
        if not branch_commit or pull.get("sourceRefName") != source_ref or pull.get("targetRefName") != target_ref or (pull.get("repository") or {}).get("id") != repo_id:
            raise ResolveError("The existing fix PR does not match the reviewed repository and branches")
    else:
        if not branch_commit:
            pushed = _request(base, pat, "/pushes", body={"refUpdates": [{"name": source_ref, "oldObjectId": "0" * 40}],
                              "commits": [{"parents": [head], "comment": f"Propose remediation for {avit}", "changes": changes}]})
            commits = pushed.get("commits") or []
            refs = pushed.get("refUpdates") or []
            if (not isinstance(commits, list) or len(commits) != 1 or not isinstance(commits[0], dict)
                    or commits[0].get("treeId") != tree or commits[0].get("parents") != [head]
                    or not isinstance(refs, list) or not any(isinstance(ref, dict) and ref.get("name") == source_ref
                    and ref.get("newObjectId") == commits[0].get("commitId") for ref in refs)):
                raise ResolveError("Azure DevOps did not confirm the proposed fix commit; inspect the fix branch before retrying")
        summary = _summary(verdict.get("title", ""))
        description = (f"{summary}. This draft proposes the source fix from the Threatlint review of {avit_label}.\n\n"
                       f"Reviewed target: `{canonical['branch']}` at `{head}`.\n"
                       f"Changed files: {', '.join('`' + change['item']['path'] + '`' for change in changes)}.\n\n"
                       "Validation: the proposed diff applies cleanly to the reviewed revision. "
                       "Application and regression tests: NOT RUN. Human review and CI validation are required before merge.")
        pull = _request(base, pat, "/pullrequests", body={"sourceRefName": source_ref, "targetRefName": target_ref,
                        "title": f"Fix {avit}: {summary}", "description": description, "isDraft": True})
        if pull.get("isDraft") is not True:
            raise ResolveError("Azure DevOps did not confirm a draft PR; inspect the PR before retrying")
    if pull.get("sourceRefName") != source_ref or pull.get("targetRefName") != target_ref or (pull.get("repository") or {}).get("id") != repo_id:
        raise ResolveError("Azure DevOps returned a PR for unexpected repository or branches")
    number = pull.get("pullRequestId")
    if type(number) is not int or number < 1:
        raise ResolveError("Azure DevOps did not return a valid PR number; inspect the fix branch before retrying")
    return {"status": "existing" if pulls else "created", "url": f"{canonical['web_url']}/pullrequest/{number}",
            "number": number, "branch": source_ref.removeprefix("refs/heads/"), "draft": pull.get("isDraft") is True,
            "reason": "Existing fix PR reused" if pulls else "Draft PR created with the proposed fix"}
