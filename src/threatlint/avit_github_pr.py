"""Publish a validated AVIT proposal through GitHub Cloud or Enterprise REST APIs."""

from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.parse
import urllib.request

from . import github_repository, tls
from .avit_pr import _AUTOMATION, _MAX_REVIEWERS, _NoRedirect, _SHA, _git, _summary, notice
from .avit_report import ResolveError
from .github_app import GitHubAppError


def _request(base: str, token: str, path: str = "", *, params=None, body=None, missing_ok=False):
    query = "?" + urllib.parse.urlencode(params) if params else ""
    request = urllib.request.Request(base + path + query,
                                    data=json.dumps(body).encode() if body is not None else None,
                                    headers={"Authorization": f"Bearer {token}",
                                             "Accept": "application/vnd.github+json",
                                             "Content-Type": "application/json",
                                             "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "threatlint"})
    opener = urllib.request.build_opener(_NoRedirect(), urllib.request.HTTPSHandler(context=tls.ssl_context()))
    try:
        with opener.open(request, timeout=45) as response:
            data = response.read(2 * 1024 * 1024 + 1)
        if len(data) > 2 * 1024 * 1024:
            raise ResolveError("GitHub returned an oversized response")
        result = json.loads(data)
    except urllib.error.HTTPError as exc:
        if missing_ok and body is None and exc.code == 404:
            return None
        raise ResolveError(f"GitHub PR operation failed (HTTP {exc.code}); check repository Contents and Pull requests write permissions") from None
    except (urllib.error.URLError, TimeoutError, ValueError):
        raise ResolveError("GitHub PR operation failed; check connectivity and the configured GitHub account") from None
    if not isinstance(result, (dict, list)):
        raise ResolveError("GitHub returned an unreadable PR response")
    return result


def _sha(value):
    return isinstance(value, str) and _SHA.fullmatch(value)


def _ref(base, token, branch, *, missing_ok=False):
    result = _request(base, token, "/git/ref/heads/" + urllib.parse.quote(branch, safe=""), missing_ok=missing_ok)
    if result is None and missing_ok:
        return ""
    obj = result.get("object") if isinstance(result, dict) else None
    if (not isinstance(obj, dict) or obj.get("type") != "commit" or not _sha(obj.get("sha"))
            or result.get("ref") != "refs/heads/" + branch):
        raise ResolveError("GitHub returned an invalid branch revision")
    return obj["sha"]


def _commit_matches(commit, head, tree):
    return (isinstance(commit, dict) and isinstance(commit.get("parents"), list)
            and len(commit["parents"]) == 1 and isinstance(commit["parents"][0], dict)
            and commit["parents"][0].get("sha") == head and isinstance(commit.get("tree"), dict)
            and commit["tree"].get("sha") == tree)


def _pull_matches(pull, repo_id, source, branch, revision):
    if not isinstance(pull, dict):
        return False
    for key, ref in (("head", source), ("base", branch)):
        side = pull.get(key)
        if (not isinstance(side, dict) or side.get("ref") != ref or not isinstance(side.get("repo"), dict)
                or side["repo"].get("id") != repo_id):
            return False
    return pull["head"].get("sha") == revision


def _graphql_url(api_url: str) -> str:
    return api_url.removesuffix("/v3") + "/graphql" if api_url.endswith("/api/v3") else api_url + "/graphql"


def _mark_ready(api_url: str, token: str, pull: dict) -> dict:
    """Publish an earlier Threatlint draft; REST cannot change draft state, GraphQL can."""
    node = pull.get("node_id")
    if not isinstance(node, str) or not node:
        raise ResolveError("GitHub did not identify the existing draft fix PR; publish it manually")
    result = _request(_graphql_url(api_url), token, body={
        "query": "mutation($id: ID!) { markPullRequestReadyForReview(input: {pullRequestId: $id}) { pullRequest { isDraft } } }",
        "variables": {"id": node}})
    ready = (((result or {}).get("data") or {}).get("markPullRequestReadyForReview") or {}).get("pullRequest") or {}
    if not isinstance(result, dict) or result.get("errors") or ready.get("isDraft") is not False:
        raise ResolveError("GitHub did not publish the existing draft fix PR; publish it manually")
    return {**pull, "draft": False}


def _reviewers(base: str, token: str, number: int, head: str, changes: list[dict], author: str) -> dict:
    """Request review from the people who most recently changed the files. Never fails the PR."""
    logins = []
    try:
        for change in changes:
            rows = _request(base, token, "/commits", params={"sha": head, "path": change["item"]["path"].removeprefix("/"), "per_page": 30})
            for row in rows if isinstance(rows, list) else []:
                user = row.get("author") if isinstance(row, dict) else None
                login = user.get("login") if isinstance(user, dict) and user.get("type") == "User" else None
                if (isinstance(login, str) and login and not _AUTOMATION.search(login)
                        and login.casefold() != author.casefold() and login.casefold() not in map(str.casefold, logins)):
                    logins.append(login)
        logins = logins[:_MAX_REVIEWERS]
        if logins:
            _request(base, token, f"/pulls/{number}/requested_reviewers", body={"reviewers": logins})
    except ResolveError:
        return {"reviewers": [], "unresolved_reviewers": logins}
    return {"reviewers": logins, "unresolved_reviewers": []}


def publish(avit, verdict, repo, canonical, patch, head, changes, tree, avit_label):
    """Create only a new proposal branch; reuse matching proposals without updating refs."""
    try:
        endpoints = github_repository.endpoints()
        token, _source = github_repository.token()
    except GitHubAppError as exc:
        raise ResolveError(str(exc)) from None
    if not token:
        raise ResolveError("No GitHub credential is configured for the repository host")
    if token in patch or token in json.dumps(changes):
        raise ResolveError("The proposed fix contains the GitHub credential")
    owner, name, branch = canonical["organization"], canonical["name"], canonical["branch"]
    quote = lambda value: urllib.parse.quote(value, safe="")
    base = f"{endpoints['api_url']}/repos/{quote(owner)}/{quote(name)}"
    repository = _request(base, token)
    repo_id = repository.get("id") if isinstance(repository, dict) else None
    if (type(repo_id) is not int or repo_id <= 0
            or str(repository.get("full_name", "")).casefold() != f"{owner}/{name}".casefold()):
        raise ResolveError("GitHub did not identify the target repository")
    if _ref(base, token, branch) != head:
        raise ResolveError("The target branch changed since review; review its current revision before opening a fix PR")
    fingerprint = hashlib.sha256(f"refs/heads/{branch}\n{head}\n{patch}".encode()).hexdigest()[:16]
    source = f"threatlint/{avit.lower()}-{fingerprint}"
    pulls = _request(base, token, "/pulls", params={"state": "all", "head": f"{owner}:{source}", "base": branch, "per_page": 100})
    if not isinstance(pulls, list) or len(pulls) > 1 or any(not isinstance(pull, dict) for pull in pulls):
        raise ResolveError("GitHub did not return an unambiguous fix PR lookup")
    revision = _ref(base, token, source, missing_ok=True)
    if revision:
        commit = _request(base, token, f"/git/commits/{revision}")
        if not _commit_matches(commit, head, tree):
            raise ResolveError("The existing fix branch differs from the reviewed proposal; it was not overwritten")
    if pulls:
        pull = pulls[0]
        if not revision or not _pull_matches(pull, repo_id, source, branch, revision):
            raise ResolveError("The existing fix PR does not match the reviewed repository and branches")
    else:
        if not revision:
            entries = []
            for change in changes:
                path = change["item"]["path"].removeprefix("/")
                old = _git(repo, ["ls-tree", head, "--", path]).decode().split()
                entry = {"path": path, "mode": old[0] if old else "100644", "type": "blob"}
                if change["changeType"] == "delete":
                    entry["sha"] = None
                else:
                    entry["content"] = change["newContent"]["content"]
                entries.append(entry)
            base_tree = _git(repo, ["rev-parse", head + "^{tree}"]).decode().strip()
            created_tree = _request(base, token, "/git/trees", body={"base_tree": base_tree, "tree": entries})
            if not isinstance(created_tree, dict) or created_tree.get("sha") != tree:
                raise ResolveError("GitHub did not confirm the exact proposed fix tree; no branch was created")
            commit = _request(base, token, "/git/commits", body={"message": f"Propose remediation for {avit}", "parents": [head], "tree": tree})
            if not _commit_matches(commit, head, tree) or not _sha(commit.get("sha")):
                raise ResolveError("GitHub did not confirm the proposed fix commit; no branch was created")
            revision = commit["sha"]
            if _ref(base, token, branch) != head:
                raise ResolveError("The target branch changed since review; no fix branch was created")
            created_ref = _request(base, token, "/git/refs", body={"ref": "refs/heads/" + source, "sha": revision})
            obj = created_ref.get("object") if isinstance(created_ref, dict) else None
            if (not isinstance(obj, dict) or obj.get("sha") != revision or obj.get("type") != "commit"
                    or created_ref.get("ref") != "refs/heads/" + source):
                raise ResolveError("GitHub did not confirm the proposed fix branch; inspect it before retrying")
        if _ref(base, token, branch) != head:
            raise ResolveError("The target branch changed since review; the proposal branch was retained without opening a PR")
        summary = _summary(verdict.get("title", ""))
        description = (f"{summary}. This PR proposes the source fix from the Threatlint review of {avit_label}.\n\n"
                       f"Reviewed target: `{branch}` at `{head}`.\n"
                       f"Changed files: {', '.join('`' + change['item']['path'] + '`' for change in changes)}.\n\n"
                       "Validation: the proposed diff applies cleanly to the reviewed revision. "
                       "Application and regression tests: NOT RUN. Human review and CI validation are required before merge.")
        pull = _request(base, token, "/pulls", body={"title": f"Fix {avit}: {summary}", "head": source,
                                                   "base": branch, "body": description, "draft": False})
        if not isinstance(pull, dict) or pull.get("draft") is not False:
            raise ResolveError("GitHub did not confirm a published PR; inspect the PR before retrying")
    if not _pull_matches(pull, repo_id, source, branch, revision):
        raise ResolveError("GitHub did not confirm the reviewed repository and branches on the PR")
    number = pull.get("number")
    if type(number) is not int or number <= 0:
        raise ResolveError("GitHub did not return a valid PR number")
    published = False
    if pulls and pull.get("draft") is True and pull.get("state") == "open":
        # Earlier Threatlint versions opened drafts, which request no review; publish them now.
        pull = _mark_ready(endpoints["api_url"], token, pull)
        published = True
    result = {"status": "existing" if pulls else "created", "url": f"{canonical['web_url']}/pull/{number}",
              "id": number, "draft": pull.get("draft") is True, "branch": source, "reviewers": [], "unresolved_reviewers": []}
    if not pulls or published:
        author = (pull.get("user") or {}).get("login") or ""
        result.update(_reviewers(base, token, number, head, changes, author))
    lead = "PR opened with the proposed fix" if not pulls else "Existing draft fix PR published" if published else "Existing fix PR reused"
    result["reason"] = lead if pulls and not published else f"{lead}; {notice(result)}"
    return result
