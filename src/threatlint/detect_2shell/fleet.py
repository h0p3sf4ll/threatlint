"""Scan many repositories and branches across every connected SCM, without cloning.

For each target the scanner lists the branch's file tree through the SCM API, then
downloads only package.json files and lockfiles. Nothing is written to any SCM.

Credentials come from ``THREATLINT_2SHELL_CREDENTIALS`` (JSON, set by the Workbench
for the connections a user picked) or, when absent, from ThreatLint's saved logins:
the GitHub App / GH_TOKEN / ``gh auth token`` and saved Azure DevOps PATs.
Tokens are only ever sent to the configured API host and are never logged.
"""
from __future__ import annotations

import base64
import fnmatch
import json
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable, Iterator

from .lockfiles import MAX_FILE_BYTES, excluded, is_lockfile, is_manifest
from .report import document, target_result
from .scanner import scan_source

CREDENTIALS_ENV = "THREATLINT_2SHELL_CREDENTIALS"
PROVIDERS = ("github", "azure-devops")
DEFAULT_MAX_REPOSITORIES = 500
HARD_MAX_REPOSITORIES = 10_000
DEFAULT_MAX_BRANCHES = 50
HARD_MAX_BRANCHES = 500
MAX_WORKERS = 16
HTTP_TIMEOUT_S = 30
_NAME = re.compile(r"^[A-Za-z0-9._/*?\[\]-][A-Za-z0-9 ._/*?\[\]-]{0,199}$")
_SAFE_ORG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")


class FleetError(Exception):
    pass


class HttpError(FleetError):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


# ─── Configuration ──────────────────────────────────────────────────────────


@dataclass
class Connection:
    id: str
    provider: str
    token: str = field(repr=False)
    organization: str = ""
    api_base: str = ""


@dataclass
class Selection:
    connection: str
    repositories: str | list[str] = "all"
    branches: str | list[str] = "default"


def _validate_patterns(value, label: str, limit: int):
    if isinstance(value, str):
        return value
    if not isinstance(value, list) or not value or len(value) > limit:
        raise FleetError(f"{label} must be \"all\"/\"default\" or a list of 1-{limit} names")
    for item in value:
        if not isinstance(item, str) or not _NAME.match(item) or ".." in item:
            raise FleetError(f"Invalid {label[:-1]} name: {str(item)[:60]!r}")
    return value


def load_targets(data: dict) -> tuple[list[Selection], int, int]:
    if not isinstance(data, dict):
        raise FleetError("Targets must be a JSON object")
    raw = data.get("connections") or [{"connection": "*"}]
    if not isinstance(raw, list) or len(raw) > 32:
        raise FleetError("connections must be a list of at most 32 selections")
    selections = []
    for item in raw:
        if not isinstance(item, dict):
            raise FleetError("Each connection selection must be an object")
        repos = _validate_patterns(item.get("repositories", "all"), "repositories", 1000)
        branches = _validate_patterns(item.get("branches", "default"), "branches", 20)
        if isinstance(repos, str) and repos != "all":
            raise FleetError('repositories must be "all" or a list')
        if isinstance(branches, str) and branches not in ("default", "all"):
            raise FleetError('branches must be "default", "all" or a list')
        selections.append(Selection(str(item.get("connection") or "*"), repos, branches))
    try:
        max_repos = int(data.get("maxRepositories", DEFAULT_MAX_REPOSITORIES))
        max_branches = int(data.get("maxBranchesPerRepository", DEFAULT_MAX_BRANCHES))
    except (TypeError, ValueError):
        raise FleetError("maxRepositories and maxBranchesPerRepository must be integers") from None
    if not 1 <= max_repos <= HARD_MAX_REPOSITORIES or not 1 <= max_branches <= HARD_MAX_BRANCHES:
        raise FleetError(f"maxRepositories must be 1-{HARD_MAX_REPOSITORIES}; maxBranchesPerRepository 1-{HARD_MAX_BRANCHES}")
    return selections, max_repos, max_branches


def _https_base(value: str, default: str) -> str:
    base = (value or default).rstrip("/")
    parsed = urllib.parse.urlsplit(base)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.query or parsed.fragment:
        raise FleetError("API base must be an https:// URL without credentials or query")
    return base


def load_connections(environ=os.environ) -> list[Connection]:
    raw = environ.get(CREDENTIALS_ENV, "")
    if raw:
        try:
            items = json.loads(raw).get("connections", [])
        except (ValueError, AttributeError):
            raise FleetError(f"{CREDENTIALS_ENV} is not valid JSON") from None
        connections = []
        for index, item in enumerate(items):
            provider = item.get("provider")
            if provider not in PROVIDERS or not item.get("token"):
                raise FleetError(f"Credential {index + 1} needs a provider ({', '.join(PROVIDERS)}) and a token")
            org = str(item.get("organization") or "")
            if provider == "azure-devops" and not _SAFE_ORG.match(org):
                raise FleetError(f"Credential {index + 1}: Azure DevOps needs a valid organization")
            default = "https://api.github.com" if provider == "github" else f"https://dev.azure.com/{org}"
            connections.append(Connection(str(item.get("id") or f"{provider}-{index + 1}"), provider, item["token"], org,
                                          _https_base(item.get("apiBase", ""), default)))
        return connections
    return _saved_connections()


def _saved_connections() -> list[Connection]:
    connections: list[Connection] = []
    try:
        from threatlint import github_app  # noqa: PLC0415
        token, _source = github_app.github_token(warn=False)
        if token:
            api = os.environ.get("THREATLINT_GITHUB_API_URL") or "https://api.github.com"
            connections.append(Connection("github", "github", token, "", _https_base(api, api)))
    except Exception:  # noqa: BLE001 - a broken GitHub login must not hide Azure DevOps
        pass
    try:
        from threatlint import ado_login  # noqa: PLC0415
        orgs = list(ado_login.organizations())
        # CI: THREATLINT_ADO_ORG names the organization for an environment PAT (THREATLINT_ADO_PAT etc.).
        env_org = (os.environ.get("THREATLINT_ADO_ORG") or os.environ.get("AZURE_DEVOPS_ORG") or "").strip()
        if env_org and env_org.lower() not in {o.lower() for o in orgs}:
            orgs.append(env_org)
        for org in orgs:
            pat, _source = ado_login.load(org)
            if pat and _SAFE_ORG.match(org):
                connections.append(Connection(f"azure-devops:{org}", "azure-devops", pat, org, f"https://dev.azure.com/{org}"))
    except Exception:  # noqa: BLE001
        pass
    return connections


# ─── HTTP ───────────────────────────────────────────────────────────────────


def _opener():
    try:
        from threatlint.tls import ssl_context  # noqa: PLC0415
        return urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl_context()))
    except Exception:  # noqa: BLE001
        return urllib.request.build_opener()


class Http:
    def __init__(self, base: str, headers: dict, opener=None, sleep=time.sleep):
        self.base, self.headers, self.sleep = base, headers, sleep
        self.opener = opener or _opener()
        self.host = urllib.parse.urlsplit(base).hostname

    def get(self, url: str, *, accept: str = "", raw: bool = False, limit: int = 20_000_000):
        url = url if url.startswith("https://") else self.base + url
        if urllib.parse.urlsplit(url).hostname != self.host:
            raise FleetError("Refusing to send credentials to a different host")
        headers = dict(self.headers, **({"Accept": accept} if accept else {}))
        for attempt in range(4):
            request = urllib.request.Request(url, headers=headers)
            try:
                with self.opener.open(request, timeout=HTTP_TIMEOUT_S) as response:
                    body = response.read(limit + 1)
                    if len(body) > limit:
                        raise FleetError("Response too large")
                    meta = {"link": response.headers.get("Link", ""),
                            "continuation": response.headers.get("x-ms-continuationtoken", ""),
                            "status": getattr(response, "status", 200)}
                    if raw:
                        return body.decode("utf-8", errors="replace"), meta
                    if meta["status"] == 203 or not body.lstrip()[:1] in (b"{", b"["):
                        raise HttpError(401, "The SCM returned a sign-in page; the credential was not accepted")
                    return json.loads(body), meta
            except urllib.error.HTTPError as exc:
                retry = exc.code in (429, 500, 502, 503, 504) or (
                    exc.code == 403 and exc.headers.get("x-ratelimit-remaining") == "0")
                if retry and attempt < 3:
                    wait = exc.headers.get("Retry-After")
                    self.sleep(min(float(wait), 60.0) if wait and wait.isdigit() else 2 ** attempt)
                    continue
                raise HttpError(exc.code, _http_message(exc.code)) from None
            except urllib.error.URLError as exc:
                if attempt < 3:
                    self.sleep(2 ** attempt)
                    continue
                raise FleetError(f"Could not reach {self.host}: {exc.reason}") from None
        raise FleetError("Request failed after retries")


def _http_message(code: int) -> str:
    return {401: "credential rejected (HTTP 401)", 403: "access denied or rate limited (HTTP 403)",
            404: "not found or no access (HTTP 404)", 409: "repository is empty (HTTP 409)"}.get(code, f"HTTP {code}")


# ─── Providers ──────────────────────────────────────────────────────────────


@dataclass
class Repo:
    provider: str
    organization: str
    project: str
    name: str  # "owner/name" for GitHub, "project/repo" for Azure DevOps
    id: str
    default_branch: str


@dataclass
class Target:
    connection: Connection
    repo: Repo
    branch: str
    commit: str


class RemoteSource:
    def __init__(self, entries: dict[str, int | None], reader: Callable[[str], str], truncated: bool):
        self.entries, self.reader, self.truncated = entries, reader, truncated

    def paths(self) -> list[str]:
        return list(self.entries)

    def size(self, path: str) -> int | None:
        return self.entries.get(path)

    def read(self, path: str) -> str:
        if not (is_manifest(path) or is_lockfile(path)):
            raise FleetError("Only manifests and lockfiles are downloaded")
        return self.reader(path)


class GitHub:
    def __init__(self, connection: Connection, opener=None, sleep=time.sleep):
        self.connection = connection
        self.http = Http(connection.api_base, {
            "Authorization": f"Bearer {connection.token}", "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "threatlint-detect-2shell"}, opener, sleep)

    def _pages(self, url: str, key: str | None = None) -> Iterator[dict]:
        while url:
            data, meta = self.http.get(url)
            yield from (data.get(key, []) if key else data)
            match = re.search(r'<([^>]+)>;\s*rel="next"', meta["link"])
            url = match.group(1) if match else ""

    def repositories(self) -> Iterator[Repo]:
        try:
            items = self._pages("/installation/repositories?per_page=100", "repositories")
            first = next(items, None)
            stream = ([first] if first else []) + list(items)
        except HttpError as exc:
            if exc.status not in (401, 403, 404):
                raise
            stream = self._pages("/user/repos?per_page=100&affiliation=owner,collaborator,organization_member")
        for repo in stream:
            if repo.get("archived") or repo.get("disabled"):
                continue
            yield Repo("github", repo["owner"]["login"], "", repo["full_name"], repo["full_name"],
                       repo.get("default_branch") or "main")

    def branches(self, repo: Repo) -> Iterator[tuple[str, str]]:
        for branch in self._pages(f"/repos/{_q(repo.name, '/')}/branches?per_page=100"):
            yield branch["name"], branch["commit"]["sha"]

    def commit(self, repo: Repo, branch: str) -> str:
        data, _ = self.http.get(f"/repos/{_q(repo.name, '/')}/commits/{_q(branch)}", accept="application/vnd.github.sha", raw=True)
        return data.strip()

    def source(self, target: Target) -> RemoteSource:
        repo = _q(target.repo.name, "/")
        data, _ = self.http.get(f"/repos/{repo}/git/trees/{target.commit}?recursive=1")
        entries = {item["path"]: item.get("size") for item in data.get("tree", []) if item.get("type") == "blob"}

        def read(path: str) -> str:
            text, _ = self.http.get(f"/repos/{repo}/contents/{_q(path, '/')}?ref={target.commit}",
                                    accept="application/vnd.github.raw", raw=True, limit=MAX_FILE_BYTES)
            return text
        return RemoteSource(entries, read, bool(data.get("truncated")))


class AzureDevOps:
    API = "api-version=7.1"

    def __init__(self, connection: Connection, opener=None, sleep=time.sleep):
        self.connection = connection
        basic = base64.b64encode(f":{connection.token}".encode()).decode()
        self.http = Http(connection.api_base, {"Authorization": f"Basic {basic}", "Accept": "application/json",
                                               "User-Agent": "threatlint-detect-2shell"}, opener, sleep)

    def repositories(self) -> Iterator[Repo]:
        data, _ = self.http.get(f"/_apis/git/repositories?{self.API}")
        for repo in data.get("value", []):
            if repo.get("isDisabled"):
                continue
            project = repo.get("project", {}).get("name", "")
            branch = (repo.get("defaultBranch") or "").removeprefix("refs/heads/")
            yield Repo("azure-devops", self.connection.organization, project, f"{project}/{repo['name']}", repo["id"],
                       branch)

    def _repo_url(self, repo: Repo) -> str:
        return f"/{_q(repo.project)}/_apis/git/repositories/{_q(repo.id)}"

    def branches(self, repo: Repo) -> Iterator[tuple[str, str]]:
        token = ""
        while True:
            suffix = f"&continuationToken={_q(token)}" if token else ""
            data, meta = self.http.get(f"{self._repo_url(repo)}/refs?filter=heads/&$top=1000&{self.API}{suffix}")
            for ref in data.get("value", []):
                yield ref["name"].removeprefix("refs/heads/"), ref["objectId"]
            token = meta["continuation"]
            if not token:
                return

    def commit(self, repo: Repo, branch: str) -> str:
        data, _ = self.http.get(f"{self._repo_url(repo)}/refs?filter=heads/{_q(branch, '/')}&{self.API}")
        for ref in data.get("value", []):
            if ref["name"] == f"refs/heads/{branch}":
                return ref["objectId"]
        raise HttpError(404, f"branch {branch} not found")

    def source(self, target: Target) -> RemoteSource:
        base = self._repo_url(target.repo)
        version = f"versionDescriptor.version={target.commit}&versionDescriptor.versionType=commit"
        data, _ = self.http.get(f"{base}/items?recursionLevel=Full&{version}&{self.API}")
        entries = {item["path"].lstrip("/"): item.get("size") for item in data.get("value", [])
                   if item.get("gitObjectType") == "blob"}

        def read(path: str) -> str:
            text, _ = self.http.get(f"{base}/items?path={_q('/' + path, '/')}&{version}&download=false&{self.API}",
                                    accept="text/plain", raw=True, limit=MAX_FILE_BYTES)
            return text
        return RemoteSource(entries, read, False)


def _q(value: str, safe: str = "") -> str:
    return urllib.parse.quote(value, safe=safe)


def client(connection: Connection, opener=None, sleep=time.sleep):
    return (GitHub if connection.provider == "github" else AzureDevOps)(connection, opener, sleep)


# ─── Planning and execution ─────────────────────────────────────────────────


def _matches(name: str, patterns) -> bool:
    lower = name.lower()
    return any(fnmatch.fnmatchcase(lower, p.lower()) or lower.endswith("/" + p.lower()) for p in patterns)


def _selected_connections(selection: Selection, connections: list[Connection]) -> list[Connection]:
    if selection.connection in ("*", "all"):
        return connections
    found = [c for c in connections if selection.connection in (c.id, c.provider)]
    if not found:
        raise FleetError(f"No credential is available for connection {selection.connection!r}")
    return found


def plan(selections, connections, max_repos, max_branches, *, clients=None, notes=None) -> list[Target]:
    notes = notes if notes is not None else []
    clients = clients or {}
    targets: list[Target] = []
    seen = set()
    repo_count = 0
    for selection in selections:
        for connection in _selected_connections(selection, connections):
            api = clients.get(connection.id) or client(connection)
            clients[connection.id] = api
            for repo in api.repositories():
                if selection.repositories != "all" and not _matches(repo.name, selection.repositories):
                    continue
                if repo_count >= max_repos:
                    notes.append(f"Stopped at {max_repos} repositories (maxRepositories).")
                    return targets
                repo_count += 1
                try:
                    if selection.branches == "default":
                        if not repo.default_branch:
                            notes.append(f"{repo.name}: no default branch (empty repository).")
                            continue
                        branches = [(repo.default_branch, "")]
                    else:
                        listed = list(api.branches(repo))
                        if selection.branches != "all":
                            listed = [b for b in listed if _matches(b[0], selection.branches)]
                        if len(listed) > max_branches:
                            notes.append(f"{repo.name}: scanned {max_branches} of {len(listed)} branches.")
                            listed = sorted(listed, key=lambda b: b[0] != repo.default_branch)[:max_branches]
                        branches = listed
                except FleetError as exc:
                    notes.append(f"{repo.name}: could not list branches ({exc}).")
                    continue
                for branch, commit in branches:
                    key = (connection.id, repo.id, branch)
                    if key not in seen:
                        seen.add(key)
                        targets.append(Target(connection, repo, branch, commit))
    return targets


def scan_target(target: Target, api) -> dict:
    meta = {"provider": target.repo.provider, "organization": target.repo.organization, "project": target.repo.project,
            "repository": target.repo.name, "branch": target.branch}
    try:
        if not target.commit:
            target.commit = api.commit(target.repo, target.branch)
        source = api.source(target)
        scan = scan_source(source)
        if source.truncated:
            scan.coverage.append("The SCM truncated the file tree; very large repositories may be partly covered.")
        return target_result(scan, commit=target.commit, **meta)
    except FleetError as exc:
        return target_result(None, commit=target.commit, error=str(exc), **meta)
    except Exception as exc:  # noqa: BLE001 - one bad repository must not stop the fleet
        return target_result(None, commit=target.commit, error=f"unexpected {type(exc).__name__}", **meta)


def run_fleet(targets_data: dict, *, workers: int = 4, progress: Callable[[dict], None] | None = None,
              environ=os.environ, clients=None) -> dict:
    selections, max_repos, max_branches = load_targets(targets_data)
    connections = load_connections(environ)
    if not connections:
        raise FleetError("No SCM credentials are available. Connect a source in ThreatLint, run `threatlint github "
                         "login` or `threatlint ado login`, or set GH_TOKEN.")
    notes: list[str] = []
    clients = clients if clients is not None else {}
    targets = plan(selections, connections, max_repos, max_branches, clients=clients, notes=notes)
    emit = progress or (lambda _event: None)
    emit({"event": "plan", "total": len(targets)})
    results: list[dict | None] = [None] * len(targets)
    lock = threading.Lock()
    done = 0

    def work(index: int):
        nonlocal done
        target = targets[index]
        result = scan_target(target, clients[target.connection.id])
        results[index] = result
        with lock:
            done += 1
            emit({"event": "target", "index": done, "total": len(targets), "provider": result["provider"],
                  "repository": result["repository"], "branch": result["branch"], "status": result["status"]})

    with ThreadPoolExecutor(max_workers=max(1, min(int(workers), MAX_WORKERS))) as pool:
        list(pool.map(work, range(len(targets))))
    providers = sorted({c.provider for c in connections})
    doc = document([r for r in results if r], scope=f"{len(targets)} target(s) across {', '.join(providers)}")
    doc["notes"] = notes
    emit({"event": "done"})
    return doc


def stderr_progress(event: dict) -> None:
    print(json.dumps(event), file=sys.stderr, flush=True)
