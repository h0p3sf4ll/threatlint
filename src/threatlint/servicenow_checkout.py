"""Repository targeting and bounded full/sparse checkout strategies for AVIT reviews."""

from __future__ import annotations

import base64
import json
import os
import re
import shutil
import subprocess
import urllib.error
import urllib.parse
import urllib.request

from threatlint import tls

_ADO_ORG = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,49}")
_ADO_NAME = re.compile(r"[^/\\:*?\"<>|#%&\x00-\x1f]{1,64}")
_GH_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}")
# git check-ref-format restrictions; commands run without a shell.
_BRANCH = re.compile(r"(?!-)(?!.*\.\.)(?!.*//)(?!.*@\{)(?!.*\.lock$)[^\x00-\x20\x7f~^:?*\[\\]{1,250}(?<![./])")


def run_tool(name: str, args: list[str], timeout: int = 60) -> str:
    executable = shutil.which(name)
    if not executable:
        return ""
    try:
        result = subprocess.run([executable, *args], capture_output=True, text=True, timeout=timeout, check=False, env=tls.tool_env())
    except (OSError, subprocess.SubprocessError):
        return ""
    return result.stdout.strip() if result.returncode == 0 else ""


def git_credential(scm: str, organization: str = "", *, run_tool) -> tuple[str, str]:
    """Resolve provider-scoped credentials without putting them into clone URLs."""
    if scm == "azure-devops":
        from threatlint.ado_login import load
        pat, source = load(organization) if organization else load()
        if pat:
            return "Basic " + base64.b64encode(f":{pat}".encode()).decode(), source
        token = run_tool("az", ["account", "get-access-token", "--resource", "499b84ac-1321-427f-aa17-267ca6975798", "--query", "accessToken", "-o", "tsv"])
        if token:
            return f"Bearer {token}", "az login"
        pat, source = load()
        return ("Basic " + base64.b64encode(f":{pat}".encode()).decode(), source) if pat else ("", "")
    from threatlint.github_app import github_token
    token, source = github_token(gh_cli=lambda: run_tool("gh", ["auth", "token"], 30))
    return ("Basic " + base64.b64encode(f"x-access-token:{token}".encode()).decode(), source) if token else ("", "")


def repository_target(context: dict[str, str], *, error_type) -> dict[str, str]:
    tool = context.get("scm_tool", "").strip().lower()
    org, project, repo = context.get("organization", "").strip(), context.get("project", "").strip(), context.get("repository", "").strip()
    branch = re.sub(r"^refs/heads/", "", context.get("branch", "").strip())
    if branch and not _BRANCH.fullmatch(branch):
        raise error_type(f"The AVIT branch is not a valid branch name: {branch[:80]}")
    if tool in ("ado", "azure devops", "azuredevops", "azure repos", "vsts", "tfs"):
        if not (_ADO_ORG.fullmatch(org) and _ADO_NAME.fullmatch(project) and _ADO_NAME.fullmatch(repo)):
            raise error_type("The AVIT needs a valid Organization Name, Project Name, and Repository for Azure DevOps")
        quote = lambda value: urllib.parse.quote(value, safe="")
        url = f"https://dev.azure.com/{quote(org)}/{quote(project)}/_git/{quote(repo)}"
        return {"scm": "azure-devops", "clone_url": url, "web_url": url, "branch": branch, "name": repo, "organization": org, "project": project}
    if tool in ("github", "gh", "github enterprise cloud", "ghec"):
        owner = org or project
        if not (_GH_NAME.fullmatch(owner) and _GH_NAME.fullmatch(repo)):
            raise error_type("The AVIT needs a valid Organization Name and Repository for GitHub")
        return {"scm": "github", "clone_url": f"https://github.com/{owner}/{repo}.git", "web_url": f"https://github.com/{owner}/{repo}",
                "branch": branch, "name": repo, "organization": owner, "project": ""}
    raise error_type(f"Unsupported or missing SCM Tool on the AVIT: {context.get('scm_tool') or 'not set'} (ADO and GitHub are supported)")


def sparse_clone(git, target, directory, file_path, env, *, error_type):
    """Blobless depth-1 clone of only the flagged file's directory."""
    branch = ["--branch", target["branch"]] if target["branch"] else []
    steps = [[git, "clone", "--filter=blob:none", "--depth", "1", "--single-branch", "--no-tags", "--no-checkout", *branch, "--", target["clone_url"], directory],
             [git, "-C", directory, "sparse-checkout", "set", "--no-cone", f"/{os.path.dirname(file_path.lstrip('/'))}/" if os.path.dirname(file_path) else f"/{file_path.lstrip('/')}"],
             [git, "-C", directory, "read-tree", "-mu", "HEAD"]]
    for step in steps:
        try:
            result = subprocess.run(step, capture_output=True, text=True, timeout=1800, check=False, env=env)
        except subprocess.TimeoutExpired:
            shutil.rmtree(directory, ignore_errors=True)
            raise error_type(f"Even a sparse checkout of {target['web_url']} exceeded 30 minutes; the repository is too large to clone from here") from None
        if result.returncode != 0:
            return result
    return result


def ado_folder_download(target, directory, file_path, *, git_credential, error_type):
    """Download one folder through the Items API when a full clone is impractical."""
    header, _source = git_credential("azure-devops", target.get("organization", ""))
    if not header:
        raise error_type("No Azure DevOps credential for the folder download")
    match = re.match(r"https://dev\.azure\.com/([^/]+)/([^/]+)/_git/([^/?#]+)", target["clone_url"])
    if not match:
        raise error_type("Folder download needs an Azure DevOps repository URL")
    org, project, repo = match.groups()
    folder = "/" + os.path.dirname(file_path.lstrip("/"))
    base = f"https://dev.azure.com/{org}/{project}/_apis/git/repositories/{repo}/items"
    version = {"versionDescriptor.version": target["branch"], "versionDescriptor.versionType": "branch"} if target["branch"] else {}

    def get(params: dict, accept: str) -> bytes:
        query = urllib.parse.urlencode({**params, **version, "api-version": "7.1"})
        request = urllib.request.Request(f"{base}?{query}", headers={"Authorization": header, "Accept": accept})
        with urllib.request.urlopen(request, timeout=120, context=tls.ssl_context()) as response:
            return response.read()

    try:
        listing = json.loads(get({"scopePath": folder, "recursionLevel": "OneLevel"}, "application/json")).get("value", [])
        files = [item["path"] for item in listing if not item.get("isFolder") and item.get("path")]
        if len(files) > 400:
            files = [path for path in files if path.lstrip("/") == file_path.lstrip("/")] + files[:399]
        for path in dict.fromkeys(files):
            destination = os.path.join(directory, path.lstrip("/"))
            os.makedirs(os.path.dirname(destination), exist_ok=True)
            with open(destination, "wb") as handle:
                handle.write(get({"path": path, "download": "true"}, "application/octet-stream"))
    except (urllib.error.URLError, ValueError, OSError) as exc:
        shutil.rmtree(directory, ignore_errors=True)
        raise error_type(f"Folder download from {target['web_url']} failed: {exc}") from exc
    if not os.path.exists(os.path.join(directory, file_path.lstrip("/"))):
        shutil.rmtree(directory, ignore_errors=True)
        raise error_type(f"The flagged file {file_path} is not on branch {target['branch'] or '(default)'}")


def checkout_repository(target, directory, file_path="", *, auth_env, sparse_clone,
                        folder_download, timeout, error_type):
    """Try a bounded full clone, then the provider-appropriate narrow fallback."""
    if os.path.exists(directory) and os.listdir(directory):
        raise error_type(f"Checkout directory is not empty: {directory}")
    git = shutil.which("git")
    if not git:
        raise error_type("git is required to check out the AVIT repository")
    command = [git, "clone", "--depth", "50", "--single-branch", "--no-tags", *(["--branch", target["branch"]] if target["branch"] else []),
               "--", target["clone_url"], directory]
    env = {**tls.tool_env(), "GIT_LFS_SKIP_SMUDGE": "1", **auth_env(target["scm"], target.get("organization", ""))}
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False, env=env)
    except subprocess.TimeoutExpired:
        shutil.rmtree(directory, ignore_errors=True)
        if not file_path:
            raise error_type(f"Cloning {target['web_url']} exceeded {timeout} s and the AVIT names no file for a sparse checkout") from None
        if target["scm"] == "azure-devops":
            print(f"  ! Full clone exceeded {timeout} s; downloading only {os.path.dirname(file_path) or file_path} through the Azure DevOps API")
            folder_download(target, directory, file_path)
            return directory
        print(f"  ! Full clone exceeded {timeout} s; retrying as a sparse checkout of {os.path.dirname(file_path) or file_path}")
        result = sparse_clone(git, target, directory, file_path, env)
    if result.returncode != 0:
        reason = (result.stderr.strip().splitlines() or ["git clone failed"])[-1][:300]
        hint = (" Run `threatlint ado login` to save a PAT with Code: Read (or set THREATLINT_ADO_PAT / run `az login`)." if target["scm"] == "azure-devops" else " Run `threatlint github login` (GitHub App), `gh auth login`, or set GH_TOKEN.")
        raise error_type(f"Could not clone {target['web_url']}{' branch ' + target['branch'] if target['branch'] else ''}: {reason}.{hint}")
    return directory
