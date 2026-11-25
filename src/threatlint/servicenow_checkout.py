"""Repository targeting and bounded full/sparse checkout strategies for AVIT reviews."""

from __future__ import annotations

import base64
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

from threatlint import tls

_ADO_ORG = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,49}")
_ADO_NAME = re.compile(r"[^/\\:*?\"<>|#%&\x00-\x1f]{1,64}")
_GH_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}")
# git check-ref-format restrictions; commands run without a shell.
_BRANCH = re.compile(r"(?!-)(?!.*\.\.)(?!.*//)(?!.*@\{)(?!.*\.lock$)[^\x00-\x20\x7f~^:?*\[\\]{1,250}(?<![./])")
_OWNERSHIP_FILE = "threatlint-checkout-owner.json"


def mark_checkout(directory):
    """Record host ownership inside Git metadata, which a remote repository cannot supply."""
    root = os.path.abspath(directory)
    git = os.path.join(root, ".git")
    if os.path.islink(root) or os.path.islink(git) or not os.path.isdir(git):
        return False
    marker = os.path.join(git, _OWNERSHIP_FILE)
    descriptor = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump({"schemaVersion": 1, "path": os.path.realpath(root)}, handle)
        handle.flush()
        os.fsync(handle.fileno())
    return True


def remove_owned_checkout(directory):
    """Never infer ownership from .git alone or fail completed triage because cleanup failed."""
    if not directory or os.path.islink(directory):
        return False
    root = os.path.abspath(directory)
    git = os.path.join(root, ".git")
    marker = os.path.join(git, _OWNERSHIP_FILE)
    try:
        if os.path.islink(git) or os.path.islink(marker) or not os.path.isdir(git):
            return False
        with open(marker, encoding="utf-8") as handle:
            claim = json.load(handle)
        if claim != {"schemaVersion": 1, "path": os.path.realpath(root)}:
            return False
        remove_checkout(root)
        return True
    except FileNotFoundError:
        return False
    except (ValueError, TypeError):
        return False
    except OSError:
        print(f"  ! Checkout cleanup could not finish: {root}; the review result is preserved. Inspect the checkout before removing it manually.", file=sys.stderr)
        return False


def git_prefix(git):
    return [git, "-c", "core.longpaths=true"] if sys.platform == "win32" else [git]


def remove_checkout(directory):
    """Delete app-owned partial checkouts, including read-only .git objects on Windows."""
    def writable(function, value, _error):
        if os.path.islink(value):
            os.unlink(value)
            return
        os.chmod(value, stat.S_IREAD | stat.S_IWRITE | stat.S_IEXEC)
        function(value)
    try:
        shutil.rmtree(directory, onerror=writable)
    except FileNotFoundError:
        pass


def source_destination(directory, source_path):
    """An Items API path must stay inside the copy and must not address Windows devices."""
    parts = source_path.lstrip('/').split('/')
    if not parts or any(part in ('', '.', '..') or '\x00' in part for part in parts):
        raise ValueError('The source provider returned an invalid file path')
    if sys.platform == 'win32' and any(re.search(r'[\\:*?"<>|]', part) or part.endswith((' ', '.'))
        or re.fullmatch(r'(?i:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?', part) for part in parts):
        raise ValueError('The source folder contains a Windows-incompatible file name; use Linux/WSL to inspect it')
    result = os.path.abspath(os.path.join(directory, *parts))
    if os.path.commonpath([os.path.abspath(directory), result]) != os.path.abspath(directory):
        raise ValueError('The source provider returned a path outside the checkout')
    return result


def checkout_failure(stderr, target):
    """Classify Git's whole diagnostic; its final line often just says 'git restore'."""
    text = stderr or ""
    if re.search(r"authentication failed|could not read.*username|HTTP.*(?:401|403)|access denied|TF401019", text, re.I):
        return ("Repository authentication or read access was rejected. Check the configured Azure DevOps PAT and Code: Read permission."
                if target["scm"] == "azure-devops" else "Repository authentication or read access was rejected. Check the GitHub App installation and Contents: Read permission.")
    if re.search(r"filename too long|invalid path|unable to (?:create|checkout)|cannot create|checkout failed|working tree", text, re.I):
        return "Git downloaded the repository but could not materialize its working tree. Check long paths, reserved file names, case collisions, file permissions, and antivirus locks. Use a shorter checkout location or Linux/WSL for file names incompatible with Windows."
    if re.search(r"certificate|SSL peer|unable to get.*issuer", text, re.I):
        return "Git could not verify the source server certificate. Configure the trusted Git certificate chain and retry."
    if re.search(r"could not resolve|failed to connect|connection.*(?:reset|refused)|HTTP/2.*(?:stream|closed)|RPC failed", text, re.I):
        return "Git could not complete the repository transfer. Check network/proxy access and retry."
    return "Git could not clone the selected repository and branch. Check branch availability, local disk space, Git configuration, and filesystem permissions."


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
    from threatlint.github_repository import token as github_token
    token, source = github_token()
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
    if tool in ("github", "gh", "github enterprise", "github enterprise cloud", "ghec", "github enterprise server", "ghes"):
        owner = org or project
        if not (_GH_NAME.fullmatch(owner) and _GH_NAME.fullmatch(repo)):
            raise error_type("The AVIT needs a valid Organization Name and Repository for GitHub")
        from threatlint.github_repository import GitHubAppError, endpoints
        try:
            origin = endpoints()["web_url"]
        except GitHubAppError as exc:
            raise error_type(str(exc)) from None
        return {"scm": "github", "clone_url": f"{origin}/{owner}/{repo}.git", "web_url": f"{origin}/{owner}/{repo}",
                "branch": branch, "name": repo, "organization": owner, "project": ""}
    raise error_type(f"Unsupported or missing SCM Tool on the AVIT: {context.get('scm_tool') or 'not set'} (ADO and GitHub are supported)")


def sparse_clone(git, target, directory, file_path, env, *, error_type):
    """Blobless depth-1 clone of only the flagged file's directory."""
    branch = ["--branch", target["branch"]] if target["branch"] else []
    prefix = git_prefix(git)
    steps = [[*prefix, "clone", "--filter=blob:none", "--depth", "1", "--single-branch", "--no-tags", "--no-checkout", *branch, "--", target["clone_url"], directory],
             [*prefix, "-C", directory, "sparse-checkout", "set", "--no-cone", f"/{os.path.dirname(file_path.lstrip('/'))}/" if os.path.dirname(file_path) else f"/{file_path.lstrip('/')}"],
             [*prefix, "-C", directory, "read-tree", "-mu", "HEAD"]]
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
            destination = source_destination(directory, path)
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
    command = [*git_prefix(git), "clone", "--depth", "50", "--single-branch", "--no-tags", *(["--branch", target["branch"]] if target["branch"] else []),
               "--", target["clone_url"], directory]
    env = {**tls.tool_env(), "GIT_LFS_SKIP_SMUDGE": "1", **auth_env(target["scm"], target.get("organization", ""))}
    def narrow_fallback(reason):
        try:
            remove_checkout(directory)
        except OSError:
            raise error_type("The partial checkout is locked or cannot be removed. Close applications using it, then retry; changing the PAT will not fix a local file lock.") from None
        if not file_path:
            raise error_type(reason + " The AVIT names no source file for a narrow checkout.") from None
        if target["scm"] == "azure-devops":
            print("  ! Full checkout unavailable; downloading the flagged source folder through the Azure DevOps API")
            folder_download(target, directory, file_path)
            return None
        print("  ! Full checkout unavailable; retrying a sparse checkout of the flagged source folder")
        return sparse_clone(git, target, directory, file_path, env)
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False, env=env)
    except subprocess.TimeoutExpired:
        result = narrow_fallback(f"Cloning the repository exceeded {timeout} s.")
        if result is None:
            return directory
    else:
        if result.returncode != 0 and sys.platform == "win32" and file_path and re.search(r"filename too long|invalid path|unable to (?:create|checkout)|cannot create|checkout failed|working tree", result.stderr or "", re.I):
            result = narrow_fallback(checkout_failure(result.stderr, target))
            if result is None:
                return directory
    if result.returncode != 0:
        raise error_type(checkout_failure(result.stderr, target))
    mark_checkout(directory)
    return directory
