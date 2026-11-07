"""GitHub fix publishing uses synthetic checkouts and a fake API, never live writes."""

import io
import json
import urllib.error
import urllib.parse

import pytest

from threatlint import avit_github_pr as github_pr, avit_pr as pr, github_repository
from threatlint.avit_report import ResolveError
from test_avit_pr import AVIT, PATCH, SOURCE, git, report


TOKEN = "synthetic-github-installation-token"
TARGET = {"scm": "github", "organization": "contoso", "project": "", "name": "api", "branch": "main"}
REPO_ID = 1234


@pytest.fixture
def checkout(tmp_path, monkeypatch):
    monkeypatch.setenv("THREATLINT_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("THREATLINT_GITHUB_API_URL", "https://api.github.com")
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-b", "main")
    git(repo, "config", "user.name", "Fixture")
    git(repo, "config", "user.email", "fixture@example.test")
    (repo / "app.py").write_bytes(SOURCE.encode("utf-8"))
    git(repo, "add", "app.py")
    git(repo, "commit", "-m", "fixture")
    git(repo, "remote", "add", "origin", "https://github.com/contoso/api.git")
    return repo


class FakeGitHub:
    def __init__(self, repo, patch=PATCH, api_url="https://api.github.com"):
        self.base = api_url + "/repos/contoso/api"
        self.head = git(repo, "rev-parse", "HEAD")
        self.base_tree = git(repo, "rev-parse", "HEAD^{tree}")
        self.tree = pr._prepare(repo, patch, self.head)[1]
        self.remote_head = self.head
        self.commit = "a" * 40
        self.source = ""
        self.pulls = []
        self.calls = []

    def __call__(self, base, token, path="", *, params=None, body=None, missing_ok=False):
        assert base == self.base
        assert token == TOKEN
        self.calls.append((path, params, body))
        if path == "":
            return {"id": REPO_ID, "full_name": "contoso/api"}
        if path.startswith("/git/ref/"):
            ref = "refs/" + urllib.parse.unquote(path.removeprefix("/git/ref/"))
            if ref == "refs/heads/main":
                return {"ref": ref, "object": {"type": "commit", "sha": self.remote_head}}
            if ref == self.source:
                return {"ref": ref, "object": {"type": "commit", "sha": self.commit}}
            assert missing_ok
            return None
        if path == "/pulls" and body is None:
            assert params["state"] == "all"
            assert params["head"].startswith("contoso:threatlint/")
            assert params["base"] == "main"
            return self.pulls
        if path.startswith("/git/commits/"):
            return {"sha": self.commit, "parents": [{"sha": self.head}], "tree": {"sha": self.tree}}
        if path == "/git/trees":
            assert body["base_tree"] == self.base_tree
            assert all(item["type"] == "blob" for item in body["tree"])
            return {"sha": self.tree}
        if path == "/git/commits":
            assert body["parents"] == [self.head]
            assert body["tree"] == self.tree
            return {"sha": self.commit, "parents": [{"sha": self.head}], "tree": {"sha": self.tree}}
        if path == "/git/refs":
            assert body["sha"] == self.commit
            assert body["ref"].startswith("refs/heads/threatlint/")
            assert not self.source, "A proposal branch must never be overwritten"
            self.source = body["ref"]
            return {"ref": self.source, "object": {"type": "commit", "sha": self.commit}}
        if path == "/pulls":
            assert body["draft"] is True
            assert body["head"] == self.source.removeprefix("refs/heads/")
            assert body["base"] == "main"
            assert "NOT RUN" in body["body"]
            assert TOKEN not in body["body"]
            pull = {"number": 42, "draft": True, "state": "open",
                    "head": {"ref": body["head"], "sha": self.commit, "repo": {"id": REPO_ID}},
                    "base": {"ref": "main", "sha": self.head, "repo": {"id": REPO_ID}}}
            self.pulls = [pull]
            return pull
        pytest.fail(f"Unexpected GitHub request: {path}")


@pytest.fixture
def api(checkout, monkeypatch):
    fake = FakeGitHub(checkout)
    monkeypatch.setattr(github_pr, "_request", fake)
    monkeypatch.setattr(github_repository, "token", lambda: (TOKEN, "GitHub App"))
    return fake


@pytest.mark.parametrize("api_url,web_url", [
    ("https://api.github.com", "https://github.com"),
    ("https://git.example.test/api/v3", "https://git.example.test"),
    ("https://api.acme.ghe.com", "https://acme.ghe.com"),
])
def test_cloud_and_enterprise_create_draft_without_touching_checkout(checkout, api, monkeypatch, api_url, web_url):
    monkeypatch.setenv("THREATLINT_GITHUB_API_URL", api_url)
    api.base = api_url + "/repos/contoso/api"
    git(checkout, "remote", "set-url", "origin", web_url + "/contoso/api.git")
    index = (checkout / ".git" / "index").read_bytes()
    objects = sorted(str(p.relative_to(checkout)) for p in (checkout / ".git" / "objects").rglob("*"))
    result = pr.create_fix_pr(AVIT, report(), str(checkout), TARGET, instance="https://test.service-now.com")
    assert result["status"] == "created" and result["draft"] is True
    assert result["url"] == web_url + "/contoso/api/pull/42"
    assert (checkout / "app.py").read_text() == SOURCE
    assert (checkout / ".git" / "index").read_bytes() == index
    assert sorted(str(p.relative_to(checkout)) for p in (checkout / ".git" / "objects").rglob("*")) == objects
    pull = next(body for path, _, body in api.calls if path == "/pulls" and body)
    assert f"[{AVIT}](https://test.service-now.com/nav_to.do?uri=" in pull["body"]


def test_retry_reuses_same_pr_without_republishing(checkout, api):
    first = pr.create_fix_pr(AVIT, report(), str(checkout), TARGET)
    second = pr.create_fix_pr(AVIT, report(), str(checkout), TARGET)
    assert second["status"] == "existing" and second["url"] == first["url"]
    for endpoint in ("/git/trees", "/git/commits", "/git/refs", "/pulls"):
        assert sum(path == endpoint and body is not None for path, _, body in api.calls) == 1


def test_retry_after_branch_creation_creates_missing_pr(checkout, api):
    pr.create_fix_pr(AVIT, report(), str(checkout), TARGET)
    api.pulls = []
    result = pr.create_fix_pr(AVIT, report(), str(checkout), TARGET)
    assert result["status"] == "created"
    assert sum(path == "/git/refs" for path, _, _ in api.calls) == 1


def test_existing_branch_with_different_tree_is_not_overwritten(checkout, api):
    pr.create_fix_pr(AVIT, report(), str(checkout), TARGET)
    api.pulls = []
    api.tree = "b" * 40
    api.calls.clear()
    with pytest.raises(ResolveError, match="not overwritten|differs"):
        pr.create_fix_pr(AVIT, report(), str(checkout), TARGET)
    assert all(body is None for _, _, body in api.calls)


@pytest.mark.parametrize("side,field,value", [
    ("head", "ref", "other"), ("base", "ref", "other"),
    ("head", "repo", {"id": 9876}), ("base", "repo", {"id": 9876}),
    ("head", "sha", "b" * 40),
])
def test_existing_pr_identity_must_match(checkout, api, side, field, value):
    pr.create_fix_pr(AVIT, report(), str(checkout), TARGET)
    api.pulls[0][side][field] = value
    api.calls.clear()
    with pytest.raises(ResolveError, match="match"):
        pr.create_fix_pr(AVIT, report(), str(checkout), TARGET)
    assert all(body is None for _, _, body in api.calls)


def test_moved_target_prevents_remote_writes(checkout, api):
    api.remote_head = "b" * 40
    with pytest.raises(ResolveError, match="changed since review"):
        pr.create_fix_pr(AVIT, report(), str(checkout), TARGET)
    assert all(body is None for _, _, body in api.calls)


def test_origin_host_mismatch_precedes_credential_lookup(checkout, monkeypatch):
    git(checkout, "remote", "set-url", "origin", "https://other.example.test/contoso/api.git")
    monkeypatch.setattr(github_repository, "token", lambda: pytest.fail("No credential lookup for a mismatched origin"))
    with pytest.raises(ResolveError, match="origin"):
        pr.create_fix_pr(AVIT, report(), str(checkout), TARGET)


@pytest.mark.parametrize("draft", [False, None, "true"])
def test_new_pr_requires_draft_acknowledgement(checkout, api, monkeypatch, draft):
    def request(*args, **kwargs):
        result = api(*args, **kwargs)
        if args[2:] == ("/pulls",) and kwargs.get("body"):
            result["draft"] = draft
        return result
    monkeypatch.setattr(github_pr, "_request", request)
    with pytest.raises(ResolveError, match="confirm a draft"):
        pr.create_fix_pr(AVIT, report(), str(checkout), TARGET)


def test_existing_pr_can_be_promoted_to_ready(checkout, api):
    pr.create_fix_pr(AVIT, report(), str(checkout), TARGET)
    api.pulls[0]["draft"] = False
    result = pr.create_fix_pr(AVIT, report(), str(checkout), TARGET)
    assert result["status"] == "existing" and result["draft"] is False


def test_tree_preserves_executable_mode_and_handles_additions_and_deletions(checkout, api, monkeypatch):
    git(checkout, "update-index", "--chmod=+x", "app.py")
    (checkout / "app.py").chmod(0o755)
    (checkout / "old.txt").write_bytes(b"old\n")
    git(checkout, "add", "old.txt")
    git(checkout, "commit", "-m", "fixture files")
    patch = PATCH.replace("100644", "100755") + """diff --git a/new.txt b/new.txt
new file mode 100644
--- /dev/null
+++ b/new.txt
@@ -0,0 +1 @@
+new
diff --git a/old.txt b/old.txt
deleted file mode 100644
--- a/old.txt
+++ /dev/null
@@ -1 +0,0 @@
-old
"""
    fake = FakeGitHub(checkout, patch)
    monkeypatch.setattr(github_pr, "_request", fake)
    result = pr.create_fix_pr(AVIT, report(patch), str(checkout), TARGET)
    assert result["status"] == "created"
    tree_body = next(body for path, _, body in fake.calls if path == "/git/trees")
    entries = {item["path"]: item for item in tree_body["tree"]}
    assert entries["app.py"]["mode"] == "100755"
    assert entries["new.txt"]["mode"] == "100644" and entries["new.txt"]["content"] == "new\n"
    assert entries["old.txt"]["sha"] is None and "content" not in entries["old.txt"]
    assert not (checkout / "new.txt").exists() and (checkout / "old.txt").read_text() == "old\n"


@pytest.mark.parametrize("endpoint,field,bad_value", [
    ("/git/trees", "sha", "b" * 40),
    ("/git/commits", "parents", [{"sha": "b" * 40}]),
    ("/git/commits", "tree", {"sha": "b" * 40}),
])
def test_wrong_created_objects_never_get_a_branch(checkout, api, monkeypatch, endpoint, field, bad_value):
    def request(*args, **kwargs):
        result = api(*args, **kwargs)
        if args[2:] == (endpoint,) and kwargs.get("body"):
            result[field] = bad_value
        return result
    monkeypatch.setattr(github_pr, "_request", request)
    with pytest.raises(ResolveError, match="confirm"):
        pr.create_fix_pr(AVIT, report(), str(checkout), TARGET)
    assert not api.source
    assert all(path != "/git/refs" for path, _, _ in api.calls)


def test_target_moving_during_object_upload_does_not_get_a_proposal_branch(checkout, api, monkeypatch):
    def request(*args, **kwargs):
        result = api(*args, **kwargs)
        if args[2:] == ("/git/commits",) and kwargs.get("body"):
            api.remote_head = "b" * 40
        return result
    monkeypatch.setattr(github_pr, "_request", request)
    with pytest.raises(ResolveError, match="changed since review"):
        pr.create_fix_pr(AVIT, report(), str(checkout), TARGET)
    assert not api.source
    assert all(path != "/git/refs" for path, _, _ in api.calls)


def test_transport_sends_bearer_to_configured_enterprise_api(monkeypatch):
    class Opener:
        def open(self, request, timeout):
            assert timeout == 45
            assert request.full_url == "https://git.example.test/api/v3/repos/contoso/api/pulls"
            assert request.get_header("Authorization") == "Bearer " + TOKEN
            assert json.loads(request.data) == {"draft": True}
            assert request.get_method() == "POST"
            return io.BytesIO(b'{"number":42}')
    def build(*handlers):
        assert any(isinstance(handler, github_pr._NoRedirect) for handler in handlers)
        return Opener()
    monkeypatch.setattr(github_pr.urllib.request, "build_opener", build)
    assert github_pr._request("https://git.example.test/api/v3/repos/contoso/api", TOKEN, "/pulls", body={"draft": True}) == {"number": 42}


@pytest.mark.parametrize("status", [302, 401, 403, 404, 422])
def test_transport_failures_do_not_expose_response_or_token(monkeypatch, status):
    class Opener:
        def open(self, request, timeout):
            raise urllib.error.HTTPError(request.full_url, status, TOKEN, {}, io.BytesIO(TOKEN.encode()))
    monkeypatch.setattr(github_pr.urllib.request, "build_opener", lambda *_: Opener())
    with pytest.raises(ResolveError, match=f"HTTP {status}") as error:
        github_pr._request("https://api.github.com/repos/contoso/api", TOKEN)
    assert TOKEN not in str(error.value)


def test_only_optional_get_404_is_treated_as_missing(monkeypatch):
    class Opener:
        def open(self, request, timeout):
            raise urllib.error.HTTPError(request.full_url, 404, "missing", {}, None)
    monkeypatch.setattr(github_pr.urllib.request, "build_opener", lambda *_: Opener())
    assert github_pr._request("https://api.github.com/repos/contoso/api", TOKEN, missing_ok=True) is None
    with pytest.raises(ResolveError, match="HTTP 404"):
        github_pr._request("https://api.github.com/repos/contoso/api", TOKEN, body={"draft": True}, missing_ok=True)


@pytest.mark.parametrize("payload", [b"not-json", b"null", b"x" * (2 * 1024 * 1024 + 1)])
def test_transport_rejects_malformed_or_oversized_responses(monkeypatch, payload):
    class Opener:
        def open(self, request, timeout):
            return io.BytesIO(payload)
    monkeypatch.setattr(github_pr.urllib.request, "build_opener", lambda *_: Opener())
    with pytest.raises(ResolveError):
        github_pr._request("https://api.github.com/repos/contoso/api", TOKEN)
