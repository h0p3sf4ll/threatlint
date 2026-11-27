"""Draft fix PRs use local Git fixtures and a mocked ADO API; no live writes."""

import json
import os
import subprocess
from types import SimpleNamespace

import pytest

from threatlint import ado_login, avit_cli, avit_pr as pr
from threatlint.avit_report import ResolveError

AVIT = "AVIT000000000000001"
TARGET = {"scm": "azure-devops", "organization": "contoso", "project": "Platform", "name": "api", "branch": "main"}
ORIGIN = "https://dev.azure.com/contoso/Platform/_git/api"
REVIEWER_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
CREATOR_ID = "99999999-8888-7777-6666-555555555555"
REPO_ID = "11111111-2222-3333-4444-555555555555"
PAT = "synthetic-service-account-pat-value"
SOURCE = "def parse(value):\n    return eval(value)\n"
PATCH = """diff --git a/app.py b/app.py
index 1111111..2222222 100644
--- a/app.py
+++ b/app.py
@@ -1,2 +1,4 @@
+import ast
+
 def parse(value):
-    return eval(value)
+    return ast.literal_eval(value)
"""


def report(patch=PATCH, disposition="TRUE POSITIVE", basis=""):
    return (f"#### [FP-001] — Unsafe expression evaluation\n**Original finding**: {AVIT}; rule; scanner; app.py:2\n"
            f"**Disposition**: {disposition}\n**Confidence**: CONFIRMED\n{basis}"
            "**Evidence**: app.py:2 evaluates caller-controlled text.\n"
            "**Verified Safe Behavior**: Synthetic proof for the false-positive test only.\n"
            + (f"**Proposed fix patch**:\n```diff\n{patch}```\n" if patch else ""))


def confirmed_report(patch=PATCH, disposition="TRUE POSITIVE", basis=""):
    return report(patch, disposition, basis).replace(
        "**Evidence**: app.py:2 evaluates caller-controlled text.",
        "**Evidence**: `app.py:1-2` passes the caller's value to `eval(value)` without validation.\n"
        "**Exploit path**: The caller controls value, which reaches eval at app.py:2 without a guard.\n"
        "**Fix rationale**: Literal parsing accepts existing literals without evaluating expressions.\n"
        "**Regression assertions**: Accept a list literal and reject a function call. Tests NOT RUN.",
    )


def git(repo, *args):
    env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, env=env).stdout.decode().strip()


@pytest.fixture
def checkout(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-b", "main")
    git(repo, "config", "user.name", "Fixture")
    git(repo, "config", "user.email", "fixture@example.test")
    # The reviewed Git blob and unified diff deliberately use exact UTF-8/LF bytes.
    # Default text writes translate to CRLF on Windows without an autocrlf policy.
    (repo / "app.py").write_bytes(SOURCE.encode("utf-8"))
    git(repo, "add", "app.py")
    git(repo, "commit", "-m", "fixture")
    git(repo, "remote", "add", "origin", ORIGIN)
    return repo


class FakeAdo:
    def __init__(self, repo):
        self.head = git(repo, "rev-parse", "HEAD")
        self.tree = pr._prepare(repo, PATCH, self.head)[1]
        self.calls = []
        self.source = ""
        self.commit = "a" * 40
        self.pulls = []
        self.remote_head = self.head
        self.identities = {"fixture@example.test": [{"id": REVIEWER_ID, "isActive": True}]}
        self.reviewers = []

    def __call__(self, base, pat, path="", *, params=None, body=None, method=None):
        assert pat == PAT
        if base == "https://vssps.dev.azure.com/contoso/_apis/identities":
            assert params["searchFilter"] == "General" and body is None
            return {"value": self.identities.get(params["filterValue"], [])}
        assert base == "https://dev.azure.com/contoso/Platform/_apis/git/repositories/api"
        self.calls.append((path, params, body))
        if path.startswith("/pullrequests/42/reviewers/"):
            assert method == "PUT" and body == {"vote": 0}
            self.reviewers.append(path.rsplit("/", 1)[1])
            return {"id": path.rsplit("/", 1)[1], "vote": 0}
        if path == "/pullrequests/42":
            assert method == "PATCH" and body == {"isDraft": False}
            self.pulls[0] = {**self.pulls[0], "isDraft": False}
            return self.pulls[0]
        if path == "":
            return {"id": REPO_ID}
        if path == "/refs":
            name = "refs/" + params["filter"]
            if name == "refs/heads/main":
                return {"value": [{"name": name, "objectId": self.remote_head}]}
            return {"value": [{"name": name, "objectId": self.commit}] if name == self.source else []}
        if path.startswith("/commits/"):
            return {"parents": [self.head], "treeId": self.tree}
        if path == "/pullrequests" and body is None:
            return {"value": self.pulls}
        if path == "/pushes":
            self.source = body["refUpdates"][0]["name"]
            assert body["refUpdates"][0]["oldObjectId"] == "0" * 40
            assert body["commits"][0]["parents"] == [self.head]
            assert body["commits"][0]["changes"][0]["newContent"]["content"] == "import ast\n\ndef parse(value):\n    return ast.literal_eval(value)\n"
            return {"commits": [{"commitId": self.commit, "treeId": self.tree, "parents": [self.head]}],
                    "refUpdates": [{"name": self.source, "newObjectId": self.commit}]}
        if path == "/pullrequests" and body:
            assert body["isDraft"] is False
            assert "autoCompleteSetBy" not in body and "completionOptions" not in body
            assert "NOT RUN" in body["description"]
            assert PAT not in body["description"]
            pull = {**body, "pullRequestId": 42, "repository": {"id": REPO_ID}, "status": "active",
                    "createdBy": {"id": CREATOR_ID}}
            self.pulls = [pull]
            return pull
        pytest.fail(f"Unexpected API path: {path}")


@pytest.fixture
def api(monkeypatch, checkout):
    fake = FakeAdo(checkout)
    monkeypatch.setattr(pr, "_request", fake)
    monkeypatch.setattr(ado_login, "service_account_pat", lambda organization, profile=None: (PAT, "AWS Parameter Store (service account)"))
    return fake


def test_creates_published_pr_without_modifying_checkout(checkout, api, monkeypatch):
    original_index = (checkout / ".git" / "index").read_bytes()
    original_objects = sorted(str(path.relative_to(checkout)) for path in (checkout / ".git" / "objects").rglob("*"))
    credentials = []
    monkeypatch.setattr(ado_login, "service_account_pat", lambda organization, profile=None: credentials.append((organization, profile)) or (PAT, "service account"))
    result = pr.create_fix_pr(AVIT, confirmed_report(), str(checkout), TARGET, profile="appsec", instance="https://test.service-now.com")
    assert result["status"] == "created" and result["draft"] is False
    assert result["url"] == ORIGIN + "/pullrequest/42"
    assert result["reviewers"] == ["Fixture"] and api.reviewers == [REVIEWER_ID]
    assert "review requested from Fixture" in result["reason"]
    assert credentials == [("contoso", "appsec")]
    assert (checkout / "app.py").read_text() == SOURCE
    assert (checkout / ".git" / "index").read_bytes() == original_index
    assert sorted(str(path.relative_to(checkout)) for path in (checkout / ".git" / "objects").rglob("*")) == original_objects
    body = next(body for path, _, body in api.calls if path == "/pullrequests" and body)
    assert f"[{AVIT}](https://test.service-now.com/nav_to.do?uri=" in body["description"]
    assert body["targetRefName"] == "refs/heads/main"
    assert body["title"] == f"Fix {AVIT}: Unsafe expression evaluation"
    assert body["description"].startswith("Unsafe expression evaluation.")


def test_retry_reuses_the_exact_existing_pr(checkout, api):
    first = pr.create_fix_pr(AVIT, confirmed_report(), str(checkout), TARGET)
    second = pr.create_fix_pr(AVIT, confirmed_report(), str(checkout), TARGET)
    assert first["url"] == second["url"]
    assert second["status"] == "existing"
    assert sum(path == "/pushes" for path, _, _ in api.calls) == 1
    assert sum(path == "/pullrequests" and body is not None for path, _, body in api.calls) == 1


def test_retry_after_push_can_create_missing_pr(checkout, api):
    pr.create_fix_pr(AVIT, confirmed_report(), str(checkout), TARGET)
    api.pulls = []
    result = pr.create_fix_pr(AVIT, confirmed_report(), str(checkout), TARGET)
    assert result["status"] == "created"
    assert sum(path == "/pushes" for path, _, _ in api.calls) == 1


def test_existing_branch_is_never_overwritten(checkout, api):
    pr.create_fix_pr(AVIT, confirmed_report(), str(checkout), TARGET)
    api.pulls = []
    api.tree = "b" * 40
    with pytest.raises(ResolveError, match="not overwritten"):
        pr.create_fix_pr(AVIT, confirmed_report(), str(checkout), TARGET)
    assert sum(path == "/pushes" for path, _, _ in api.calls) == 1


@pytest.mark.parametrize("change", ["sourceRefName", "targetRefName", "repository"])
def test_existing_pr_must_match_identity(checkout, api, change):
    pr.create_fix_pr(AVIT, confirmed_report(), str(checkout), TARGET)
    api.pulls[0][change] = {"id": "other"} if change == "repository" else "refs/heads/other"
    with pytest.raises(ResolveError, match="does not match"):
        pr.create_fix_pr(AVIT, confirmed_report(), str(checkout), TARGET)


@pytest.mark.parametrize("content,target", [
    (confirmed_report(disposition="FALSE POSITIVE"), TARGET),
    (confirmed_report(basis="**Decision basis**: CONSERVATIVE DEFAULT\n"), TARGET),
    (confirmed_report(patch=""), TARGET),
    (confirmed_report(), {**TARGET, "scm": "unsupported"}),
    (confirmed_report(), {**TARGET, "branch": ""}),
    (confirmed_report(), {**TARGET, "branch_deleted": "release"}),
])
def test_ineligible_reviews_skip_without_credentials_or_network(checkout, monkeypatch, content, target):
    monkeypatch.setattr(ado_login, "service_account_pat", lambda *_: pytest.fail("No credential lookup for a skipped proposal"))
    monkeypatch.setattr(pr, "_request", lambda *_args, **_kwargs: pytest.fail("No network for a skipped proposal"))
    assert pr.create_fix_pr(AVIT, content, str(checkout), target)["status"] == "skipped"


@pytest.mark.parametrize("content,reason", [
    (report(), "Exploit path"),
    (confirmed_report().replace("Confidence**: CONFIRMED", "Confidence**: PLAUSIBLE"), "Confirm the actual rule claim"),
    (confirmed_report() + "\n- **Validation status:** UNVERIFIED\n", "still unverified"),
    (confirmed_report().replace("app.py:1-2", "app.py:999"), "invalid source citation"),
    (confirmed_report().replace("**Fix rationale**", "**Other details**"), "Fix rationale"),
    (confirmed_report().replace("**Regression assertions**", "**Test notes**"), "Regression assertions"),
])
def test_publisher_requires_confirmation_and_local_evidence_before_preparing_patch(checkout, monkeypatch, content, reason):
    monkeypatch.setattr(pr, "_prepare", lambda *_: pytest.fail("No patch preparation before evidence is ready"))
    monkeypatch.setattr(ado_login, "service_account_pat", lambda *_: pytest.fail("No credential lookup before evidence is ready"))
    monkeypatch.setattr(pr, "_request", lambda *_args, **_kwargs: pytest.fail("No network before evidence is ready"))
    result = pr.create_fix_pr(AVIT, content, str(checkout), TARGET)
    assert result["status"] == "skipped" and reason in result["reason"]


def test_direct_fix_pr_command_checks_source_evidence(checkout, tmp_path, monkeypatch, capsys):
    markdown = tmp_path / "review.md"
    markdown.write_text(confirmed_report().replace("app.py:1-2", "missing.py:1"), encoding="utf-8")
    target = tmp_path / "target.json"
    target.write_text(json.dumps({**TARGET, "avit": AVIT, "file_path": "app.py"}), encoding="utf-8")
    monkeypatch.setattr(ado_login, "service_account_pat", lambda *_: pytest.fail("No credential lookup for invalid evidence"))
    args = SimpleNamespace(number=AVIT, report=str(markdown), checkout=str(checkout), target=str(target),
                           yes=True, aws_profile=None, snow_instance="")
    assert avit_cli.cmd_fix_pr(args) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "skipped" and "invalid source citation" in result["reason"]


def test_folder_download_cannot_publish_a_pr(tmp_path):
    assert pr.create_fix_pr(AVIT, confirmed_report(), str(tmp_path), TARGET)["status"] == "skipped"


def test_conservative_true_positive_explains_why_no_pr_was_opened(checkout, api):
    result = pr.create_fix_pr(AVIT, confirmed_report(basis="**Decision basis**: CONSERVATIVE DEFAULT\n"), str(checkout), TARGET)
    assert result == {"status": "skipped", "reason": "The report marks this TRUE POSITIVE as unverified (conservative default); no automatic fix PR was opened"}
    assert api.calls == []


def test_patch_from_a_different_finding_is_not_published(checkout, api):
    content = confirmed_report(patch="") + confirmed_report().replace(AVIT, "AVIT000000000000002").replace("FP-001", "FP-002")
    result = pr.create_fix_pr(AVIT, content, str(checkout), TARGET)
    assert result["status"] == "skipped" and "alone" in result["reason"]
    assert api.calls == []


@pytest.mark.parametrize("marker", ["**Proposed fix patch:**", "- **Proposed fix patch**:", "### Proposed fix patch"])
def test_formatted_patch_label_creates_the_same_validated_pr(checkout, api, marker):
    content = confirmed_report().replace("**Proposed fix patch**:", marker).replace("**Original finding**:", "- **Original finding:**")
    assert pr.create_fix_pr(AVIT, content, str(checkout), TARGET)["status"] == "created"
    assert any(body and body.get("isDraft") is False for _, _, body in api.calls)


def test_example_patch_markers_are_not_executable_proposals():
    content = "````md\n" + report() + "````\n"
    assert pr._patch(content) == ""
    assert pr._patch(content + report()) == PATCH
    assert pr._patch("\n".join("    " + line for line in report().splitlines())) == ""


def test_duplicate_or_incomplete_formatted_patch_is_rejected():
    for content in (report() + "\n### Proposed fix patch\n", report().removesuffix("```\n")):
        with pytest.raises(ResolveError, match="exactly one complete"):
            pr._patch(content)


@pytest.mark.parametrize("path", ["../outside.py", ".git/config", "folder/.git/config", ".gitattributes", "folder/../../out.py"])
def test_patch_paths_cannot_escape_or_change_git_controls(checkout, api, path):
    with pytest.raises(ResolveError, match="path"):
        pr.create_fix_pr(AVIT, confirmed_report(PATCH.replace("app.py", path)), str(checkout), TARGET)
    assert api.calls == []


def test_symlink_patch_is_rejected(checkout, api):
    (checkout / "linked.py").symlink_to("app.py")
    git(checkout, "add", "linked.py")
    git(checkout, "commit", "-m", "link fixture")
    with pytest.raises(ResolveError, match="symlink"):
        pr.create_fix_pr(AVIT, confirmed_report(PATCH.replace("app.py", "linked.py")), str(checkout), TARGET)
    assert api.calls == []


@pytest.mark.parametrize("patch", [
    PATCH.replace("return eval(value)", "return missing(value)"),
    PATCH.replace("index 1111111..2222222 100644", "old mode 100644\nnew mode 100755"),
    PATCH.replace("import ast", 'token = "ghp_' + "x" * 30 + '"'),
    PATCH.replace("import ast", "[REDACTED]"),
])
def test_unsafe_or_inapplicable_proposal_never_publishes(checkout, api, patch):
    with pytest.raises(ResolveError):
        pr.create_fix_pr(AVIT, confirmed_report(patch), str(checkout), TARGET)
    assert api.calls == []


def test_dirty_checkout_is_not_published(checkout, api):
    (checkout / "app.py").write_bytes(b"user edit\n")
    with pytest.raises(ResolveError, match="clean"):
        pr.create_fix_pr(AVIT, confirmed_report(), str(checkout), TARGET)
    assert api.calls == []


def test_filters_are_rejected_without_executing_them(checkout, api, tmp_path):
    marker = tmp_path / "filter-executed"
    git(checkout, "config", "filter.evil.clean", f"touch {marker}")
    with pytest.raises(ResolveError, match="content filters"):
        pr.create_fix_pr(AVIT, confirmed_report(), str(checkout), TARGET)
    assert not marker.exists() and api.calls == []


def test_moved_target_is_not_published(checkout, api):
    api.remote_head = "b" * 40
    with pytest.raises(ResolveError, match="changed since review"):
        pr.create_fix_pr(AVIT, confirmed_report(), str(checkout), TARGET)
    assert all(body is None for _, _, body in api.calls)


def test_service_account_failure_never_uses_personal_credentials(checkout, api, monkeypatch):
    monkeypatch.setattr(ado_login, "service_account_pat", lambda *_: (_ for _ in ()).throw(ado_login.AdoLoginError("AWS access failed")))
    monkeypatch.setattr(ado_login, "load", lambda *_: pytest.fail("No local PAT fallback"))
    with pytest.raises(ResolveError, match="AWS access failed"):
        pr.create_fix_pr(AVIT, confirmed_report(), str(checkout), TARGET)
    assert api.calls == []


@pytest.mark.parametrize("draft", [None, True, "false"])
def test_creation_requires_an_explicit_published_acknowledgement(checkout, api, monkeypatch, draft):
    def request(*args, **kwargs):
        result = api(*args, **kwargs)
        if args[2:] == ("/pullrequests",) and kwargs.get("body"):
            result["isDraft"] = draft
        return result
    monkeypatch.setattr(pr, "_request", request)
    with pytest.raises(ResolveError, match="confirm a published PR"):
        pr.create_fix_pr(AVIT, confirmed_report(), str(checkout), TARGET)


def test_existing_pr_can_have_been_promoted_from_draft(checkout, api):
    pr.create_fix_pr(AVIT, confirmed_report(), str(checkout), TARGET)
    api.pulls[0]["isDraft"] = False
    result = pr.create_fix_pr(AVIT, confirmed_report(), str(checkout), TARGET)
    assert result["status"] == "existing" and result["draft"] is False


def test_summary_is_bounded_single_line_without_token_values():
    assert pr._summary("Unsafe\n<script>evaluation</script>\n" + "x " * 200).count("\n") == 0
    assert len(pr._summary("x " * 200)) <= 140
    assert "ghp_" not in pr._summary("Leaked ghp_" + "x" * 30)


def test_http_errors_do_not_reveal_response_bodies_or_credentials(monkeypatch):
    class Opener:
        def open(self, request, timeout):
            assert timeout == 45
            raise pr.urllib.error.HTTPError(request.full_url, 403, PAT, {}, None)
    monkeypatch.setattr(pr.urllib.request, "build_opener", lambda *_: Opener())
    with pytest.raises(ResolveError, match="HTTP 403") as error:
        pr._request("https://dev.azure.com/contoso/Platform/_apis/git/repositories/api", PAT)
    assert PAT not in str(error.value)
    assert pr._NoRedirect().redirect_request(None, None, 302, "", {}, "https://other.test") is None


def test_proposal_can_add_a_regular_regression_test_without_writing_it(checkout):
    test_patch = """diff --git a/test_app.py b/test_app.py
new file mode 100644
--- /dev/null
+++ b/test_app.py
@@ -0,0 +1,3 @@
+from app import parse
+def test_parse():
+    assert parse('[1]') == [1]
"""
    changes, tree = pr._prepare(checkout, PATCH + test_patch, git(checkout, "rev-parse", "HEAD"))
    assert changes[-1] == {"changeType": "add", "item": {"path": "/test_app.py"}, "newContent": {
        "content": "from app import parse\ndef test_parse():\n    assert parse('[1]') == [1]\n", "contentType": "rawtext"}}
    assert len(tree) == 40 and not (checkout / "test_app.py").exists()


@pytest.mark.parametrize("newline", ["\n", "\r\n"], ids=["lf-blob", "crlf-blob"])
def test_cached_proposal_preserves_committed_line_endings_without_weakening_matching(checkout, newline):
    git(checkout, "config", "core.autocrlf", "false")
    source = SOURCE.replace("\n", newline).encode("utf-8")
    (checkout / "app.py").write_bytes(source)
    git(checkout, "add", "app.py")
    git(checkout, "commit", "--allow-empty", "-m", "explicit line-ending fixture")
    head = git(checkout, "rev-parse", "HEAD")
    index = (checkout / ".git" / "index").read_bytes()
    # Git diff headers stay LF; hunk content carries each source line's actual ending.
    patch = "".join(line if line.startswith(("diff ", "index ", "--- ", "+++ ", "@@ "))
                    else line.rstrip("\n") + newline for line in PATCH.splitlines(keepends=True))
    if newline == "\r\n":
        with pytest.raises(ResolveError, match="could not be validated"):
            pr._prepare(checkout, PATCH, head)
    changes, tree = pr._prepare(checkout, patch, head)
    expected = "import ast\n\ndef parse(value):\n    return ast.literal_eval(value)\n".replace("\n", newline)
    assert changes[0]["newContent"]["content"] == expected
    assert len(tree) == 40
    assert (checkout / "app.py").read_bytes() == source
    assert (checkout / ".git" / "index").read_bytes() == index
    assert git(checkout, "status", "--porcelain") == ""


def test_lf_proposal_uses_index_content_for_an_autocrlf_checkout(checkout):
    git(checkout, "config", "core.autocrlf", "true")
    working_bytes = SOURCE.replace("\n", "\r\n").encode("utf-8")
    (checkout / "app.py").unlink()
    git(checkout, "checkout", "--", "app.py")
    assert (checkout / "app.py").read_bytes() == working_bytes
    assert git(checkout, "status", "--porcelain") == ""
    changes, _tree = pr._prepare(checkout, PATCH, git(checkout, "rev-parse", "HEAD"))
    assert changes[0]["newContent"]["content"] == "import ast\n\ndef parse(value):\n    return ast.literal_eval(value)\n"
    assert (checkout / "app.py").read_bytes() == working_bytes


def test_earlier_draft_is_published_and_reviewers_requested(checkout, api):
    pr.create_fix_pr(AVIT, confirmed_report(), str(checkout), TARGET)
    api.pulls[0]["isDraft"] = True
    api.reviewers.clear()
    result = pr.create_fix_pr(AVIT, confirmed_report(), str(checkout), TARGET)
    assert result["status"] == "existing" and result["draft"] is False
    assert result["reason"].startswith("Existing draft fix PR published; review requested from Fixture")
    assert api.reviewers == [REVIEWER_ID]


def test_reused_published_pr_does_not_renotify(checkout, api):
    pr.create_fix_pr(AVIT, confirmed_report(), str(checkout), TARGET)
    api.reviewers.clear()
    result = pr.create_fix_pr(AVIT, confirmed_report(), str(checkout), TARGET)
    assert result["reason"] == "Existing fix PR reused" and api.reviewers == []


def test_abandoned_draft_is_left_alone(checkout, api):
    pr.create_fix_pr(AVIT, confirmed_report(), str(checkout), TARGET)
    api.pulls[0].update(isDraft=True, status="abandoned")
    result = pr.create_fix_pr(AVIT, confirmed_report(), str(checkout), TARGET)
    assert result["draft"] is True and not any(path == "/pullrequests/42" for path, _, _ in api.calls)


def test_unmatched_author_is_reported_without_failing_the_pr(checkout, api):
    api.identities = {}
    result = pr.create_fix_pr(AVIT, confirmed_report(), str(checkout), TARGET)
    assert result["status"] == "created" and result["reviewers"] == [] and result["unresolved_reviewers"] == ["Fixture"]
    assert "could not request review from Fixture" in result["reason"]


def test_recent_authors_are_newest_first_without_bots_or_duplicates(checkout):
    for name, email in (("Build Service", "build@example.test"), ("Dev Two", "two@example.test"),
                        ("dependabot[bot]", "bot@example.test"), ("Dev One", "one@example.test"), ("Dev Two", "TWO@example.test")):
        (checkout / "app.py").write_text((checkout / "app.py").read_text() + "#\n")
        git(checkout, "-c", f"user.name={name}", "-c", f"user.email={email}", "commit", "-am", "change")
    head = git(checkout, "rev-parse", "HEAD")
    changes = [{"item": {"path": "/app.py"}}]
    assert pr.recent_authors(checkout, head, changes) == [("Dev Two", "TWO@example.test"), ("Dev One", "one@example.test"),
                                                         ("Fixture", "fixture@example.test")]
