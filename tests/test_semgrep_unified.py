"""Synthetic Unified policy fixtures; no network, credentials, or real policy data."""

from copy import deepcopy
import io
from pathlib import Path
import urllib.error

import pytest

from threatlint import semgrep_platform as sp
from threatlint import semgrep_unified as unified


def bundle(product="code"):
    return {"deployment_slug": "synthetic", "product": product, "rulesets": [],
            "rules": ["r", "unrelated"], "disabled": ["other.disabled"],
            "exceptions": [{"project": "other/repo", "rule": "r", "rule_type": "rule", "exception_type": "include"},
                           {"project_tag_name": "opaque tag / name", "rule": "unrelated", "rule_type": "rule",
                            "exception_type": "exclude"}]}


class Platform:
    def __init__(self):
        self.state = {"code": {"bundle": bundle(), "state_version": "v1"},
                      "secrets": {"bundle": bundle("secrets"), "state_version": "s1"}}
        self.state["secrets"]["bundle"]["rules"] = []
        self.calls = []
        self.preview = None
        self.put_error = None
        self.corrupt = False

    def call(self, path, token, *, method="GET", body=None, headers=None):
        self.calls.append((path, method, deepcopy(body), headers))
        if "/v1/" in path:
            raise sp.SemgrepError("legacy retired", status=410)
        product = path.rsplit("/", 1)[-1].removesuffix(":dryRun")
        if path.endswith(":dryRun"):
            self.preview = deepcopy(body)
            return {"state_version": self.state[product]["state_version"], "validation_errors": []}
        if method == "PUT":
            assert headers == {"If-Match": self.state[product]["state_version"]}
            assert body == self.preview, "apply must be exactly the dry-run proposal"
            if self.put_error:
                raise self.put_error
            self.state[product] = {"bundle": deepcopy(body["bundle"]), "state_version": "v2"}
            if self.corrupt:
                self.state[product]["bundle"]["exceptions"] = []
        return deepcopy(self.state[product])

    @property
    def writes(self):
        return [item for item in self.calls if item[1] == "PUT"]


@pytest.fixture
def platform(monkeypatch):
    fake = Platform()
    monkeypatch.setattr(sp, "call", fake.call)
    return fake


def test_legacy_410_reads_both_products_and_preserves_complete_snapshots(platform):
    policies = sp.policy_reads("synthetic", {"id": 7})
    assert [item["id"] for item in policies] == ["code", "secrets"]
    assert policies[0]["snapshot"] == platform.state["code"]
    assert platform.writes == []


@pytest.mark.parametrize("status", [401, 403, 404, 409, 429, 500])
def test_non_410_legacy_errors_never_fall_back(monkeypatch, status):
    seen = []

    def call(path, token):
        seen.append(path)
        raise sp.SemgrepError("failure", status=status)

    monkeypatch.setattr(sp, "call", call)
    with pytest.raises(sp.SemgrepError):
        sp.policy_reads("synthetic", {"id": 7})
    assert seen == ["/api/policies/v1/deployments/7"]


def test_only_product_not_enabled_404_is_skipped(monkeypatch, platform):
    original = platform.call

    def call(path, token, **kwargs):
        if path.endswith("/secrets"):
            raise sp.SemgrepError("disabled", status=404, api_code="PRODUCT_NOT_ENABLED")
        return original(path, token, **kwargs)

    monkeypatch.setattr(sp, "call", call)
    assert [item["id"] for item in sp.policy_reads("synthetic", {"id": 7})] == ["code"]

    platform.state.pop("secrets")
    monkeypatch.setattr(sp, "call", lambda *args, **kwargs: (_ for _ in ()).throw(
        sp.SemgrepError("missing", status=404)))
    with pytest.raises(sp.SemgrepError):
        unified.policies({"id": 7}, "synthetic", call=sp.call, error_type=sp.SemgrepError)


def test_secrets_classification_finds_project_tuning_in_code(platform, monkeypatch):
    platform.state["code"]["bundle"]["exceptions"].append(
        {"project": "org/repo", "rule": "org.r.tuned", "rule_type": "rule", "exception_type": "include"})
    assert sp.existing_tuning("synthetic", {"id": 7}, "secrets", "r") == []
    found = sp.existing_tuning("synthetic", {"id": 7}, "secrets", "r", project="org/repo")
    assert found[0]["tuned"] == "org.r.tuned"
    assert found[0]["mode"] == "include", "V2 has detection, not legacy remediation modes"
    monkeypatch.setattr(sp, "original_rule_yaml", lambda rule, token: rule)
    assert sp.rule_base("r", "secrets", "synthetic", {"id": 7}, project="org/repo")[0] == "org.r.tuned"
    assert platform.writes == []


def test_project_exclusion_hides_global_tuning(platform):
    data = platform.state["code"]["bundle"]
    data["rules"].append("org.r.tuned")
    data["exceptions"].append({"project": "org/repo", "rule": "org.r.tuned", "rule_type": "rule",
                               "exception_type": "exclude"})
    assert sp.existing_tuning("synthetic", {"id": 7}, "sast", "r", project="org/repo") == []
    assert len(sp.existing_tuning("synthetic", {"id": 7}, "sast", "r", project="another/repo")) == 1


@pytest.mark.parametrize("operation", ["replace", "disable"])
def test_unified_mutation_requires_project_before_any_dry_run(platform, operation):
    with pytest.raises(sp.SemgrepError, match="project name"):
        if operation == "replace":
            sp.replace_in_policies("synthetic", {"id": 7}, "sast", "r", "org.r.tuned", mode="include")
        else:
            sp.disable_originals("synthetic", {"id": 7}, "sast", "r")
    assert all(item[1] == "GET" for item in platform.calls)


def test_unified_replacement_does_not_pretend_to_support_monitor_mode(platform):
    with pytest.raises(sp.SemgrepError, match="MODE_MONITOR"):
        sp.replace_in_policies("synthetic", {"id": 7}, "sast", "r", "org.r.tuned", project="org/repo")
    assert all(item[1] == "GET" for item in platform.calls)


def test_project_replacement_preserves_every_unrelated_selection_and_exception(platform):
    before = deepcopy(platform.state["code"]["bundle"])
    changes = sp.replace_in_policies("synthetic", {"id": 7}, "secrets", "r", "org.r.tuned",
                                    project="org/repo", mode="include")
    after = platform.state["code"]["bundle"]
    assert {key: value for key, value in after.items() if key != "exceptions"} == {
        key: value for key, value in before.items() if key != "exceptions"}
    assert after["exceptions"][:len(before["exceptions"])] == before["exceptions"]
    assert after["exceptions"][-2:] == [
        {"project": "org/repo", "rule": "r", "rule_type": "rule", "exception_type": "exclude"},
        {"project": "org/repo", "rule": "org.r.tuned", "rule_type": "rule", "exception_type": "include"}]
    assert len(platform.writes) == 1
    assert changes[0]["rollback"]["body"] == {"bundle": before}
    assert changes[0]["rollback"]["if_match"] == "v2"
    assert platform.calls[-1][1] == "GET", "read persisted policy after applying it"


def test_disabling_original_is_project_scoped_and_idempotent(platform):
    platform.state["code"]["bundle"]["rules"].append("org.r.tuned")
    changes = sp.disable_originals("synthetic", {"id": 7}, "secrets", "r", project="org/repo")
    assert len(changes) == 1
    assert platform.state["code"]["bundle"]["rules"] == ["r", "unrelated", "org.r.tuned"]
    assert sp.disable_originals("synthetic", {"id": 7}, "secrets", "r", project="org/repo") == []
    assert len(platform.writes) == 1


def test_disabled_tuned_rule_cannot_authorize_original_disable(platform):
    platform.state["code"]["bundle"]["rules"].append("org.r.tuned")
    platform.state["code"]["bundle"]["disabled"].append("org.r.tuned")
    assert sp.disable_originals("synthetic", {"id": 7}, "sast", "r", project="org/repo") == []
    assert platform.writes == []


@pytest.mark.parametrize("failure", ["validation", "version", "conflict", "persisted"])
def test_failed_proposals_never_replay_stale_writes(platform, monkeypatch, failure):
    original = platform.call
    if failure == "conflict":
        platform.put_error = sp.SemgrepError("conflict", status=409)
    if failure == "persisted":
        platform.corrupt = True

    def call(path, token, **kwargs):
        data = original(path, token, **kwargs)
        if path.endswith(":dryRun"):
            if failure == "validation":
                data["validation_errors"] = [{"code": "UNKNOWN_REFERENCE"}]
            elif failure == "version":
                data["state_version"] = "changed"
        return data

    monkeypatch.setattr(sp, "call", call)
    with pytest.raises(sp.SemgrepError) as error:
        sp.replace_in_policies("synthetic", {"id": 7}, "sast", "r", "org.r.tuned",
                               project="org/repo", mode="include")
    assert len(platform.writes) == (1 if failure in ("conflict", "persisted") else 0)
    if failure == "persisted":
        assert error.value.rollback["if_match"] == "v2"


def test_missing_snapshot_fields_cannot_delete_exceptions(platform):
    del platform.state["code"]["bundle"]["exceptions"]
    with pytest.raises(sp.SemgrepError, match="partial snapshot"):
        sp.replace_in_policies("synthetic", {"id": 7}, "sast", "r", "org.r.tuned",
                               project="org/repo", mode="include")
    assert platform.writes == []


def test_unresolved_tag_membership_fails_closed(platform):
    platform.state["code"]["bundle"]["exceptions"].append(
        {"project_tag_name": "segment", "rule": "r", "rule_type": "rule", "exception_type": "exclude"})
    with pytest.raises(sp.SemgrepError, match="precedence"):
        sp.replace_in_policies("synthetic", {"id": 7}, "sast", "r", "org.r.tuned",
                               project="org/repo", mode="include")
    assert platform.writes == []


def test_existing_project_exception_is_updated_not_dropped(platform):
    platform.state["code"]["bundle"]["exceptions"].append(
        {"project": "org/repo", "rule": "r", "rule_type": "rule", "exception_type": "include",
         "future_metadata": "retained"})
    sp.replace_in_policies("synthetic", {"id": 7}, "sast", "r", "org.r.tuned",
                           project="org/repo", mode="include")
    exception = next(item for item in platform.state["code"]["bundle"]["exceptions"] if item.get("project") == "org/repo")
    assert exception["exception_type"] == "exclude" and exception["future_metadata"] == "retained"


def test_pack_original_is_excluded_only_for_project_when_tuning_is_known(platform):
    data = platform.state["code"]["bundle"]
    data["rules"] = ["org.r.tuned"]
    data["rulesets"] = ["p/synthetic"]
    sp.disable_originals("synthetic", {"id": 7}, "sast", "r", project="org/repo")
    assert platform.state["code"]["bundle"]["rulesets"] == ["p/synthetic"]
    assert platform.state["code"]["bundle"]["disabled"] == ["other.disabled"]
    assert platform.state["code"]["bundle"]["exceptions"][-2]["rule"] == "r"


def test_globally_disabled_pack_original_is_already_safe(platform):
    data = platform.state["code"]["bundle"]
    data["rules"] = ["org.r.tuned"]
    data["rulesets"] = ["p/synthetic"]
    data["disabled"].append("r")
    assert sp.disable_originals("synthetic", {"id": 7}, "sast", "r", project="org/repo") == []
    assert platform.writes == []


def test_post_apply_concurrency_cannot_generate_an_unsafe_rollback(platform, monkeypatch):
    original = platform.call

    def call(path, token, **kwargs):
        data = original(path, token, **kwargs)
        if kwargs.get("method", "GET") == "GET" and platform.writes:
            data["state_version"] = "another-writer"
            data["bundle"]["rules"].append("concurrent.rule")
        return data

    monkeypatch.setattr(sp, "call", call)
    with pytest.raises(sp.SemgrepError, match="changed after apply") as error:
        sp.replace_in_policies("synthetic", {"id": 7}, "sast", "r", "org.r.tuned",
                               project="org/repo", mode="include")
    assert error.value.rollback["if_match"] == "v2", "rollback must conflict rather than overwrite another writer"
    assert len(platform.writes) == 1


def test_existing_unified_tuning_noop_never_republishes_or_changes_policy(platform, monkeypatch):
    data = platform.state["code"]["bundle"]
    data["rules"].append("org.r.tuned")
    data["exceptions"].append({"project": "org/repo", "rule": "r", "rule_type": "rule", "exception_type": "exclude"})
    monkeypatch.setattr(sp, "original_rule_yaml", lambda *args: "synthetic live YAML")
    monkeypatch.setattr(sp, "_matches", lambda *args, **kwargs: [])
    monkeypatch.setattr(sp, "publish", lambda *args: pytest.fail("must not republish a covered false positive"))
    assert sp.tune_rule("unused", "secrets", "r", "", None, "synthetic", {"id": 7},
                        out=io.StringIO(), project="org/repo") == []
    assert all(item[1] == "GET" for item in platform.calls)


def test_tuning_noop_returns_rollback_data_when_project_original_needs_repair(platform, monkeypatch):
    platform.state["code"]["bundle"]["rules"].append("org.r.tuned")
    monkeypatch.setattr(sp, "original_rule_yaml", lambda *args: "synthetic live YAML")
    monkeypatch.setattr(sp, "publish", lambda *args: pytest.fail("must not republish"))
    changes = sp.tune_rule("unused", "secrets", "r", "", None, "synthetic", {"id": 7},
                           out=io.StringIO(), project="org/repo")
    assert len(changes) == 1
    assert changes[0]["rollback"]["if_match"] == "v2"
    assert len(platform.writes) == 1


def test_shared_unified_rule_extension_fails_before_publication(platform, monkeypatch):
    platform.state["code"]["bundle"]["rules"].append("org.r.tuned")
    monkeypatch.setattr(sp, "original_rule_yaml", lambda *args: "synthetic live YAML")
    monkeypatch.setattr(sp, "_matches", lambda *args, **kwargs: [1])
    monkeypatch.setattr(sp, "publish", lambda *args: pytest.fail("must not republish a shared Unified rule"))
    with pytest.raises(sp.SemgrepError, match="not project-scoped"):
        sp.tune_rule("unused", "sast", "r", __file__, 1, "synthetic", {"id": 7},
                     out=io.StringIO(), project="org/repo")
    assert platform.writes == []


def test_new_unified_tuning_fails_before_publication(platform, monkeypatch):
    monkeypatch.setattr(sp, "tuned_rule_from_report", lambda *args: "synthetic YAML")
    monkeypatch.setattr(sp, "validate_tuned_rule", lambda *args: {"path": "unused"})
    monkeypatch.setattr(sp, "publish", lambda *args: pytest.fail("must not publish without monitor-mode support"))
    with pytest.raises(sp.SemgrepError, match="cannot enforce MODE_MONITOR"):
        sp.tune_rule("unused", "sast", "r", "", None, "synthetic", {"id": 7},
                     out=io.StringIO(), project="org/repo")
    assert platform.writes == []


def test_rule_base_cli_passes_project_context(monkeypatch, tmp_path):
    from argparse import ArgumentParser
    from threatlint import semgrep_cli

    parser = ArgumentParser()
    sp.add_semgrep_parser(parser.add_subparsers())
    output = tmp_path / "rule.yaml"
    args = parser.parse_args(["semgrep", "rule-base", "r", "--kind", "secrets", "--project", "org/repo", "-o", str(output)])
    seen = []
    result = semgrep_cli.cmd_semgrep(
        args, login=None, resolve_token=lambda *args: ("synthetic", "synthetic"), deployment=lambda token: {"id": 7},
        rule_base=lambda *args, **kwargs: seen.append(kwargs) or ("rules: []", "synthetic"),
        logout=None, error_type=sp.SemgrepError)
    assert result == 0 and seen == [{"project": "org/repo"}]
    assert Path(output).read_text().endswith("rules: []")


def test_transport_sends_if_match_without_retrying_ambiguous_writes(monkeypatch):
    seen = []

    class Opener:
        def open(self, request, **kwargs):
            seen.append(request)
            raise TimeoutError("synthetic timeout")

    monkeypatch.setattr(sp, "_OPENER", Opener())
    with pytest.raises(sp.SemgrepError, match="1 attempts"):
        sp.call("/synthetic", "synthetic", method="PUT", body={"bundle": {}}, headers={"If-Match": "v1"})
    assert len(seen) == 1
    assert seen[0].get_header("If-match") == "v1"


def test_transport_does_not_retry_version_conflicts(monkeypatch):
    seen = []

    class Opener:
        def open(self, request, **kwargs):
            seen.append(request)
            raise urllib.error.HTTPError("https://synthetic.invalid", 409, "conflict", {},
                                         io.BytesIO(b'{"code":"STATE_VERSION_CONFLICT"}'))

    monkeypatch.setattr(sp, "_OPENER", Opener())
    with pytest.raises(sp.SemgrepError) as error:
        sp.call("/synthetic", "synthetic", method="PUT", body={"bundle": {}}, headers={"If-Match": "stale"})
    assert error.value.status == 409 and len(seen) == 1


def test_http_errors_keep_status_and_machine_code_without_response_details():
    error = urllib.error.HTTPError("https://synthetic.invalid", 404, "missing", {},
                                   io.BytesIO(b'{"code":"PRODUCT_NOT_ENABLED","message":"private response"}'))
    result = sp._http_error(error, "/synthetic")
    assert result.status == 404 and result.api_code == "PRODUCT_NOT_ENABLED"
    assert "private response" not in str(result)
