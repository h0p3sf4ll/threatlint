"""Semgrep Unified detection policies (policies v2): project exceptions, strict replacement, optimistic locking.

Unified deployments replace legacy per-rule policy modes with one bundle per product (rulesets, rules, disabled,
exceptions). Threatlint only ever adds or flips *project-scoped rule exceptions*, and only when precedence is
unambiguous (no pack or project-tag exception touches the rule). Every write is:

  propose (copy the snapshot, flip two exceptions) → dry run (must validate and keep the same state_version)
  → PUT with If-Match (never retried) → read back (state_version and canonical bundle must match).

A failed write carries `rollback` (the original bundle and the If-Match to restore it) on the raised error.
Callers inject `call` (semgrep_platform.call), `same_rule`, and `error_type` so this module has no I/O of its own.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from copy import deepcopy

PRODUCTS = {"PRODUCT_TYPE_SAST": "code", "PRODUCT_TYPE_SECRETS": "secrets"}
POLICY_LISTS = ("rulesets", "rules", "disabled", "exceptions")
SameRule = Callable[[str, str], bool]


def path(dep_id, product: str) -> str:
    return f"/api/policies/v2/deployments/{dep_id}/detection-policy/{product}"


def snapshot(data: object, product: str, error_type: type[Exception]) -> dict:
    """A deep copy of a complete, internally consistent policy response; refuses partial or ambiguous bundles."""
    if not isinstance(data, dict):
        raise error_type("Unified detection policy response is not an object")
    bundle = data.get("bundle")
    if not isinstance(bundle, dict) or not isinstance(data.get("state_version"), str) or not data["state_version"]:
        raise error_type("Unified detection policy is missing its bundle or state_version")
    if bundle.get("product") != product:
        raise error_type("Unified detection policy product does not match the requested product")
    for key in POLICY_LISTS:
        if not isinstance(bundle.get(key), list):
            raise error_type(f"Unified detection policy is missing its {key} list; refusing a partial snapshot")
    if any(not isinstance(rule, str) or not rule for key in ("rulesets", "rules", "disabled") for rule in bundle[key]):
        raise error_type("Unified detection policy contains an invalid rule selection")
    identities = set()
    for item in bundle["exceptions"]:
        if (not isinstance(item, dict) or item.get("exception_type") not in ("include", "exclude") or
                item.get("rule_type") not in ("rule", "pack") or not isinstance(item.get("rule"), str) or
                not item["rule"] or bool(item.get("project")) == bool(item.get("project_tag_name")) or
                any(value is not None and not isinstance(value, str)
                    for value in (item.get("project"), item.get("project_tag_name")))):
            raise error_type("Unified detection policy contains an invalid exception")
        identity = (item.get("project"), item.get("project_tag_name"), item["rule"], item["rule_type"])
        if identity in identities:
            raise error_type("Duplicate Unified project rule exceptions; refusing an ambiguous replacement")
        identities.add(identity)
    return deepcopy(data)


def policies(dep: dict, token: str, *, call: Callable, error_type: type[Exception]) -> list[dict]:
    """One validated snapshot per enabled product, shaped like a legacy policy record (`unified: True`)."""
    result = []
    for legacy_product, product in PRODUCTS.items():
        try:
            data = call(path(dep["id"], product), token)
        except error_type as exc:
            if getattr(exc, "status", None) == 404 and getattr(exc, "api_code", None) == "PRODUCT_NOT_ENABLED":
                continue
            raise
        result.append({"id": product, "name": f"Unified {product} detection", "productType": legacy_product,
                       "unified": True, "snapshot": snapshot(data, product, error_type)})
    return result


def enabled(bundle: dict, project: str | None, *, same_rule: SameRule) -> set[str]:
    """Only direct rule selections can be resolved without pack expansion or project-tag membership."""
    exceptions = bundle["exceptions"]
    selected = {rule for rule in bundle["rules"]
                if not any(same_rule(rule, disabled) for disabled in bundle["disabled"])}
    if project:
        for item in exceptions:
            if item.get("project") == project and item.get("rule_type") == "rule":
                rule = item["rule"]
                if item.get("exception_type") == "include":
                    selected.add(rule)
                elif item.get("exception_type") == "exclude":
                    selected = {candidate for candidate in selected if not same_rule(candidate, rule)}
    return selected


def check_scope(bundle: dict, project: str | None, rules: list[str], *, same_rule: SameRule, error_type: type[Exception]) -> None:
    """Refuse a mutation whose effect depends on pack or project-tag exceptions (their precedence is not resolvable)."""
    if not isinstance(project, str) or not project.strip():
        raise error_type("Unified detection policy mutation requires an explicit Semgrep project name")
    for item in bundle["exceptions"]:
        relevant = item.get("rule_type") == "pack" or any(same_rule(item.get("rule", ""), rule) for rule in rules)
        if relevant and (item.get("project_tag_name") or
                         (item.get("project") == project and item.get("rule_type") == "pack")):
            raise error_type("Cannot resolve project-tag or pack exception precedence for this Unified tuning")


def _canonical(bundle: dict) -> dict:
    """The bundle with list order and output-only fields removed, for comparing what was sent with what persisted."""
    result = deepcopy(bundle)
    result.pop("deployment_slug", None)  # Output-only; ignored in request bodies.
    for key in POLICY_LISTS:
        result[key] = sorted(result[key], key=lambda value: json.dumps(value, sort_keys=True))
    return result


def _propose(bundle: dict, project: str, original: str, tuned: str, error_type: type[Exception]) -> dict:
    """A copy of the bundle that excludes `original` and includes `tuned` for this project only."""
    candidate = deepcopy(bundle)
    for rule, exception_type in ((original, "exclude"), (tuned, "include")):
        entries = [item for item in candidate["exceptions"]
                   if item.get("project") == project and item.get("rule_type") == "rule" and item.get("rule") == rule]
        if len(entries) > 1:
            raise error_type("Duplicate Unified project rule exceptions; refusing an ambiguous replacement")
        if entries:
            entries[0]["exception_type"] = exception_type
        else:
            candidate["exceptions"].append({"project": project, "rule": rule, "rule_type": "rule", "exception_type": exception_type})
    return candidate


def _dry_run(endpoint: str, token: str, body: dict, state_version: str, *, call: Callable, error_type: type[Exception]) -> str:
    """The state_version to write against, once the server validates the proposal without changes underneath it."""
    preview = call(endpoint + ":dryRun", token, method="POST", body=deepcopy(body))
    if preview.get("validation_errors"):
        raise error_type("Unified detection policy dry run rejected the proposal; no policy was changed")
    if preview.get("state_version") != state_version:
        raise error_type("Unified detection policy changed during dry run; re-read and prepare a new proposal")
    return preview["state_version"]


def _write_and_verify(endpoint: str, token: str, body: dict, if_match: str, product: str, rollback: dict, *,
                      call: Callable, error_type: type[Exception]) -> str:
    """PUT once with If-Match, then read back; returns the persisted state_version. Fills rollback['if_match']."""
    applied = call(endpoint, token, method="PUT", body=deepcopy(body), headers={"If-Match": if_match})
    if not isinstance(applied.get("state_version"), str) or not applied["state_version"]:
        raise error_type("Unified detection policy apply response is missing state_version; verify before rollback")
    rollback["if_match"] = applied["state_version"]
    persisted = snapshot(call(endpoint, token), product, error_type)
    if persisted["state_version"] != applied["state_version"]:
        raise error_type("Unified detection policy changed after apply; no stale write or rollback was replayed")
    if _canonical(persisted["bundle"]) != _canonical(body["bundle"]):
        raise error_type("Unified detection policy persistence verification failed")
    return persisted["state_version"]


def apply(token: str, dep: dict, policy: dict, original: str, tuned: str, project: str, *,
          call: Callable, same_rule: SameRule, error_type: type[Exception]) -> list[dict]:
    """Exclude `original` and include `tuned` for `project`; [] when the bundle already says so, else one change record."""
    before = policy["snapshot"]
    bundle = before["bundle"]
    check_scope(bundle, project, [original, tuned], same_rule=same_rule, error_type=error_type)
    candidate = _propose(bundle, project, original, tuned, error_type)
    if candidate == bundle:
        return []
    endpoint = path(dep["id"], policy["id"])
    body = {"bundle": candidate}
    if_match = _dry_run(endpoint, token, body, before["state_version"], call=call, error_type=error_type)
    rollback = {"path": endpoint, "body": {"bundle": deepcopy(bundle)}, "before_state_version": before["state_version"]}
    try:
        state_version = _write_and_verify(endpoint, token, body, if_match, policy["id"], rollback, call=call, error_type=error_type)
    except error_type as exc:
        exc.rollback = rollback
        raise
    return [{"policy": policy["name"], "policy_id": policy["id"], "original": original, "tuned": tuned,
             "project": project, "mode": "include", "original_mode": "detection",
             "state_version": state_version, "rollback": rollback}]
