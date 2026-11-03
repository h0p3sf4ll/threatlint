"""Semgrep policy pagination and conservative original/tuned rule replacement."""

from __future__ import annotations

import urllib.parse

from threatlint import semgrep_unified as unified

PRODUCT_POLICY = {"sast": "PRODUCT_TYPE_SAST", "secrets": "PRODUCT_TYPE_SECRETS"}
TUNED_MODE = "MODE_MONITOR"


def policy_rules(dep_id: str, policy_id: str, token: str, *, call) -> list[dict]:
    rules, cursor = [], ""
    for _ in range(20):
        query = urllib.parse.urlencode({"limit": 2000, **({"cursor": cursor} if cursor else {})})
        data = call(f"/api/policies/v1/deployments/{dep_id}/{policy_id}/rules?{query}", token)
        rules += data.get("rules", [])
        cursor = data.get("cursor") or ""
        if not cursor:
            break
    return rules


def same_rule(path: str, rule: str) -> bool:
    return path == rule or path.endswith("." + rule) or rule.endswith("." + path)


def products(kind: str) -> list[str]:
    return [PRODUCT_POLICY[kind], *(p for k, p in PRODUCT_POLICY.items() if k != kind)]


def tunes(path: str, original_rule: str) -> bool:
    """Compare the complete rule ID, never only its last segment."""
    path, rule = path.lower(), original_rule.lower().removesuffix(".tuned")
    if not path.endswith(".tuned"):
        return False
    stem = path[:-len(".tuned")]
    return stem == rule or stem.endswith("." + rule)


def policy_reads(token, dep, *, call, error_type):
    """Use legacy policies unless the server explicitly reports their retirement."""
    try:
        return call(f"/api/policies/v1/deployments/{dep['id']}", token).get("policies", [])
    except error_type as exc:
        if getattr(exc, "status", None) != 410:
            raise
    return unified.policies(dep, token, call=call, error_type=error_type)


def replace_in_policies(token, dep, kind, original_rule, tuned_path, *, call, replace_in, error_type,
                        project=None, mode=TUNED_MODE):
    all_policies = policy_reads(token, dep, call=call, error_type=error_type)
    for product in products(kind):
        options = {**({"project": project} if project is not None else {}),
                   **({"mode": mode} if mode != TUNED_MODE else {})}
        changes = replace_in(token, dep, [p for p in all_policies if p.get("productType") == product],
                             original_rule, tuned_path, **options)
        if changes:
            return changes
    raise error_type(f"No directly selected policy rule runs {original_rule}; nothing to replace "
                     "(Unified ruleset membership cannot be inferred)")


def replace_in(token, dep, policies, original_rule, tuned_path, *, call, policy_rules, mode,
               project=None, error_type=RuntimeError):
    changes = []
    for policy in policies:
        if policy.get("unified"):
            bundle = policy["snapshot"]["bundle"]
            unified.check_scope(bundle, project, [original_rule, tuned_path], same_rule=same_rule, error_type=error_type)
            if mode != "include":
                raise error_type("Unified detection policies do not support legacy MODE_MONITOR; "
                                 "explicit mode='include' opts into project-scoped detection only")
            active = unified.enabled(bundle, project, same_rule=same_rule)
            original = [rule for rule in active if same_rule(rule, original_rule)]
            if len(original) > 1:
                raise error_type("Several Unified rules match the original; use its unambiguous full registry path")
            for rule in original:
                changes += unified.apply(token, dep, policy, rule, tuned_path, project,
                                         call=call, same_rule=same_rule, error_type=error_type)
            continue
        if mode not in ("MODE_MONITOR", "MODE_BLOCK", "MODE_COMMENT", "MODE_DISABLED"):
            raise error_type("Legacy policy replacement requires a legacy policy mode, not a Unified include")
        rules = policy_rules(str(dep["id"]), str(policy["id"]), token)
        original = [rule for rule in rules if same_rule(str(rule.get("path", "")), original_rule) and rule.get("policyMode") != "MODE_DISABLED"]
        for rule in original:
            base = f"/api/policies/v1/deployments/{dep['id']}/{policy['id']}/rules"
            call(f"{base}/{urllib.parse.quote(tuned_path, safe='.')}", token, method="PUT", body={"policyMode": mode})
            call(f"{base}/{urllib.parse.quote(rule['path'], safe='.')}", token, method="PUT", body={"policyMode": "MODE_DISABLED"})
            changes.append({"policy": policy.get("name"), "policy_id": policy["id"], "original": rule["path"], "tuned": tuned_path, "mode": mode,
                            "original_mode": rule.get("policyMode", "MODE_MONITOR")})
    return changes


def disable_originals(token, dep, kind, original_rule, *, call, policy_rules, project=None, error_type=RuntimeError):
    changes = []
    for policy in policy_reads(token, dep, call=call, error_type=error_type):
        if policy.get("productType") not in products(kind):
            continue
        if policy.get("unified"):
            bundle = policy["snapshot"]["bundle"]
            unified.check_scope(bundle, project, [original_rule], same_rule=same_rule, error_type=error_type)
            active = unified.enabled(bundle, project, same_rule=same_rule)
            tuned = sorted(rule for rule in active if tunes(rule, original_rule))
            if not tuned:
                continue
            unified.check_scope(bundle, project, [*tuned, original_rule], same_rule=same_rule, error_type=error_type)
            originals = [rule for rule in active if same_rule(rule, original_rule)]
            if len(originals) > 1 or len(tuned) > 1:
                raise error_type("Several Unified rules match this tuning; resolve the ambiguity before mutation")
            if not originals and bundle["rulesets"] and not any(same_rule(rule, original_rule) for rule in bundle["disabled"]) and not any(
                item.get("project") == project and item.get("rule_type") == "rule" and
                item.get("exception_type") == "exclude" and same_rule(item.get("rule", ""), original_rule)
                for item in bundle["exceptions"]
            ):
                originals = [original_rule]
            for rule in originals:
                changes += unified.apply(token, dep, policy, rule, tuned[0], project,
                                         call=call, same_rule=same_rule, error_type=error_type)
            continue
        rules = policy_rules(str(dep["id"]), str(policy["id"]), token)
        if not any(tunes(str(rule.get("path", "")), original_rule) and rule.get("policyMode") != "MODE_DISABLED" for rule in rules):
            continue
        for rule in rules:
            path = str(rule.get("path", ""))
            if not path.endswith(".tuned") and same_rule(path, original_rule) and rule.get("policyMode") != "MODE_DISABLED":
                call(f"/api/policies/v1/deployments/{dep['id']}/{policy['id']}/rules/{urllib.parse.quote(path, safe='.')}", token,
                     method="PUT", body={"policyMode": "MODE_DISABLED"})
                changes.append({"policy": policy.get("name"), "original": path, "mode": rule.get("policyMode")})
    return changes


def existing_tuning(token, dep, kind, original_rule, *, call, policy_rules, project=None, error_type=RuntimeError):
    found = []
    for policy in policy_reads(token, dep, call=call, error_type=error_type):
        if policy.get("productType") not in products(kind):
            continue
        if policy.get("unified"):
            bundle = policy["snapshot"]["bundle"]
            active = unified.enabled(bundle, project, same_rule=same_rule)
            for rule in sorted(active):
                if tunes(rule, original_rule):
                    if project:
                        unified.check_scope(bundle, project, [rule], same_rule=same_rule, error_type=error_type)
                    found.append({"policy": policy["name"], "policy_id": policy["id"], "tuned": rule,
                                  "mode": "include", "project": project, "unified": True})
            continue
        for rule in policy_rules(str(dep["id"]), str(policy["id"]), token):
            path = str(rule.get("path", ""))
            if tunes(path, original_rule) and rule.get("policyMode") != "MODE_DISABLED":
                found.append({"policy": policy.get("name"), "tuned": path, "mode": rule.get("policyMode")})
    return found
