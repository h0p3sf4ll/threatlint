"""Semgrep policy pagination and conservative original/tuned rule replacement."""

from __future__ import annotations

import urllib.parse

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


def replace_in_policies(token, dep, kind, original_rule, tuned_path, *, call, replace_in, error_type):
    all_policies = call(f"/api/policies/v1/deployments/{dep['id']}", token).get("policies", [])
    for product in products(kind):
        changes = replace_in(token, dep, [p for p in all_policies if p.get("productType") == product], original_rule, tuned_path)
        if changes:
            return changes
    raise error_type(f"No policy runs {original_rule}; nothing to replace (the tuned rule is published but not enabled)")


def replace_in(token, dep, policies, original_rule, tuned_path, *, call, policy_rules, mode):
    changes = []
    for policy in policies:
        rules = policy_rules(str(dep["id"]), str(policy["id"]), token)
        original = [rule for rule in rules if same_rule(str(rule.get("path", "")), original_rule) and rule.get("policyMode") != "MODE_DISABLED"]
        for rule in original:
            base = f"/api/policies/v1/deployments/{dep['id']}/{policy['id']}/rules"
            call(f"{base}/{urllib.parse.quote(tuned_path, safe='.')}", token, method="PUT", body={"policyMode": mode})
            call(f"{base}/{urllib.parse.quote(rule['path'], safe='.')}", token, method="PUT", body={"policyMode": "MODE_DISABLED"})
            changes.append({"policy": policy.get("name"), "policy_id": policy["id"], "original": rule["path"], "tuned": tuned_path, "mode": mode,
                            "original_mode": rule.get("policyMode", "MODE_MONITOR")})
    return changes


def disable_originals(token, dep, kind, original_rule, *, call, policy_rules):
    changes = []
    for policy in call(f"/api/policies/v1/deployments/{dep['id']}", token).get("policies", []):
        if policy.get("productType") not in products(kind):
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


def existing_tuning(token, dep, kind, original_rule, *, call, policy_rules):
    found = []
    for policy in call(f"/api/policies/v1/deployments/{dep['id']}", token).get("policies", []):
        if policy.get("productType") not in products(kind):
            continue
        for rule in policy_rules(str(dep["id"]), str(policy["id"]), token):
            path = str(rule.get("path", ""))
            if tunes(path, original_rule) and rule.get("policyMode") != "MODE_DISABLED":
                found.append({"policy": policy.get("name"), "tuned": path, "mode": rule.get("policyMode")})
    return found
