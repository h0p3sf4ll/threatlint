"""Base class for findings-management platforms.

A findings-management platform is a **system of record**: it aggregates findings that many scanners produced
(Semgrep, Snyk, Trivy, ZAP, …), tracks their status across products and engagements, and keeps evidence. It does
not scan code itself. DefectDojo is the built-in example; ThreadFix, Faraday, Kenna, or ArmorCode would fit here.

What this type adds to `ReviewableIntegration`:
  - the Word report is required and attached first, so a finding is never closed without its evidence;
  - the finding's original scanner is recorded (`finding_source`), so Threatlint can also triage the matching
    finding in that scanner. For Semgrep-sourced findings a FALSE POSITIVE ignores the open Semgrep finding and
    tunes the rule (tuned rules run in monitor mode; enforced in semgrep_platform).

Subclasses implement `attach` plus the `ReviewableIntegration` methods (references, fetch, search, get, resolve,
note, describe, auth_headers, validate_token).
"""

from __future__ import annotations

import os

from threatlint import avit_semgrep, servicenow as sn
from threatlint.integrations.common import IntegrationError, ReviewableIntegration, report_line

KIND = "findings-management"


class FindingsManagementPlatform(ReviewableIntegration):
    kind = KIND
    supports_attachments = True

    def attach(self, url: str, token: str, finding_id, name: str, content: bytes, content_type: str) -> None:
        raise NotImplementedError

    def semgrep_applicable(self, item: dict) -> bool:
        """Whether the platform recorded Semgrep as this finding's original scanner."""
        return "semgrep" in item.get("context", {}).get("finding_source", "").lower()

    # Hooks -------------------------------------------------------------------
    def add_resolve_arguments(self, parser) -> None:
        parser.add_argument("--docx", required=True, help="Word report to attach")
        parser.add_argument("--semgrep-deployment", help="Semgrep deployment slug when the token can access several")
        parser.add_argument("--semgrep-rule-hash-id", help="Authoritative ruleHashId for Secrets-product correlation")
        parser.add_argument("--skip-semgrep", action="store_true", help="Do not change Semgrep triage or rules")
        parser.add_argument("--skip-rule-tuning", action="store_true", help="Ignore the Semgrep finding but do not replace the rule")
        parser.add_argument("--checkout", help=f"The finding's checkout (from `{self.command} checkout`), to validate a tuned rule; deleted afterwards")
        parser.add_argument("--keep-checkout", action="store_true", help="Do not delete the checkout after resolving")

    def after_resolve(self, item: dict, verdict: dict, markdown: str, args) -> None:
        if verdict["disposition"] == "FALSE POSITIVE" and self.semgrep_applicable(item) and not getattr(args, "skip_semgrep", True):
            semgrep_step(item, verdict, markdown, args)

    def cleanup(self, args) -> None:
        # The checkout holds a copy of someone else's source (possibly live secrets); never leave it on disk.
        from threatlint import avit_resolve as ar  # noqa: PLC0415
        if getattr(args, "integration_command", "") == "resolve" and not getattr(args, "keep_checkout", False) \
                and ar.remove_checkout(getattr(args, "checkout", None)):
            print(f"  ✓ Deleted the local checkout {args.checkout}")


def semgrep_step(item: dict, verdict: dict, markdown: str, args) -> None:
    """Ignore the matching Semgrep finding and tune its rule (tuned rules run in monitor mode; enforced in semgrep_platform)."""
    from threatlint import avit_resolve as ar  # noqa: PLC0415
    from threatlint import semgrep_platform as sp  # noqa: PLC0415
    from threatlint.integrations.verbs import finding_kind  # noqa: PLC0415
    reference, context, kind = item["reference"], dict(item["context"]), finding_kind(item)
    if getattr(args, "semgrep_rule_hash_id", None):
        context["rule_hash_id"] = args.semgrep_rule_hash_id
    try:
        target = sn.repository_target(context)
        sg_token = ar.semgrep_token(args.aws_profile)
        dep, matches = ar.semgrep_matches(sg_token, kind, target, {**context, "avit": reference}, args.semgrep_deployment, markdown)
    except (ar.ResolveError, sn.ServiceNowError) as exc:
        raise IntegrationError(f"Semgrep unchanged: {exc}") from exc
    kind = dep.get("product", kind)
    if not matches:
        print(f"  ! No open Semgrep finding matches {context.get('file_path')}; Semgrep unchanged")
    else:
        for match in matches:
            print(f"    Semgrep #{match['id']} · {match['rule']} · {match['path']}:{match['line'] or '?'} · {match['ref'] or ''}")
        try:
            count = ar.ignore_matches(sg_token, dep, kind, matches,
                                      f"Closed by Threatlint as a false positive ({reference}, {verdict['id']}): {verdict['title']}")
        except ar.ResolveError as exc:
            raise IntegrationError(str(exc)) from exc
        print(f"  ✓ Semgrep ignored {count} finding(s) as false_positive")
    if kind in ("sast", "secrets") and not args.skip_rule_tuning:
        path = context.get("file_path", "")
        target_file = os.path.join(args.checkout, path) if getattr(args, "checkout", None) and path else ""
        line = int(context["line"]) if context.get("line", "").isdigit() else report_line(markdown, reference)
        if not (context.get("rule") and target_file and os.path.exists(target_file)):
            print("  ! Rule not tuned: pass --checkout <checkout> so the tuned rule can be validated against the flagged file")
            return
        try:
            sp.tune_rule(markdown, kind, context["rule"], target_file, line, sg_token, {"id": dep["id"], "slug": dep["slug"]},
                         project=avit_semgrep.tuning_project(target, matches))
        except sp.SemgrepError as exc:
            raise IntegrationError(f"Rule not tuned: {exc}") from exc
