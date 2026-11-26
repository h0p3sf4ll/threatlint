"""Validate the source location and Semgrep proposal before AVIT write-back."""

from __future__ import annotations

import re
import tempfile
from pathlib import Path

from . import avit_resolve, avit_semgrep, servicenow as sn
from .avit_report import ResolveError, report_line, safe_error, verdict_for


def guard_fp_rule(item: dict, repo: Path, rule_base: str, report: str, avit: str) -> None:
    """Reject known missing tuning prerequisites before attaching or closing an FP."""
    if not sn.in_code_security_view(item) or sn.finding_kind(item) not in ("sast", "secrets"):
        return
    if not rule_base:
        raise ResolveError("The Semgrep rule source is unavailable; the false-positive AVIT was not changed")
    flagged_location(repo, item["context"], report, avit)
    require_proposal(item["context"], report)


def require_proposal(context: dict, report: str) -> None:
    """Check the exact rule identity and both fixture markers before executing Semgrep."""
    from . import semgrep_rule_text  # noqa: PLC0415

    yaml = semgrep_rule_text.tuned_rule_from_report(report)
    fixtures = semgrep_rule_text.fixtures_from_report(report)
    ids = re.findall(r"(?m)^\s*-\s*id:\s*([\w.-]+)", yaml)
    if len(ids) != 1 or not fixtures:
        raise ResolveError("The report needs one complete tuned rule and its fixtures")
    rule = context.get("rule", "")
    if not rule or ids[0] != f"{rule}.tuned":
        raise ResolveError("The tuned rule ID must equal the AVIT rule ID plus .tuned")
    expected, avoided = semgrep_rule_text.fixture_lines(fixtures, ids[0])
    if not expected or not avoided:
        raise ResolveError("The tuned rule needs true-positive and false-positive fixtures")


def flagged_location(repo: Path, context: dict, report: str, avit: str) -> tuple[Path, int]:
    file_path = context.get("file_path", "")
    root = repo.resolve()
    flagged = (root / file_path).resolve() if file_path else root
    if not file_path or Path(file_path).is_absolute() or not flagged.is_relative_to(root) or not flagged.is_file():
        raise ResolveError("The flagged checkout file is unavailable; the false-positive AVIT was not changed")
    if context.get("line_blocker"):
        raise ResolveError(context["line_blocker"])
    line_text = str(context.get("line", ""))
    line = int(line_text) if line_text.isdigit() else report_line(report, avit, file_path)
    if not line or line < 1:
        raise ResolveError("The flagged source line is unavailable; the false-positive AVIT was not changed")
    with flagged.open(encoding="utf-8", errors="replace") as source:
        if sum(1 for _ in source) < line:
            raise ResolveError("The flagged line is beyond the checkout file; the false-positive AVIT was not changed")
    return flagged, line


def prove_tuned_rule(item: dict, repo: Path, report: str, avit: str, args) -> None:
    """Run Semgrep's local rule proof before ServiceNow can be changed."""
    if not sn.in_code_security_view(item) or sn.finding_kind(item) not in ("sast", "secrets"):
        return
    from . import semgrep_platform as sp, semgrep_rule_text  # noqa: PLC0415

    context = item["context"]
    flagged, line = flagged_location(repo, context, report, avit)
    token = avit_resolve.semgrep_token(args.aws_profile)
    with tempfile.TemporaryDirectory(prefix="threatlint-preflight-") as work:
        checked = sp.validate_tuned_rule(semgrep_rule_text.tuned_rule_from_report(report), context["rule"],
                                         str(flagged), line, semgrep_rule_text.fixtures_from_report(report), token,
                                         work=Path(work))
        if context.get("line_source") == "scanner_snippet" and not checked["reproduced"]:
            confirm_snippet_match(context, flagged, line, token, getattr(args, "semgrep_deployment", None), reproduced=False)


def confirm_snippet_match(context: dict, flagged: Path, line: int, token: str, deployment=None, *, reproduced=None) -> str:
    """Corroborate the unique snippet with the original rule or one exact scanner finding."""
    from . import semgrep_platform as sp

    if not context.get("rule"):
        raise ResolveError("The AVIT has no scanner rule to corroborate the snippet location.")
    if reproduced is None:
        try:
            original = sp.original_rule_yaml(context["rule"], token)
            reproduced = bool(sp.live_rule_matches(original, str(flagged), line))
        except (sp.SemgrepError, OSError):
            reproduced = False
    if reproduced:
        return "checkout"
    target = context if context.get("scm") and context.get("name") else sn.repository_target(context)
    kind = context.get("kind") or sn.finding_kind({"context": context})
    exact = {**context, "line": str(line), "line_source": "scanner_snippet", "branch": target["branch"]}
    dep, matches = avit_resolve.semgrep_matches(token, kind, target, exact, deployment)
    product = dep.get("product", kind)
    rule = context.get("rule_hash_id") if product == "secrets" else context["rule"]
    project = avit_semgrep.project_names(target)[0]
    products = {"secrets", "sast"} if kind == "secrets" else {kind}
    if len(matches) == 1 and rule and product in products:
        match = matches[0]
        if (match.get("project") == project and match.get("ref") == target["branch"] and match.get("product") == product
                and match.get("rule") == rule and match.get("status") in ("open", "ignored")
                and avit_semgrep.same_path(match.get("path"), context["file_path"]) and str(match.get("line")) == str(line)):
            return "semgrep"
    raise ResolveError(f"The original rule did not reproduce at checkout line {line}, and Semgrep did not identify one exact "
                       "finding for the project, branch, rule, file and line. Verify the original scanner location and scan revision.")


def repairable_rule_error(error: Exception) -> bool:
    """A missing or invalid proposal can be repaired; missing source identity cannot."""
    from . import semgrep_platform as sp  # noqa: PLC0415

    if isinstance(error, sp.SemgrepError):
        message = str(error).lower()
        # Only proposal diagnostics can be fixed by revising the report. Identifiers
        # such as "access-token" inside a rule name do not indicate an auth failure.
        return message.startswith(("the tuned rule must contain", "tuned rule is not valid:",
                                   "semgrep could not parse the tuned rule pattern", "the report has no",
                                   "fixtures need at least one", "tuned rule fixtures did not pass:",
                                   "the original rule misses ", "the tuned rule still reports "))
    message = str(error).lower()
    return any(fragment in message for fragment in ("report needs one complete tuned rule", "tuned rule id must",
                                                    "tuned rule needs true-positive"))


def assess_draft(avit: str, report: str, target: dict, args) -> dict:
    """Return Workbench readiness without changing the tracker or Semgrep."""
    from . import semgrep_platform as sp

    disposition = verdict_for(report, avit)["disposition"]
    status, reason = "skipped", ""
    if disposition == "FALSE POSITIVE" and target.get("branch_deleted"):
        status, reason = "blocked", "The AVIT branch was deleted. Its default branch cannot establish this false positive."
    elif disposition == "FALSE POSITIVE" and target.get("code_security", True) and target.get("kind") in ("sast", "secrets"):
        item = {"in_view": True, "context": target}
        repo = Path(args.checkout)
        try:
            if target.get("line_blocker"):
                raise ResolveError(target["line_blocker"])
            base = Path(args.rule_base) if args.rule_base else None
            if not base or not base.is_file():
                raise ResolveError("The Semgrep rule source is unavailable for this project")
            with base.open(encoding="utf-8") as handle:
                label = handle.readline()
                if not label.strip():
                    raise ResolveError("The Semgrep rule source is empty for this project")
            covered = False
            if label.startswith("# Tuning base: live tuned rule "):
                flagged, line = flagged_location(repo, target, report, avit)
                covered = not sp._matches(str(base), str(flagged), line, exact=True)
                if covered and target.get("line_source") == "scanner_snippet":
                    original = sp.original_rule_yaml(target["rule"], avit_resolve.semgrep_token(args.aws_profile))
                    covered = bool(sp.live_rule_matches(original, str(flagged), line))
            if not covered:
                require_proposal(target, report)
                prove_tuned_rule(item, repo, report, avit, args)
            status = "ready"
        except (sp.SemgrepError, ResolveError, sn.ServiceNowError, OSError) as exc:
            status = "refine" if repairable_rule_error(exc) else "blocked"
            reason = safe_error(exc)
    return {"status": status, "reason": reason, "disposition": disposition}
