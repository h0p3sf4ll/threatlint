"""AVIT command arguments, authentication prompts, and cleanup/error dispatch."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from threatlint import servicenow as sn
from threatlint.avit_report import ResolveError


def add_resolve_parsers(actions) -> None:
    checkout = actions.add_parser("checkout", help="Clone the repository and branch named in the AVIT (SCM Tool, Organization, Project, Repository, Branch)")
    checkout.add_argument("number", metavar="AVIT")
    checkout.add_argument("--dir", required=True, help="Empty directory to clone into")
    sn.add_avit_arguments(checkout)
    semgrep = actions.add_parser("semgrep", help="Re-run the Semgrep triage for an AVIT already closed as a false positive by Threatlint")
    semgrep.add_argument("number", metavar="AVIT")
    semgrep.add_argument("--line", type=int, help="Flagged line, when the AVIT does not record one (narrows the match to ±3 lines)")
    semgrep.add_argument("--semgrep-deployment", help="Semgrep deployment ID or slug (default: THREATLINT_SEMGREP_DEPLOYMENT, org.json, or the token's only deployment)")
    semgrep.add_argument("--semgrep-rule-hash-id", help="Authoritative ruleHashId for Secrets-product correlation")
    semgrep.add_argument("--report", help="FP report with a **Tuned rule** block: also tune the rule (SAST/Secrets)")
    semgrep.add_argument("--checkout", help="The AVIT checkout, to validate the tuned rule against the flagged file (deleted afterwards)")
    sn.add_avit_arguments(semgrep)
    note = actions.add_parser("note", help="Add a work note to an AVIT without changing its state (e.g. why it could not be reviewed)")
    note.add_argument("number", metavar="AVIT")
    note.add_argument("--message", required=True, help="Work note text")
    note.add_argument("--yes", action="store_true", help="Apply without prompting")
    sn.add_avit_arguments(note)
    removed = actions.add_parser("close-removed", help="Close an AVIT whose repository was deleted (verified first; no report is attached)")
    removed.add_argument("number", metavar="AVIT")
    removed.add_argument("--yes", action="store_true", help="Apply without prompting")
    sn.add_avit_arguments(removed)
    resolve = actions.add_parser("resolve", help="Upload the FP report to the AVIT; close it and tune Semgrep when it is a false positive")
    resolve.add_argument("number", metavar="AVIT")
    resolve.add_argument("--report", required=True, help="FP review report (Markdown) naming the AVIT in Original finding")
    resolve.add_argument("--docx", required=True, help="Word report to attach (the only file attached to the AVIT)")
    resolve.add_argument("--semgrep-deployment", help="Semgrep deployment slug when the token can access several")
    resolve.add_argument("--semgrep-rule-hash-id", help="Authoritative ruleHashId for Secrets-product correlation")
    resolve.add_argument("--skip-semgrep", action="store_true", help="Do not change Semgrep triage or rules")
    resolve.add_argument("--skip-rule-tuning", action="store_true", help="Ignore the Semgrep finding but do not replace the rule")
    resolve.add_argument("--checkout", help="The AVIT checkout (from `avit checkout`); used to validate the tuned rule, then deleted")
    resolve.add_argument("--keep-checkout", action="store_true", help="Do not delete the checkout after resolving")
    resolve.add_argument("--yes", action="store_true", help="Apply without prompting (the caller has confirmed the verdict)")
    sn.add_avit_arguments(resolve)
    fix = actions.add_parser("fix-pr", help="Open a draft Azure DevOps or GitHub pull request for a reviewed AVIT fix")
    fix.add_argument("number", metavar="AVIT")
    fix.add_argument("--report", required=True, help="Reviewed Markdown report containing a Proposed fix patch")
    fix.add_argument("--checkout", required=True, help="Clean checkout of the exact reviewed repository and branch")
    fix.add_argument("--target", required=True, help="JSON repository target emitted by avit checkout")
    fix.add_argument("--yes", action="store_true", help="Create the draft PR without prompting")
    sn.add_avit_arguments(fix)
    from threatlint.dast import add_dast_parser
    add_dast_parser(actions)


def session(args):
    if not args.snow_instance:
        raise ResolveError(f"Set the ServiceNow instance with --snow-instance or {sn.INSTANCE_ENV}")
    instance = sn.validate_instance_url(args.snow_instance)
    client_id, client_secret = sn.resolve_credentials(args.aws_profile)
    return instance, sn.access_token(instance, client_id, client_secret)


def confirm(question: str, yes: bool) -> None:
    if yes:
        return
    if not sys.stdin.isatty():
        raise ResolveError("Confirmation required: rerun with --yes after reviewing the verdict")
    if input(f"{question} [y/N] ").strip().lower() not in ("y", "yes"):
        raise ResolveError("Cancelled; nothing was changed")


def cmd_fix_pr(args) -> int:
    from threatlint.avit_pr import create_fix_pr  # noqa: PLC0415

    [avit] = sn.parse_avit_numbers(args.number)
    try:
        target = json.loads(Path(args.target).read_text(encoding="utf-8"))
    except (ValueError, OSError):
        raise ResolveError("The reviewed repository target could not be read") from None
    if not isinstance(target, dict) or target.get("avit", avit) != avit:
        raise ResolveError("The repository target does not belong to this AVIT")
    report = Path(args.report).read_text(encoding="utf-8")
    confirm(f"{avit}: publish its proposed fix as a draft pull request?", args.yes)
    result = create_fix_pr(avit, report, args.checkout, target, profile=args.aws_profile, instance=args.snow_instance)
    print(json.dumps(result))
    return 0


def run(handler, args, *, remove_checkout) -> int:
    try:
        return handler(args)
    except (ResolveError, sn.ServiceNowError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    finally:
        if getattr(args, "avit_command", "") in ("resolve", "semgrep") and not getattr(args, "keep_checkout", False) and remove_checkout(getattr(args, "checkout", None)):
            print(f"  ✓ Deleted the local checkout {args.checkout}")
