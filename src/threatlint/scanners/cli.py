"""`threatlint dojo …` and `threatlint sonar …`: the AVIT commands, for scanner findings.

  fetch    [REF ...] [filters] -o FILE   findings as a Markdown artifact for /fp-review or `run fp-review --findings`
  checkout REF --dir DIR                 clone the finding's repository and branch (and commit, when recorded)
  resolve  REF --report MD [--docx DOCX] act on the FP reviewer's verdict (asks first; --yes to skip)
  note     REF --message TEXT            add a note/comment only (asks first; --yes to skip)
  login    [--url URL]                   check a token against the server and save it to ~/.threatlint (mode 0600)

Every write needs confirmation. Tokens come from the environment, the saved config, or Parameter Store and are
never printed.
"""

from __future__ import annotations

import json
import os
import sys

from threatlint import servicenow as sn
from threatlint.scanners.base import ScannerError, report_line, save_config, saved_config, verdict_for

_DOCX = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"


def _common(parser, adapter) -> None:
    parser.add_argument("--url", default=None, help=f"{adapter.label} base URL (default: {adapter.url_env} or the saved config)")
    parser.add_argument("--aws-profile", metavar="PROFILE", help="AWS CLI profile for a Parameter Store token")


def add_parsers(sub) -> None:
    from threatlint.scanners import registry  # noqa: PLC0415
    for command, adapter in registry().items():
        parser = sub.add_parser(command, help=f"{adapter.label} findings: fetch for FP review, check out, resolve, note")
        actions = parser.add_subparsers(dest="scanner_command", required=True)
        fetch = actions.add_parser("fetch", help=f"Write {adapter.label} findings as a findings file for /fp-review")
        fetch.add_argument("references", nargs="*", metavar="REF", help=f"Finding references, e.g. {adapter.reference_example}")
        adapter.add_filter_arguments(fetch)
        fetch.add_argument("-o", "--output", metavar="FILE", required=True, help="Markdown file to write")
        _common(fetch, adapter)
        checkout = actions.add_parser("checkout", help="Clone the repository and branch the finding names")
        checkout.add_argument("reference", metavar="REF")
        checkout.add_argument("--dir", required=True, help="Empty directory to clone into")
        checkout.add_argument("--repo-url", help="Repository URL when the finding does not record one (GitHub or Azure DevOps)")
        checkout.add_argument("--branch", dest="checkout_branch", help="Branch when the finding does not record one")
        _common(checkout, adapter)
        resolve = actions.add_parser("resolve", help=f"Write the FP reviewer's verdict back to {adapter.label}")
        resolve.add_argument("reference", metavar="REF")
        resolve.add_argument("--report", required=True, help="FP review report (Markdown) naming the finding in Original finding")
        resolve.add_argument("--docx", required=adapter.supports_attachments, help="Word report to attach" if adapter.supports_attachments else "Word report (named in the comment; not uploaded)")
        if not adapter.supports_attachments:
            resolve.add_argument("--report-url", help="Where the full report lives (named in the comment)")
        if adapter.name == "defectdojo":
            resolve.add_argument("--semgrep-deployment", help="Semgrep deployment slug when the token can access several")
            resolve.add_argument("--skip-semgrep", action="store_true", help="Do not change Semgrep triage or rules")
            resolve.add_argument("--skip-rule-tuning", action="store_true", help="Ignore the Semgrep finding but do not replace the rule")
            resolve.add_argument("--checkout", help="The finding's checkout (from `dojo checkout`), to validate a tuned rule; deleted afterwards")
            resolve.add_argument("--keep-checkout", action="store_true", help="Do not delete the checkout after resolving")
        resolve.add_argument("--yes", action="store_true", help="Apply without prompting (the caller has confirmed the verdict)")
        _common(resolve, adapter)
        note = actions.add_parser("note", help="Add a note without changing the finding's status")
        note.add_argument("reference", metavar="REF")
        note.add_argument("--message", required=True, help="Note text")
        note.add_argument("--yes", action="store_true", help="Apply without prompting")
        _common(note, adapter)
        login = actions.add_parser("login", help=f"Check a {adapter.label} token and save it to ~/.threatlint/{adapter.config_file}")
        login.add_argument("--token-stdin", action="store_true", help="Read the token from stdin instead of prompting")
        _common(login, adapter)


def _confirm(question: str, yes: bool) -> None:
    from threatlint.avit_resolve import ResolveError, _confirm as confirm  # noqa: PLC0415
    try:
        confirm(question, yes)
    except ResolveError as exc:
        raise ScannerError(str(exc)) from exc


def cmd_fetch(adapter, args) -> int:
    url, token = adapter.session(args)
    filters = adapter.filters(args)
    if args.references:
        references = adapter.parse_references(args.references)
        print(f"  {adapter.label} : {url} · requesting {len(references)} finding{'s' if len(references) != 1 else ''}")
        items, missing = adapter.fetch(url, token, references)
        description = ""
    else:
        if not {key for key in filters if key != "limit"}:
            raise ScannerError(f"Pass finding references or filters (see `threatlint {adapter.command} fetch --help`)")
        print(f"  {adapter.label} : {url} · searching {', '.join(f'{k}={v}' for k, v in filters.items())}")
        items, missing, references = adapter.search(url, token, filters), [], []
        references = [item["reference"] for item in items]
        description = f"filter {json.dumps(filters, sort_keys=True)} → {len(items)}"
    if not items:
        raise ScannerError(f"No {adapter.label} findings were returned. Check the references, filters, and token permissions.")
    print(f"  Retrieved : {len(items)}" + (f" · not found: {', '.join(missing)}" if missing else ""))
    with open(os.path.expanduser(args.output), "w", encoding="utf-8") as handle:
        handle.write(adapter.markdown(url, items, references, missing, description))
    print(f"✓ {adapter.label} findings written to {args.output}")
    return 0


def _semgrep_kind(item: dict) -> str:
    source = item.get("context", {}).get("finding_source", "").lower()
    return "secrets" if "secret" in source else "sca" if "supply chain" in source or "dependenc" in source else "sast"


def cmd_checkout(adapter, args) -> int:
    from threatlint import avit_resolve as ar  # noqa: PLC0415
    from threatlint.scanners.base import context_from_repository_url  # noqa: PLC0415
    [reference] = adapter.parse_references(args.reference)
    url, token = adapter.session(args)
    item = adapter.get(url, token, reference)
    context = dict(item["context"])
    if args.repo_url:
        override = context_from_repository_url(args.repo_url)
        if not override:
            raise ScannerError("--repo-url must be a GitHub or Azure DevOps repository URL")
        context.update(override)
    if args.checkout_branch:
        context["branch"] = args.checkout_branch
    try:
        target = sn.repository_target(context)
    except sn.ServiceNowError as exc:
        raise ScannerError(f"{reference} names no usable repository ({exc}); pass --repo-url, or triage it from the finding evidence without a checkout") from exc
    print(f"  {reference} : {target['web_url']} · branch {target['branch'] or '(default)'} · {context.get('file_path', 'no file path')}")
    target = ar._checkout_branch(target, args.dir, context.get("file_path", ""))
    commit = context.get("commit", "")
    if commit:
        target["commit"] = commit if _checkout_commit(target, args.dir, commit) else ""
    print(f"✓ Checked out to {args.dir}")
    print(json.dumps({"reference": reference, "kind": _semgrep_kind(item), "checkout": os.path.abspath(args.dir), **target,
                      **{key: value for key, value in context.items() if key in ("file_path", "line", "rule", "finding_source")}}))
    return 0


def _checkout_commit(target: dict, directory: str, commit: str) -> bool:
    """Detach at the recorded commit when it is reachable (fetching just that commit once); warn and keep the branch otherwise."""
    import re  # noqa: PLC0415
    import shutil  # noqa: PLC0415
    import subprocess  # noqa: PLC0415
    git = shutil.which("git")
    if not git or not re.fullmatch(r"[0-9a-fA-F]{7,40}", commit) or not os.path.isdir(os.path.join(directory, ".git")):
        print(f"  ! Commit {commit[:40]} not checked out; reviewing the branch head")
        return False
    from threatlint.tls import tool_env  # noqa: PLC0415
    env = {**tool_env(), "GIT_LFS_SKIP_SMUDGE": "1", **sn._git_auth_env(target["scm"], target.get("organization", ""))}
    run = lambda *argv: subprocess.run([git, "-C", directory, *argv], capture_output=True, text=True, timeout=600, check=False, env=env)
    if run("checkout", "--quiet", "--detach", commit).returncode == 0:
        print(f"  ✓ At commit {commit}")
        return True
    if run("fetch", "--quiet", "--depth", "1", "origin", commit).returncode == 0 and run("checkout", "--quiet", "--detach", commit).returncode == 0:
        print(f"  ✓ At commit {commit}")
        return True
    print(f"  ! Commit {commit} is not reachable; reviewing the branch head")
    return False


def cmd_note(adapter, args) -> int:
    [reference] = adapter.parse_references(args.reference)
    message = args.message.strip()
    if not message or len(message) > 4000:
        raise ScannerError("The note must be 1 to 4000 characters")
    url, token = adapter.session(args)
    item = adapter.get(url, token, reference)
    _confirm(f"{reference}: add the note?", args.yes)
    adapter.note(url, token, item, message)
    print(f"  ✓ Note added to {reference}; status unchanged")
    return 0


def cmd_resolve(adapter, args) -> int:
    [reference] = adapter.parse_references(args.reference)
    with open(os.path.expanduser(args.report), encoding="utf-8") as handle:
        markdown = handle.read()
    verdict = verdict_for(markdown, reference)
    print(f"  {reference} : {verdict['id']} · {verdict['disposition']} ({verdict['confidence'] or 'confidence not stated'}) · {verdict['title']}")
    files = []
    if adapter.supports_attachments:
        with open(os.path.expanduser(args.docx), "rb") as handle:
            files.append((f"{reference}-threatlint-fp-review.docx", handle.read(), _DOCX))
    url, token = adapter.session(args)
    item = adapter.get(url, token, reference)
    _confirm(f"{reference}: {adapter.describe(verdict['disposition'])}?", args.yes)
    result = adapter.resolve(url, token, item, verdict, files=files, args=args)
    if verdict["disposition"] == "FALSE POSITIVE" and adapter.semgrep_applicable(item) and not getattr(args, "skip_semgrep", True):
        _semgrep_step(item, verdict, markdown, args)
    print(json.dumps({key: value for key, value in result.items() if key != "note"}))
    return 0


def _semgrep_step(item: dict, verdict: dict, markdown: str, args) -> None:
    """Ignore the matching Semgrep finding and tune its rule (tuned rules run in monitor mode; enforced in semgrep_platform)."""
    from threatlint import avit_resolve as ar  # noqa: PLC0415
    from threatlint import semgrep_platform as sp  # noqa: PLC0415
    reference, context, kind = item["reference"], dict(item["context"]), _semgrep_kind(item)
    try:
        target = sn.repository_target(context)
        sg_token = ar.semgrep_token(args.aws_profile)
        dep, matches = ar.semgrep_matches(sg_token, kind, target, {**context, "avit": reference}, args.semgrep_deployment, markdown)
    except (ar.ResolveError, sn.ServiceNowError) as exc:
        print(f"  ! Semgrep unchanged: {exc}")
        return
    if not matches:
        print(f"  ! No open Semgrep finding matches {context.get('file_path')}; Semgrep unchanged")
    else:
        for match in matches:
            print(f"    Semgrep #{match['id']} · {match['rule']} · {match['path']}:{match['line'] or '?'} · {match['ref'] or ''}")
        count = ar.semgrep_ignore(sg_token, dep["slug"], kind, [match["id"] for match in matches],
                                  f"Closed by Threatlint as a false positive ({reference}, {verdict['id']}): {verdict['title']}")
        print(f"  ✓ Semgrep ignored {count} finding(s) as false_positive")
    if kind in ("sast", "secrets") and not args.skip_rule_tuning:
        path = context.get("file_path", "")
        target_file = os.path.join(args.checkout, path) if getattr(args, "checkout", None) and path else ""
        line = int(context["line"]) if context.get("line", "").isdigit() else report_line(markdown, reference)
        if not (context.get("rule") and target_file and os.path.exists(target_file)):
            print("  ! Rule not tuned: pass --checkout <checkout> so the tuned rule can be validated against the flagged file")
            return
        try:
            sp.tune_rule(markdown, kind, context["rule"], target_file, line, sg_token, {"id": dep["id"], "slug": dep["slug"]})
        except sp.SemgrepError as exc:
            print(f"  ! Rule not tuned: {exc}")


def cmd_login(adapter, args) -> int:
    url = args.url or adapter.default_url()
    if not url and sys.stdin.isatty():
        url = input(f"{adapter.label} URL: ").strip()
    if not url:
        raise ScannerError(f"Pass --url with the {adapter.label} base URL")
    url = adapter.validate_url(url)
    if args.token_stdin:
        token = sys.stdin.readline().strip()
    else:
        import getpass  # noqa: PLC0415
        token = getpass.getpass(f"{adapter.label} API token: ").strip()
    if not token or len(token) > 400 or any(ch.isspace() for ch in token):
        raise ScannerError("Enter the API token (one line, no spaces)")
    adapter.validate_token(url, token)
    path = save_config(adapter.config_file, {**saved_config(adapter.config_file), "url": url, "token": token})
    print(f"✓ {adapter.label} token accepted and saved to {path} (readable only by you)")
    return 0


def cmd_scanner(args) -> int:
    from threatlint import avit_resolve as ar  # noqa: PLC0415
    from threatlint.scanners import registry  # noqa: PLC0415
    adapter = registry()[args.command]
    handler = {"fetch": cmd_fetch, "checkout": cmd_checkout, "resolve": cmd_resolve, "note": cmd_note, "login": cmd_login}[args.scanner_command]
    try:
        return handler(adapter, args)
    except (ScannerError, sn.ServiceNowError, ar.ResolveError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    finally:
        # The checkout holds a copy of someone else's source (possibly live secrets); never leave it on disk.
        if args.scanner_command == "resolve" and not getattr(args, "keep_checkout", False) and ar.remove_checkout(getattr(args, "checkout", None)):
            print(f"  ✓ Deleted the local checkout {args.checkout}")
