"""The review verbs every reviewable integration gets, whatever its type.

  fetch    [REF ...] [filters] -o FILE   findings as a Markdown artifact for /fp-review or `run fp-review --findings`
  checkout REF --dir DIR                 clone the finding's repository and branch (and commit, when recorded)
  resolve  REF --report MD [--docx DOCX] act on the FP reviewer's verdict (asks first; --yes to skip)
  note     REF --message TEXT            add a note/comment only (asks first; --yes to skip)
  login    [--url URL]                   check a token against the server and save it to ~/.threatlint (mode 0600)

Type-specific behaviour (attachments, Semgrep triage, report URLs) comes from the integration's own hooks
(`add_resolve_arguments`, `after_resolve`, `cleanup`), so this module never names a tool. Every write needs
confirmation. Tokens come from the environment, the saved config, or Parameter Store and are never printed.
"""

from __future__ import annotations

import json
import os
import sys

from threatlint import servicenow as sn
from threatlint.integrations.common import IntegrationError, save_config, saved_config, verdict_for

_DOCX = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"


def _common(parser, integration) -> None:
    parser.add_argument("--url", default=None, help=f"{integration.label} base URL (default: {integration.url_env} or the saved config)")
    parser.add_argument("--aws-profile", metavar="PROFILE", help="AWS CLI profile for a Parameter Store token")


def add_parsers(sub, integration, *, help_text: str) -> None:
    """Add `threatlint <integration.command> fetch|checkout|resolve|note|login`."""
    parser = sub.add_parser(integration.command, help=help_text)
    parser.set_defaults(integration_handler=cmd_integration, integration=integration)
    actions = parser.add_subparsers(dest="integration_command", required=True)
    fetch = actions.add_parser("fetch", help=f"Write {integration.label} findings as a findings file for /fp-review")
    fetch.add_argument("references", nargs="*", metavar="REF", help=f"Finding references, e.g. {integration.reference_example}")
    integration.add_filter_arguments(fetch)
    fetch.add_argument("-o", "--output", metavar="FILE", required=True, help="Markdown file to write")
    _common(fetch, integration)
    checkout = actions.add_parser("checkout", help="Clone the repository and branch the finding names")
    checkout.add_argument("reference", metavar="REF")
    checkout.add_argument("--dir", required=True, help="Empty directory to clone into")
    checkout.add_argument("--repo-url", help="Repository URL when the finding does not record one (GitHub or Azure DevOps)")
    checkout.add_argument("--branch", dest="checkout_branch", help="Branch when the finding does not record one")
    _common(checkout, integration)
    resolve = actions.add_parser("resolve", help=f"Write the FP reviewer's verdict back to {integration.label}")
    resolve.add_argument("reference", metavar="REF")
    resolve.add_argument("--report", required=True, help="FP review report (Markdown) naming the finding in Original finding")
    integration.add_resolve_arguments(resolve)
    resolve.add_argument("--yes", action="store_true", help="Apply without prompting (the caller has confirmed the verdict)")
    _common(resolve, integration)
    note = actions.add_parser("note", help="Add a note without changing the finding's status")
    note.add_argument("reference", metavar="REF")
    note.add_argument("--message", required=True, help="Note text")
    note.add_argument("--yes", action="store_true", help="Apply without prompting")
    _common(note, integration)
    login = actions.add_parser("login", help=f"Check a {integration.label} token and save it to ~/.threatlint/{integration.config_file}")
    login.add_argument("--token-stdin", action="store_true", help="Read the token from stdin instead of prompting")
    _common(login, integration)


def _confirm(question: str, yes: bool) -> None:
    from threatlint.avit_resolve import ResolveError, _confirm as confirm  # noqa: PLC0415
    try:
        confirm(question, yes)
    except ResolveError as exc:
        raise IntegrationError(str(exc)) from exc


def cmd_fetch(integration, args) -> int:
    url, token = integration.session(args)
    filters = integration.filters(args)
    if args.references:
        references = integration.parse_references(args.references)
        print(f"  {integration.label} : {url} · requesting {len(references)} finding{'s' if len(references) != 1 else ''}")
        items, missing = integration.fetch(url, token, references)
        description = ""
    else:
        if not {key for key in filters if key != "limit"}:
            raise IntegrationError(f"Pass finding references or filters (see `threatlint {integration.command} fetch --help`)")
        print(f"  {integration.label} : {url} · searching {', '.join(f'{k}={v}' for k, v in filters.items())}")
        items, missing, references = integration.search(url, token, filters), [], []
        references = [item["reference"] for item in items]
        description = f"filter {json.dumps(filters, sort_keys=True)} → {len(items)}"
    if not items:
        raise IntegrationError(f"No {integration.label} findings were returned. Check the references, filters, and token permissions.")
    print(f"  Retrieved : {len(items)}" + (f" · not found: {', '.join(missing)}" if missing else ""))
    with open(os.path.expanduser(args.output), "w", encoding="utf-8") as handle:
        handle.write(integration.markdown(url, items, references, missing, description))
    print(f"✓ {integration.label} findings written to {args.output}")
    return 0


def finding_kind(item: dict) -> str:
    """sast, sca, or secrets, from the finding's recorded source."""
    source = item.get("context", {}).get("finding_source", "").lower()
    return "secrets" if "secret" in source else "sca" if "supply chain" in source or "dependenc" in source else "sast"


def cmd_checkout(integration, args) -> int:
    from threatlint import avit_resolve as ar  # noqa: PLC0415
    from threatlint.integrations.common import context_from_repository_url  # noqa: PLC0415
    [reference] = integration.parse_references(args.reference)
    url, token = integration.session(args)
    item = integration.get(url, token, reference)
    context = dict(item["context"])
    if args.repo_url:
        override = context_from_repository_url(args.repo_url)
        if not override:
            raise IntegrationError("--repo-url must be a GitHub or Azure DevOps repository URL")
        context.update(override)
    if args.checkout_branch:
        context["branch"] = args.checkout_branch
    try:
        target = sn.repository_target(context)
    except sn.ServiceNowError as exc:
        raise IntegrationError(f"{reference} names no usable repository ({exc}); pass --repo-url, or triage it from the finding evidence without a checkout") from exc
    print(f"  {reference} : {target['web_url']} · branch {target['branch'] or '(default)'} · {context.get('file_path', 'no file path')}")
    target = ar._checkout_branch(target, args.dir, context.get("file_path", ""))
    commit = context.get("commit", "")
    if commit:
        target["commit"] = commit if _checkout_commit(target, args.dir, commit) else ""
    print(f"✓ Checked out to {args.dir}")
    print(json.dumps({"reference": reference, "kind": finding_kind(item), "checkout": os.path.abspath(args.dir), **target,
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


def cmd_note(integration, args) -> int:
    [reference] = integration.parse_references(args.reference)
    message = args.message.strip()
    if not message or len(message) > 4000:
        raise IntegrationError("The note must be 1 to 4000 characters")
    url, token = integration.session(args)
    item = integration.get(url, token, reference)
    _confirm(f"{reference}: add the note?", args.yes)
    integration.note(url, token, item, message)
    print(f"  ✓ Note added to {reference}; status unchanged")
    return 0


def cmd_resolve(integration, args) -> int:
    [reference] = integration.parse_references(args.reference)
    with open(os.path.expanduser(args.report), encoding="utf-8") as handle:
        markdown = handle.read()
    verdict = verdict_for(markdown, reference)
    print(f"  {reference} : {verdict['id']} · {verdict['disposition']} ({verdict['confidence'] or 'confidence not stated'}) · {verdict['title']}")
    files = []
    if integration.supports_attachments:
        with open(os.path.expanduser(args.docx), "rb") as handle:
            files.append((f"{reference}-threatlint-fp-review.docx", handle.read(), _DOCX))
    url, token = integration.session(args)
    item = integration.get(url, token, reference)
    _confirm(f"{reference}: {integration.describe(verdict['disposition'])}?", args.yes)
    result = integration.resolve(url, token, item, verdict, files=files, args=args)
    integration.after_resolve(item, verdict, markdown, args)
    print(json.dumps({key: value for key, value in result.items() if key != "note"}))
    return 0


def cmd_login(integration, args) -> int:
    url = args.url or integration.default_url()
    if not url and sys.stdin.isatty():
        url = input(f"{integration.label} URL: ").strip()
    if not url:
        raise IntegrationError(f"Pass --url with the {integration.label} base URL")
    url = integration.validate_url(url)
    if args.token_stdin:
        token = sys.stdin.readline().strip()
    else:
        import getpass  # noqa: PLC0415
        token = getpass.getpass(f"{integration.label} API token: ").strip()
    if not token or len(token) > 400 or any(ch.isspace() for ch in token):
        raise IntegrationError("Enter the API token (one line, no spaces)")
    integration.validate_token(url, token)
    path = save_config(integration.config_file, {**saved_config(integration.config_file), "url": url, "token": token})
    print(f"✓ {integration.label} token accepted and saved to {path} (readable only by you)")
    return 0


def cmd_integration(args) -> int:
    from threatlint import avit_resolve as ar  # noqa: PLC0415
    integration = args.integration
    handler = {"fetch": cmd_fetch, "checkout": cmd_checkout, "resolve": cmd_resolve, "note": cmd_note, "login": cmd_login}[args.integration_command]
    try:
        return handler(integration, args)
    except (IntegrationError, sn.ServiceNowError, ar.ResolveError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    finally:
        integration.cleanup(args)
