"""Argument parsing and terminal interaction for ServiceNow AVIT imports."""

from __future__ import annotations

import getpass
import os
import sys


def add_avit_arguments(parser, *, instance_env, saved_config):
    parser.add_argument("--avit", metavar="AVIT", action="append", default=[],
        help="ServiceNow AVIT number to triage (repeatable; comma-separated lists accepted)")
    parser.add_argument("--avit-file", metavar="PATH",
        help="Text file of AVIT numbers, separated by commas, spaces, or newlines")
    parser.add_argument("--snow-instance", metavar="URL", default=os.environ.get(instance_env, "") or saved_config().get("instance", ""),
        help=f"ServiceNow instance URL, e.g. https://<instance>.service-now.com (or set {instance_env}; defaults to the Workbench's saved instance)")
    parser.add_argument("--aws-profile", metavar="PROFILE",
        help="AWS CLI profile with access to the ServiceNow parameters (default: AWS CLI default chain)")


def requested_avits(args, *, parse_numbers, error_type):
    values = list(getattr(args, "avit", None) or [])
    if getattr(args, "avit_file", None):
        try:
            with open(os.path.expanduser(args.avit_file), encoding="utf-8") as handle:
                values.append(handle.read(64 * 1024))
        except OSError as exc:
            raise error_type(f"Cannot read AVIT list: {exc}") from exc
    return parse_numbers(values) if values else []


def prompt_credentials(reason, *, error_type):
    if not sys.stdin.isatty():
        raise reason
    print(str(reason), file=sys.stderr)
    print("\nPaste the values from Parameter Store to continue (input is not saved).", file=sys.stderr)
    client_id = input("ServiceNow client ID: ").strip()
    client_secret = getpass.getpass("ServiceNow client secret: ").strip()
    if not client_id or not client_secret:
        raise error_type("Both the ServiceNow client ID and secret are required")
    return client_id, client_secret


def collect_avits(args, numbers, *, instance_env, validate_instance, resolve_credentials,
                  prompt_credentials, load_avits, error_type):
    if not args.snow_instance:
        raise error_type(f"Set the ServiceNow instance with --snow-instance or {instance_env}")
    instance = validate_instance(args.snow_instance)
    try:
        client_id, client_secret = resolve_credentials(args.aws_profile)
    except error_type as exc:
        client_id, client_secret = prompt_credentials(exc)
    print(f"  ServiceNow : {instance} · requesting {len(numbers)} AVIT{'s' if len(numbers) > 1 else ''}")
    content, count, missing, excluded = load_avits(instance, numbers, client_id, client_secret)
    print(f"  Retrieved  : {count} in scope of {len(numbers)}" + (f" · not found: {', '.join(missing)}" if missing else "")
          + (f" · skipped (not in the CodeSecurity view): {', '.join(excluded)}" if excluded else ""))
    return f"ServiceNow AVITs ({', '.join(numbers)})", content


def add_avit_parser(sub, *, add_arguments):
    p = sub.add_parser("avit", help="Fetch ServiceNow application vulnerable items (AVITs) for FP review")
    actions = p.add_subparsers(dest="avit_command", required=True)
    fetch = actions.add_parser("fetch", help="Write AVITs as a findings file for /fp-review or `run fp-review --findings`")
    fetch.add_argument("numbers", nargs="*", metavar="AVIT", help="AVIT numbers")
    add_arguments(fetch)
    fetch.add_argument("-o", "--output", metavar="FILE", required=True, help="Markdown file to write")
    from threatlint.avit_resolve import add_resolve_parsers
    add_resolve_parsers(actions)


def cmd_avit(args, *, requested_avits, collect_avits, error_type):
    if args.avit_command in ("checkout", "resolve", "semgrep", "note", "close-removed", "dast"):
        from threatlint import avit_resolve
        if args.avit_command == "dast":
            from threatlint.dast import cmd_dast
            return avit_resolve.run(cmd_dast, args)
        handler = {"checkout": avit_resolve.cmd_checkout, "resolve": avit_resolve.cmd_resolve, "semgrep": avit_resolve.cmd_semgrep, "note": avit_resolve.cmd_note, "close-removed": avit_resolve.cmd_close_removed}[args.avit_command]
        return avit_resolve.run(handler, args)
    try:
        args.avit = [*args.numbers, *args.avit]
        numbers = requested_avits(args)
        if not numbers:
            raise error_type("Provide AVIT numbers as arguments, with --avit, or with --avit-file")
        _label, content = collect_avits(args, numbers)
    except error_type as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    with open(os.path.expanduser(args.output), "w", encoding="utf-8") as handle:
        handle.write(content)
    print(f"✓ AVIT findings written to {args.output}")
    return 0
