"""Semgrep account setup prompts, argument parsing, and command dispatch."""

from __future__ import annotations

import getpass
import sys
from pathlib import Path


def login(token, deployment_slug, from_stdin, profile, *, parameter_token, parameter_name,
          deployment, save_token, token_pattern, error_type):
    if from_stdin:
        token = sys.stdin.readline().strip()
    if not token:
        token = parameter_token(profile)
        if token:
            print(f"  Read the Semgrep token from Parameter Store {parameter_name()}.")
    if not token:
        if not sys.stdin.isatty():
            raise error_type("No terminal to prompt for the Semgrep token; pipe it with --token-stdin")
        print("Create a Web API token in Semgrep AppSec Platform → Settings → Tokens.")
        token = getpass.getpass("Semgrep API token (input hidden): ").strip()
    if not token_pattern.fullmatch(token):
        raise error_type("That does not look like a Semgrep API token")
    dep = deployment(token, deployment_slug)
    where = save_token(token, str(dep.get("id", "")))
    return f"{where} (deployment {dep.get('name') or dep.get('slug')})"


def add_semgrep_parser(sub, *, products):
    p = sub.add_parser("semgrep", help="Set up the Semgrep AppSec Platform API token")
    actions = p.add_subparsers(dest="semgrep_command", required=True)
    login_parser = actions.add_parser("login", help="Validate and save the Semgrep API token")
    login_parser.add_argument("--token-stdin", action="store_true", help="Read the token from standard input")
    login_parser.add_argument("--deployment", default="", help="Deployment slug when the token can access several")
    login_parser.add_argument("--aws-profile", help="Read the token from Parameter Store with this AWS profile first")
    actions.add_parser("status", help="Show where the token comes from (never prints it)")
    base = actions.add_parser("rule-base", help="Write the rule a false-positive tuning should start from (live tuned rule, else the original)")
    base.add_argument("rule", help="Semgrep rule ID from the AVIT")
    base.add_argument("--kind", choices=sorted(products), required=True)
    base.add_argument("-o", "--output", required=True, help="File to write the rule YAML to")
    base.add_argument("--aws-profile")
    actions.add_parser("logout", help="Remove the saved token")


def logout(*, keyring, store_path, service):
    if keyring:
        try:
            keyring.delete_password(service, "token")
        except Exception:
            pass
    store_path.unlink(missing_ok=True)
    print("✓ Saved Semgrep token removed")


def cmd_semgrep(args, *, login, resolve_token, rule_base, deployment, logout, error_type):
    try:
        if args.semgrep_command == "login":
            print(f"✓ Semgrep token validated and saved to {login('', args.deployment, args.token_stdin, args.aws_profile)}")
        elif args.semgrep_command == "rule-base":
            token = resolve_token(args.aws_profile)[0]
            yaml_text, label = rule_base(args.rule, args.kind, token, deployment(token))
            Path(args.output).write_text(f"# Tuning base: {label}\n{yaml_text}", encoding="utf-8")
            print(f"✓ Wrote the {label} to {args.output}")
        elif args.semgrep_command == "status":
            try:
                _token, source = resolve_token()
                print(f"Semgrep token: {source}")
            except error_type as exc:
                print(str(exc))
        else:
            logout()
        return 0
    except (error_type, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
