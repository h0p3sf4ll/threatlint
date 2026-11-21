#!/usr/bin/env python3
"""Trusted workflow-only deterministic fix and draft PR; never interprets issue comments."""

import argparse
import json
import os
import re
import subprocess
from pathlib import Path


def run(args, *, cwd, env=None):
    result = subprocess.run(args, cwd=cwd, env=env, capture_output=True, text=True,
                            timeout=60, check=False, shell=False)
    if result.returncode:
        raise ValueError(f"{args[0]} operation failed; inspect the workflow step without exposing credentials")
    return result.stdout.strip()


def main(argv=None):
    from threatlint.security_scanner.scan import scan_repository
    from threatlint.security_scanner.fixes import RULES, propose_fix, apply_fix
    from threatlint.security_scanner.snapshot import git
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo', required=True)
    parser.add_argument('--repository', required=True)
    parser.add_argument('--base-branch', required=True)
    parser.add_argument('--expected-sha', required=True)
    parser.add_argument('--finding-id', required=True)
    parser.add_argument('--output-dir', required=True)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--auto-apply-debug', action='store_true', help='Compatibility option: explicitly authorize only the DEBUG correction')
    parser.add_argument('--auto-apply-rule', action='append', choices=tuple(RULES), default=[], help='Explicitly authorize this supported rule without per-edit approval')
    args = parser.parse_args(argv)
    if not re.fullmatch(r'[a-f0-9]{40,64}', args.expected_sha):
        raise ValueError('Expected head must be a full commit SHA')
    if not re.fullmatch(r'[a-f0-9]{24}', args.finding_id):
        raise ValueError('Use the exact normalized finding ID from the scanner artifact')
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', args.repository):
        raise ValueError('Invalid repository')
    root = Path(args.repo).resolve()
    run(['git', 'check-ref-format', '--branch', args.base_branch], cwd=root)
    if git(root, 'rev-parse', 'HEAD') != args.expected_sha:
        raise ValueError('Branch head changed; scan the new revision and review a fresh proposal')
    if git(root, 'status', '--porcelain'):
        raise ValueError('CI remediation requires a clean checkout')
    output = Path(args.output_dir).resolve()
    if output == root or root in output.parents:
        raise ValueError('Evidence output must be outside the target checkout')
    output.mkdir(parents=True, exist_ok=True)
    report = scan_repository(str(root))
    plan = propose_fix(report, args.finding_id)
    (output / 'proposal.json').write_text(json.dumps(plan, indent=2), encoding='utf-8')
    rules = list(dict.fromkeys(args.auto_apply_rule + (['TL-DEBUG-ENABLED'] if args.auto_apply_debug else [])))
    if not args.apply and not rules:
        return 0
    result = apply_fix(plan, confirm=args.apply,
                       policy={'autoApply': True, 'rules': rules} if rules else None)
    (output / 'rescan.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    # Only the one validated path may enter the commit. No `git add -A` or project test hooks.
    changed = run(['git', 'diff', '--name-only'], cwd=root).splitlines()
    if changed != [plan['path']]:
        raise ValueError('Unexpected changed paths; refusing to commit')
    run_id = os.environ.get('GITHUB_RUN_ID', '')
    if not run_id.isdigit():
        raise ValueError('This publication path requires a trusted GitHub workflow run')
    branch = 'security-fix/' + run_id
    run(['git', '-c', 'core.hooksPath=/dev/null', 'checkout', '-b', branch], cwd=root)
    run(['git', 'add', '--', plan['path']], cwd=root)
    run(['git', '-c', 'core.hooksPath=/dev/null', '-c', 'user.name=github-actions[bot]',
         '-c', 'user.email=41898282+github-actions[bot]@users.noreply.github.com',
         'commit', '-m', 'fix(security): apply reviewed ' + plan['ruleId'] + ' correction'], cwd=root)
    # GitHub authentication is configured only for the trusted git client, never repository code.
    server = os.environ.get('GITHUB_SERVER_URL', 'https://github.com')
    if not re.fullmatch(r'https://[A-Za-z0-9.-]+', server):
        raise ValueError('Invalid GitHub server')
    git_env = dict(os.environ, GIT_CONFIG_COUNT='2', GIT_CONFIG_KEY_0='credential.helper',
                   GIT_CONFIG_VALUE_0='', GIT_CONFIG_KEY_1='credential.helper',
                   GIT_CONFIG_VALUE_1='!gh auth git-credential')
    remote_head = run(['git', 'ls-remote', server + '/' + args.repository + '.git', 'refs/heads/' + args.base_branch], cwd=root, env=git_env)
    if not remote_head or remote_head.split()[0] != args.expected_sha:
        raise ValueError('Remote base branch changed; refusing to publish a stale correction')
    run(['git', 'push', server + '/' + args.repository + '.git', 'HEAD:refs/heads/' + branch], cwd=root, env=git_env)
    body_file = output / 'pull-request.md'
    body_file.write_text('This draft applies the reviewed deterministic correction for `' + args.finding_id +
                         '` at `' + args.expected_sha + '`.\n\nPython syntax validation and a baseline rescan passed. '
                         'Application tests were not run. Review runtime behavior and run the application checks before merging.\n', encoding='utf-8')
    run(['gh', 'pr', 'create', '--repo', args.repository, '--draft', '--base', args.base_branch, '--head', branch,
         '--title', 'fix(security): apply ' + plan['ruleId'] + ' correction', '--body-file', str(body_file)], cwd=root)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
