"""threatlint ide — install secure-by-default instructions and guard hooks into a repository.

Every write is idempotent: Markdown sections live between threatlint markers and are
replaced in place, and JSON files are merged without removing existing entries.
"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path
from typing import Callable

_DATA = Path(__file__).parent / "data" / "ide"
BEGIN = "<!-- threatlint:secure-code:begin -->"
END = "<!-- threatlint:secure-code:end -->"
HOOK_COMMAND = "threatlint guard --hook"
HOOK_MATCHER = "Edit|Write|MultiEdit"
HOOK_TIMEOUT_S = 30
EDITORS = ("vscode", "cursor", "claude", "copilot", "windsurf")
PRE_COMMIT_CONFIG = """repos:
  - repo: https://github.com/h0p3sf4ll/threatlint
    rev: v1.0.0
    hooks:
      - id: threatlint-guard
"""


def instructions() -> str:
    return (_DATA / "secure-code-instructions.md").read_text(encoding="utf-8").strip() + "\n"


def _section() -> str:
    return f"{BEGIN}\n{instructions()}{END}\n"


def upsert_section(path: Path) -> str:
    """Insert or replace the marked threatlint section, preserving all other content."""
    path.parent.mkdir(parents=True, exist_ok=True)
    section = _section()
    if not path.exists():
        path.write_text(section, encoding="utf-8")
        return "added"
    text = path.read_text(encoding="utf-8")
    if BEGIN in text and END in text:
        start, end = text.index(BEGIN), text.index(END) + len(END)
        updated = text[:start] + section.rstrip("\n") + text[end:]
    else:
        updated = text.rstrip("\n") + ("\n\n" if text.strip() else "") + section
    if updated == text:
        return "unchanged"
    path.write_text(updated, encoding="utf-8")
    return "updated"


def write_file(path: Path, content: str) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.read_text(encoding="utf-8") == content:
        return "unchanged"
    status = "updated" if path.exists() else "added"
    path.write_text(content, encoding="utf-8")
    return status


def _load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8") or "{}")
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a JSON object")  # noqa: TRY004 — reported to the user as invalid config
    return data


def _write_json(path: Path, before: dict, after: dict) -> str:
    existed = path.exists()
    if existed and before == after:
        return "unchanged"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(after, indent=2) + "\n", encoding="utf-8")
    return "updated" if existed else "added"


def merge_claude_settings(path: Path) -> str:
    before = _load_json(path)
    data = copy.deepcopy(before)
    post = data.setdefault("hooks", {}).setdefault("PostToolUse", [])
    present = any(hook.get("command") == HOOK_COMMAND
                  for entry in post if isinstance(entry, dict)
                  for hook in entry.get("hooks", []) if isinstance(hook, dict))
    if not present:
        post.append({"matcher": HOOK_MATCHER, "hooks": [{"type": "command", "command": HOOK_COMMAND, "timeout": HOOK_TIMEOUT_S}]})
    return _write_json(path, before, data)


# Matches guard's text output so findings appear in the VS Code Problems panel.
GUARD_PROBLEM_MATCHER = {"owner": "threatlint", "fileLocation": "absolute",
                         "pattern": {"regexp": r"^(.+):(\d+):(\d+): (CRITICAL|HIGH|MEDIUM|LOW|INFO) (\S+) (.*)$",
                                     "file": 1, "line": 2, "column": 3, "severity": 4, "code": 5, "message": 6}}
VSCODE_TASKS = [
    {"label": "Threatlint: guard workspace", "type": "shell", "command": "threatlint",
     "args": ["guard", "${workspaceFolder}", "--fail-on", "medium"], "group": "test",
     "problemMatcher": GUARD_PROBLEM_MATCHER},
    {"label": "Threatlint: guard current file", "type": "shell", "command": "threatlint",
     "args": ["guard", "${file}", "--fail-on", "medium"], "problemMatcher": GUARD_PROBLEM_MATCHER},
    {"label": "Threatlint: guard staged changes", "type": "shell", "command": "threatlint",
     "args": ["guard", "--staged"], "problemMatcher": []},
]


def merge_vscode_tasks(path: Path) -> str:
    before = _load_json(path)
    data = copy.deepcopy(before)
    data.setdefault("version", "2.0.0")
    tasks = data.setdefault("tasks", [])
    labels = {task.get("label") for task in tasks if isinstance(task, dict)}
    tasks.extend(task for task in VSCODE_TASKS if task["label"] not in labels)
    return _write_json(path, before, data)


def _copilot_instructions_file() -> str:
    return ('---\napplyTo: "**"\ndescription: Threatlint secure-by-default rules for generated code\n---\n\n'
            + instructions())


def _cursor_rule() -> str:
    return ("---\ndescription: Threatlint secure-by-default rules for generated code\nglobs:\nalwaysApply: true\n---\n\n"
            + instructions())


def install(target: Path, editors: list[str]) -> dict[str, str]:
    """Install into ``target``. Returns {relative path: added|updated|unchanged|skipped}."""
    target = target.resolve()
    results: dict[str, str] = {}

    def record(rel: str, action: Callable[[Path], str]) -> None:
        results[rel] = action(target / rel)

    if "copilot" in editors:
        record(".github/copilot-instructions.md", upsert_section)
        record(".github/instructions/threatlint-secure-code.instructions.md",
               lambda p: write_file(p, _copilot_instructions_file()))
    if "cursor" in editors:
        record(".cursor/rules/threatlint-secure-code.mdc", lambda p: write_file(p, _cursor_rule()))
    if "windsurf" in editors:
        record(".windsurfrules", upsert_section)
    if "claude" in editors:
        record("CLAUDE.md", upsert_section)
        record(".claude/settings.json", merge_claude_settings)
    if "vscode" in editors:
        record(".vscode/tasks.json", merge_vscode_tasks)
    pre_commit = target / ".pre-commit-config.yaml"
    if pre_commit.exists():
        results[".pre-commit-config.yaml"] = ("unchanged" if "threatlint-guard" in pre_commit.read_text(encoding="utf-8")
                                              else "skipped")
    else:
        results[".pre-commit-config.yaml"] = write_file(pre_commit, PRE_COMMIT_CONFIG)
    return results


def cmd_ide(args) -> int:
    if args.ide_command == "instructions":
        sys.stdout.write(instructions())
        return 0
    editors = [item.strip() for item in args.editors.split(",") if item.strip()]
    unknown = sorted(set(editors) - set(EDITORS))
    if unknown:
        print(f"Unknown editor(s): {', '.join(unknown)}. Choose from: {', '.join(EDITORS)}", file=sys.stderr)
        return 2
    target = Path(args.target or ".")
    if not target.is_dir():
        print(f"Target is not a directory: {target}", file=sys.stderr)
        return 2
    try:
        results = install(target, editors)
    except (ValueError, json.JSONDecodeError) as error:
        print(f"threatlint ide install: {error}", file=sys.stderr)
        return 1
    for rel, status in results.items():
        print(f"  {status:9} {rel}")
    if results.get(".pre-commit-config.yaml") == "skipped":
        print("\nAdd this to your existing .pre-commit-config.yaml:\n" + PRE_COMMIT_CONFIG.split("\n", 1)[1])
    print("\nSecure-by-default instructions installed. Generated code is now checked by "
          "`threatlint guard`; see docs/ide.md for the recommended workflow.")
    return 0


def add_ide_parser(sub) -> None:
    p = sub.add_parser("ide", help="Install secure-by-default AI coding instructions and guard hooks")
    ide_sub = p.add_subparsers(dest="ide_command", required=True)
    p_install = ide_sub.add_parser("install", help="Write instructions, hooks, and tasks into a repository")
    p_install.add_argument("--target", metavar="DIR", help="Repository directory (default: current directory)")
    p_install.add_argument("--editors", default=",".join(EDITORS),
                           help=f"Comma-separated subset of: {','.join(EDITORS)} (default: all)")
    ide_sub.add_parser("instructions", help="Print the canonical secure-code instructions")
