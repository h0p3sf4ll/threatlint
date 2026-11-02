"""Dependency-free local checks; public imports remain under threatlint.guard."""

from .cli import (
    HOOK_BLOCKING_SEVERITY as HOOK_BLOCKING_SEVERITY,
    add_guard_parser as add_guard_parser,
    cmd_guard as cmd_guard,
    run_hook as run_hook,
    staged_files as staged_files,
)
from .models import Finding as Finding, Rule as Rule, SEVERITIES as SEVERITIES
from .output import (
    failing as failing,
    to_json as to_json,
    to_sarif as to_sarif,
    to_text as to_text,
)
from .rules import ANY as ANY, RULES as RULES, RULES_BY_ID as RULES_BY_ID
from .scanning import (
    FILE_SUPPRESSION_LINES as FILE_SUPPRESSION_LINES,
    LANGUAGE_EXTENSIONS as LANGUAGE_EXTENSIONS,
    MAX_FILE_BYTES as MAX_FILE_BYTES,
    MAX_LINE_CHARS as MAX_LINE_CHARS,
    SKIP_DIRS as SKIP_DIRS,
    SNIPPET_CHARS as SNIPPET_CHARS,
    SUPPRESS as SUPPRESS,
    SUPPRESS_FILE as SUPPRESS_FILE,
    TEXT_EXTENSIONS as TEXT_EXTENSIONS,
    iter_files as iter_files,
    scan_paths as scan_paths,
    scan_text as scan_text,
)
