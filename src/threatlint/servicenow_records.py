"""Pure ServiceNow field normalization and AVIT context classification."""

from __future__ import annotations

import re
from collections.abc import Callable

MAX_FIELD_CHARS = 4000
SKIPPED_FIELDS = frozenset({"sys_tags", "sys_mod_count", "sys_domain", "sys_domain_path", "sys_class_name"})
CONTEXT_FIELDS = {
    "scm_tool": ("SCM Tool", ("scmtool", "scm", "sourcecontrol", "scmprovider")),
    "organization": ("Organization Name", ("organizationname", "organisationname", "orgname", "organization", "scmorganization")),
    "project": ("Project Name", ("projectname", "scmproject", "project")),
    "repository": ("Repository", ("repository", "repositoryname", "reponame", "repo")),
    "branch": ("Project Branch", ("projectbranch", "branch", "branchname", "scmbranch")),
    "file_path": ("File Path", ("filepath", "sourcefile", "filename", "file", "location")),
    "finding_source": ("Security Finding Source", ("securityfindingsource", "findingsource", "securitysource")),
    "rule": ("Rule", ("rule", "ruleid", "rulename", "checkid", "policy", "vulnerability")),
    "line": ("Line Number", ("linenumber", "line", "startline")),
}


def field_value(raw, limit: int = MAX_FIELD_CHARS) -> str:
    if isinstance(raw, dict):
        value = raw.get("display_value") or raw.get("value") or ""
    else:
        value = raw if raw is not None else ""
    return str(value).strip()[:limit]


def flatten(record: dict, value_of: Callable = field_value, skipped=SKIPPED_FIELDS) -> dict[str, str]:
    fields = {
        name: value_of(raw) for name, raw in record.items()
        if name not in skipped and not (
            name.startswith("sys_") and name not in ("sys_id", "sys_created_on", "sys_updated_on")
        )
    }
    return {name: value for name, value in fields.items() if value}


def in_code_security_view(item: dict) -> bool:
    """Prefer the evaluated view rule; fall back to the SCM fields only when unknown."""
    if item.get("in_view") is not None:
        return bool(item["in_view"])
    context = item.get("context", {})
    return bool(context.get("scm_tool") and context.get("repository"))


def finding_kind(item: dict) -> str:
    """The Semgrep product selected by the Security Finding Source."""
    source = item.get("context", {}).get("finding_source", "").lower()
    if re.search(r"\bsca\b|supply\s*chain|dependenc|open\s*source", source):
        return "sca"
    if re.search(r"\bsecrets?\b", source):
        return "secrets"
    return "sast"


def normalized(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", re.sub(r"^u_", "", name.lower()))


def avit_context(
    fields: dict[str, str], labels: dict[str, str] | None = None, *,
    context_fields: dict = CONTEXT_FIELDS, normalize: Callable = normalized,
) -> dict[str, str]:
    """Resolve form labels first, then normalized custom and standard column names."""
    by_name = {normalize(name): value for name, value in fields.items()}
    context = {}
    for key, (label, names) in context_fields.items():
        element = (labels or {}).get(label.lower())
        value = fields.get(element, "") if element else ""
        if not value:
            value = next((by_name[name] for name in names if by_name.get(name)), "")
        if value:
            context[key] = value.strip()
    return context
