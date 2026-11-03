"""Threatlint integrations, grouped by type, with a plugin registry for community extensions.

Integration types (each has its own base class and its own package; types never depend on each other):

  findings-management  Centralized systems of record that aggregate findings from many scanners and track their
                       status (built in: DefectDojo). Base: findings_management.FindingsManagementPlatform.
  scanning             Tools that analyze code themselves and own the issues they raise (built in: SonarQube).
                       Base: scanning.ScanningTool.
  secret-validation    Plugin validators that report whether a detected credential is live (none built in).
                       Base: secret_validation.SecretValidator.

Community integrations are ordinary Python packages that declare an entry point in the `threatlint.integrations`
group; the object it names is an integration instance, an integration class, or a zero-argument factory:

    [project.entry-points."threatlint.integrations"]
    acme-findings = "threatlint_acme:AcmeFindings"

Installed plugins load automatically. Set THREATLINT_DISABLE_PLUGINS=1 to load only the built-ins (CI, audits).
A plugin that fails to load, has an unknown type, or reuses a built-in name or command is skipped with a warning;
it never breaks the CLI. Plugins run with the user's privileges, so install only packages you trust.
See docs/integrations/authoring.md.
"""

from __future__ import annotations

import os
import re
import sys
from functools import lru_cache

from threatlint.integrations.common import Integration, IntegrationError

ENTRY_POINT_GROUP = "threatlint.integrations"
KINDS = {
    "findings-management": "Findings management: centralized systems of record for findings from many tools",
    "scanning": "Scanning tools: analyze code and own the issues they raise",
    "secret-validation": "Secret validation: confirm whether a detected credential is live",
}
_NAME = re.compile(r"[a-z][a-z0-9-]{1,39}")


def plugins_disabled() -> bool:
    return os.environ.get("THREATLINT_DISABLE_PLUGINS", "").strip().lower() in ("1", "true", "yes", "on")


def _builtins() -> list[Integration]:
    from threatlint.integrations.findings_management import defectdojo  # noqa: PLC0415
    from threatlint.integrations.scanning import sonarqube  # noqa: PLC0415
    return [defectdojo.INTEGRATION, sonarqube.INTEGRATION]


def _instantiate(value) -> Integration:
    if isinstance(value, Integration):
        return value
    if isinstance(value, type) and issubclass(value, Integration):
        return value()
    if callable(value):
        result = value()
        if isinstance(result, Integration):
            return result
    raise TypeError("entry point must name an Integration instance, subclass, or factory")


def _warn(message: str) -> None:
    print(f"  ! threatlint plugin skipped: {message}", file=sys.stderr)


def check(integration: Integration, taken_names: set[str], taken_commands: set[str]) -> str:
    """Why this integration cannot be registered ('' when it can)."""
    if integration.kind not in KINDS:
        return f"unknown integration type {integration.kind!r} (expected one of {', '.join(KINDS)})"
    if not _NAME.fullmatch(integration.name or ""):
        return f"name {integration.name!r} must be lowercase letters, digits, and hyphens"
    if not integration.label:
        return f"{integration.name} has no label"
    if integration.name in taken_names:
        return f"name {integration.name!r} is already registered"
    command = getattr(integration, "command", "")
    if command and (not _NAME.fullmatch(command) or command in taken_commands):
        return f"command {command!r} is invalid or already registered"
    return ""


def _plugins():
    from importlib.metadata import entry_points  # noqa: PLC0415
    for entry in entry_points(group=ENTRY_POINT_GROUP):
        distribution = getattr(getattr(entry, "dist", None), "name", "") or entry.value.split(":")[0]
        try:
            integration = _instantiate(entry.load())
        except Exception as exc:  # noqa: BLE001 - a broken plugin must never break the CLI
            _warn(f"{entry.name} ({distribution}): {type(exc).__name__}: {exc}")
            continue
        integration.source = distribution
        yield entry.name, integration


@lru_cache(maxsize=1)
def _all() -> tuple[Integration, ...]:
    registered: list[Integration] = []
    names: set[str] = set()
    commands: set[str] = set()
    for integration in _builtins():
        registered.append(integration)
        names.add(integration.name)
        if getattr(integration, "command", ""):
            commands.add(integration.command)
    if not plugins_disabled():
        for entry_name, integration in _plugins():
            problem = check(integration, names, commands)
            if problem:
                _warn(f"{entry_name} ({integration.source}): {problem}")
                continue
            registered.append(integration)
            names.add(integration.name)
            if getattr(integration, "command", ""):
                commands.add(integration.command)
    return tuple(registered)


def reload() -> None:
    """Forget the cached registry (tests, or after installing a plugin in the same process)."""
    _all.cache_clear()


def integrations(kind: str | None = None) -> list[Integration]:
    if kind is not None and kind not in KINDS:
        raise IntegrationError(f"Unknown integration type {kind!r}")
    return [integration for integration in _all() if kind is None or integration.kind == kind]


def reviewable() -> dict[str, Integration]:
    """CLI command -> integration for every type whose findings can be fetched and resolved."""
    return {integration.command: integration for integration in _all()
            if integration.kind in ("findings-management", "scanning") and getattr(integration, "command", "")}


__all__ = ["ENTRY_POINT_GROUP", "KINDS", "Integration", "IntegrationError", "integrations", "reviewable", "reload", "check"]
