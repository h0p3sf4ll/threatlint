"""Scanner adapters: fetch a tool's findings for FP review and write the reviewer's verdict back.

Implemented: DefectDojo (`threatlint dojo …`) and SonarQube / SonarCloud (`threatlint sonar …`). To add another
tool (Checkmarx, Snyk, GitHub code scanning, …), subclass `base.Adapter`, implement its tool-specific methods,
and register an instance here; `scanners.cli` then provides fetch / checkout / resolve / note / login for it.
"""

from __future__ import annotations

from threatlint.scanners.base import Adapter, ScannerError


def registry() -> dict[str, Adapter]:
    from threatlint.scanners import defectdojo, sonarqube  # noqa: PLC0415
    return {adapter.command: adapter for adapter in (defectdojo.ADAPTER, sonarqube.ADAPTER)}


__all__ = ["Adapter", "ScannerError", "registry"]
