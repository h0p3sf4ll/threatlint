"""Deprecated: use `threatlint.integrations.findings_management.defectdojo`."""

from threatlint.integrations.findings_management.defectdojo import *  # noqa: F403
import threatlint.integrations.findings_management.defectdojo as _target

ADAPTER = _target.INTEGRATION


def __getattr__(name: str):
    return getattr(_target, name)
