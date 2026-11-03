"""Deprecated: use `threatlint.integrations.common`."""

from threatlint.integrations.common import *  # noqa: F403
import threatlint.integrations.common as _target

ScannerError = _target.IntegrationError
Adapter = _target.ReviewableIntegration


def __getattr__(name: str):
    return getattr(_target, name)
