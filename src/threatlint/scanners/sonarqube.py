"""Deprecated: use `threatlint.integrations.scanning.sonarqube`."""

from threatlint.integrations.scanning.sonarqube import *  # noqa: F403
import threatlint.integrations.scanning.sonarqube as _target

ADAPTER = _target.INTEGRATION


def __getattr__(name: str):
    return getattr(_target, name)
