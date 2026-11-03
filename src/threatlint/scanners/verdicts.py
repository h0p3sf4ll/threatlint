"""Deprecated: use `threatlint.integrations.verdicts`."""

from threatlint.integrations.verdicts import *  # noqa: F403
import threatlint.integrations.verdicts as _target


def __getattr__(name: str):
    return getattr(_target, name)
