"""Claude model policy: Sonnet for security scanning, Opus for everything else.

SCAN_MODEL is the default for every security analysis run (the appsec-* agents and their slash commands,
review/triage pipelines, FP review, AVIT and scanner batches, DAST review, and CI scan workflows).
GENERAL_MODEL is the default for conversation and assistance (Ask Threatlint, PR chat, auto-fix).

Each default can be overridden by THREATLINT_SCAN_MODEL / THREATLINT_GENERAL_MODEL, then by the
``scanModel`` / ``generalModel`` keys of ~/.threatlint/org.json. An explicit model chosen for a run
(``--model``, a Workbench setting, a workflow input) always wins. The defaults apply only to the
Claude/Anthropic provider; other providers keep their own defaults.

web/lib/model-policy.cjs mirrors these values for the Workbench; tests keep the two in sync.
"""

from __future__ import annotations

from threatlint import org_config

SCAN_MODEL = "claude-sonnet-5-5"
GENERAL_MODEL = "claude-opus-5-5"

SCAN = "scan"
GENERAL = "general"


def scan_model() -> str:
    """The configured scanning model for the Claude provider."""
    return org_config.value("scanModel") or SCAN_MODEL


def general_model() -> str:
    """The configured model for chat, assistance, and other non-scanning work on the Claude provider."""
    return org_config.value("generalModel") or GENERAL_MODEL


def default_model(purpose: str) -> str:
    """Default Claude model for ``purpose`` ('scan' or 'general')."""
    if purpose == SCAN:
        return scan_model()
    if purpose == GENERAL:
        return general_model()
    raise ValueError(f"Unknown model purpose: {purpose}")


def resolve(purpose: str, explicit: str | None = "") -> str:
    """The explicit model when one was chosen, otherwise the policy default for ``purpose``."""
    return (explicit or "").strip() or default_model(purpose)
