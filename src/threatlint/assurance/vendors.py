"""Injectable DAST/MAST vendor hooks: Invicti (web/API) and NowSecure (mobile).

Neither vendor is called by Threatlint. Each is a single injectable hook, mirroring ``redteam.servicenow_stub``:
by default the submission is **stubbed** — it records intent and returns no findings — so the pipeline runs end to
end and reports what it *would* send. A real integration registers a provider with ``set_invicti_provider`` /
``set_nowsecure_provider``, where ``fn(context) -> dict`` performs the submission or scan and returns
``{"reference": str, "findings": [...]}``. Returned findings flow into the gate like any other stage's.
"""

from __future__ import annotations

from collections.abc import Callable

_INVICTI: Callable[[dict], dict] | None = None
_NOWSECURE: Callable[[dict], dict] | None = None


def set_invicti_provider(provider: Callable[[dict], dict] | None) -> None:
    global _INVICTI
    _INVICTI = provider


def set_nowsecure_provider(provider: Callable[[dict], dict] | None) -> None:
    global _NOWSECURE
    _NOWSECURE = provider


def invicti_stubbed() -> bool:
    return _INVICTI is None


def nowsecure_stubbed() -> bool:
    return _NOWSECURE is None


def _submit(provider, vendor: str, context: dict) -> dict:
    if provider is None:
        return {"vendor": vendor, "submitted": False, "reference": None, "findings": [],
                "note": f"{vendor} submission is stubbed; no external call was made"}
    result = provider(context) or {}
    findings = result.get("findings") or []
    return {"vendor": vendor, "submitted": True, "reference": result.get("reference"),
            "findings": findings, "note": result.get("note") or f"Submitted to {vendor}"}


def submit_invicti(context: dict) -> dict:
    """Submit a web/API target to Invicti (stubbed unless a provider is registered)."""
    return _submit(_INVICTI, "Invicti", context)


def submit_nowsecure(context: dict) -> dict:
    """Submit a mobile build to NowSecure (stubbed unless a provider is registered)."""
    return _submit(_NOWSECURE, "NowSecure", context)
