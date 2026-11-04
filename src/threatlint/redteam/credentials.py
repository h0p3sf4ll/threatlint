"""Optional credential resolution from a credential store named in the codebase configuration.

By default the ephemeral app runs on synthetic credentials (runtime_config), which is safe and needs nothing. When
the user opts in with a credentials config, this resolves the referenced secrets from the named store and merges them
into the application's environment for the run only. Resolved values are treated as sensitive: they are redacted from
the report and evidence, and the no-egress sandbox network prevents them leaving even if the app echoes them.

The config is JSON in or beside the repository:

    { "store": "aws-parameter-store", "secrets": { "STRIPE_KEY": "/app/stripe", "DB_PASSWORD": "/app/db" } }

Only reference-based stores are supported; literal secrets in the config are rejected so secrets never live in a file
Threatlint reads as configuration. The store reader is injectable for testing.
"""

from __future__ import annotations

import json

from threatlint.avit_resolve import ResolveError

SUPPORTED_STORES = ("aws-parameter-store",)


def load_config(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as handle:
            config = json.load(handle)
    except (OSError, ValueError) as exc:
        raise ResolveError(f"Could not read the credentials config {path}: {exc}") from exc
    if not isinstance(config, dict) or config.get("store") not in SUPPORTED_STORES:
        raise ResolveError(f"The credentials config must set \"store\" to one of: {', '.join(SUPPORTED_STORES)}")
    secrets = config.get("secrets")
    if not isinstance(secrets, dict) or not secrets:
        raise ResolveError("The credentials config needs a non-empty \"secrets\" map of ENV_VAR -> store reference")
    for name, reference in secrets.items():
        if not isinstance(reference, str) or not reference.startswith("/"):
            raise ResolveError(f"{name}: a store reference (e.g. /app/key) is required; literal secrets are not allowed in the config")
    return config


def _parameter_reader(profile: str | None):
    from threatlint.integrations.common import read_parameter  # noqa: PLC0415
    return lambda reference: read_parameter(reference, profile)


def resolve(config: dict, profile: str | None = None, *, reader=None) -> dict[str, str]:
    """{ENV_VAR: secret} resolved from the configured store. `reader(reference) -> value` is injectable for tests."""
    read = reader or _parameter_reader(profile)
    resolved = {}
    for name, reference in config["secrets"].items():
        try:
            value = read(reference)
        except Exception as exc:  # noqa: BLE001 - surface a clean, value-free error
            raise ResolveError(f"Could not resolve {name} from {config['store']} ({reference}): {type(exc).__name__}") from exc
        if not isinstance(value, str) or not value:
            raise ResolveError(f"{name}: the store returned an empty value for {reference}")
        resolved[str(name)] = value
    return resolved


def redact_resolved(text: str, values: dict[str, str]) -> str:
    """Replace any resolved credential literal that slipped into output with a placeholder."""
    for value in sorted(set(values.values()), key=len, reverse=True):
        if value:
            text = text.replace(value, "<resolved-credential>")
    return text
