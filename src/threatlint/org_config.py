"""Organization-specific settings: SSO portal, Parameter Store names, and the Semgrep deployment.

Threatlint ships with no organization defaults. Each value comes from its environment variable, then
from ~/.threatlint/org.json (THREATLINT_HOME relocates it), for example:

  {"ssoUrl": "https://sso.example.com/aws",
   "snowClientIdParameter": "/appsec/servicenow/client-id",
   "snowClientSecretParameter": "/appsec/servicenow/client-secret",
   "semgrepTokenParameter": "/appsec/semgrep-token",
   "semgrepDeployment": "12345",
   "dojoTokenParameter": "/appsec/defectdojo-token",
   "sonarTokenParameter": "/appsec/sonarqube-token",
   "scanModel": "claude-opus-5-5",
   "generalModel": "claude-opus-5-5"}

An unset Parameter Store name means that credential is not read from Parameter Store; it is entered with
`threatlint setup`, the matching login command, or the Workbench settings instead.
`bootstrap` can populate metadata from an explicitly selected JSON parameter after AWS sign-in.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

ENV = {
    "orgParameter": "THREATLINT_ORG_PARAMETER",
    "awsRegion": "THREATLINT_AWS_REGION",
    "awsProfile": "THREATLINT_AWS_PROFILE",
    "ssoUrl": "THREATLINT_AWS_SSO_PORTAL_URL",
    "snowInstance": "THREATLINT_SNOW_INSTANCE",
    "snowClientIdParameter": "THREATLINT_SNOW_CLIENT_ID_PARAMETER",
    "snowClientSecretParameter": "THREATLINT_SNOW_CLIENT_SECRET_PARAMETER",
    "semgrepTokenParameter": "THREATLINT_SEMGREP_TOKEN_PARAMETER",
    "semgrepDeployment": "THREATLINT_SEMGREP_DEPLOYMENT",
    "adoPatParameter": "THREATLINT_ADO_PAT_PARAMETER",
    # Parameter Store names of the DefectDojo and SonarQube API tokens (optional; see docs/integrations/).
    "dojoTokenParameter": "THREATLINT_DOJO_TOKEN_PARAMETER",
    "sonarTokenParameter": "THREATLINT_SONAR_TOKEN_PARAMETER",
    # Sidekick (reporting, ownership, bulk closure). A comma-separated list in the environment; a JSON list in org.json.
    "adoOrganizations": "THREATLINT_ADO_ORGANIZATIONS",
    "emailDomain": "THREATLINT_EMAIL_DOMAIN",
    "reportFooter": "THREATLINT_REPORT_FOOTER",
    # Claude model policy (threatlint/models.py): scanning runs and chat/assistance defaults.
    "scanModel": "THREATLINT_SCAN_MODEL",
    "generalModel": "THREATLINT_GENERAL_MODEL",
    # Base directory for repositories cloned during scans (DAST, runtime red team, AVIT triage, rule tuning).
    # Unset means the system temporary location. See runtime_env.repo_store_base().
    "repoStore": "THREATLINT_REPO_STORE",
}


def path() -> Path:
    return Path(os.environ.get("THREATLINT_HOME") or Path.home() / ".threatlint") / "org.json"


def values(key: str) -> list[str]:
    """A list setting: comma-separated in the environment, a JSON list (or comma string) in org.json."""
    if os.environ.get(ENV[key]):
        return [item.strip() for item in os.environ[ENV[key]].split(",") if item.strip()]
    try:
        saved = json.loads(path().read_text(encoding="utf-8")).get(key)
    except (OSError, ValueError, AttributeError):
        return []
    if isinstance(saved, list):
        return [str(item).strip() for item in saved if str(item).strip()]
    return [item.strip() for item in str(saved or "").split(",") if item.strip()]


def value(key: str) -> str:
    if os.environ.get(ENV[key]):
        return os.environ[ENV[key]].strip()
    try:
        saved = json.loads(path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ""
    return str(saved.get(key) or "").strip() if isinstance(saved, dict) else ""


def aws_region() -> str:
    """Region of the organization's Parameter Store, preserving the legacy default."""
    return value("awsRegion") or "us-west-2"


def aws_profile() -> str | None:
    """Configured profile, or None to use the AWS CLI credential chain."""
    return value("awsProfile") or None


def _metadata(payload: object, region: str) -> dict:
    from threatlint.parameter_store import ParameterStoreError, validate_profile, validate_reference, validate_region  # noqa: PLC0415

    if not isinstance(payload, dict) or any(key not in ENV for key in payload):
        raise ParameterStoreError("The organization parameter must be a JSON object containing supported configuration metadata and parameter names only.")
    normalized = {}
    for key, entry in payload.items():
        if key == "adoOrganizations":
            if not isinstance(entry, list) or any(not isinstance(item, str) or not item.strip() for item in entry):
                raise ParameterStoreError("Organization setting adoOrganizations must be a list of nonempty strings.")
            normalized[key] = [item.strip() for item in entry]
            continue
        if not isinstance(entry, str):
            raise ParameterStoreError(f"Organization setting {key} must be a string.")
        normalized[key] = entry.strip()
        if key in ("ssoUrl", "snowInstance") and normalized[key]:
            try:
                parsed = urlsplit(normalized[key])
                valid = (parsed.scheme == "https" and bool(parsed.hostname) and not parsed.username and not parsed.password
                         and not parsed.fragment and not any(char.isspace() for char in normalized[key]))
                _ = parsed.port  # Reject invalid port syntax before saving the metadata.
            except ValueError:
                valid = False
            if not valid:
                raise ParameterStoreError(f"Organization setting {key} must be an HTTPS URL without embedded credentials or a fragment.")
        if key == "awsRegion" and normalized[key]:
            validate_region(normalized[key])
        if key == "awsProfile" and normalized[key]:
            validate_profile(normalized[key])
    for key, entry in normalized.items():
        if key.endswith("Parameter") and entry:
            validate_reference(entry, region=region)
    return normalized


def bootstrap(parameter: str, profile: str | None = None, region: str | None = None) -> Path:
    """Import metadata from one explicitly selected SSM parameter into org.json.

    Credential values are deliberately not part of this schema. Existing nonempty
    local settings override imported defaults; environment variables remain first.
    """
    from threatlint.parameter_store import ParameterStoreError, read_parameter  # noqa: PLC0415

    selected_region = aws_region() if region is None else region
    raw = read_parameter(parameter, profile=profile, region=selected_region)
    try:
        imported = _metadata(json.loads(raw), selected_region)
    except (ValueError, TypeError):
        raise ParameterStoreError("The organization parameter does not contain valid configuration JSON.") from None
    destination = path()
    try:
        existing = json.loads(destination.read_text(encoding="utf-8"))
    except FileNotFoundError:
        existing = {}
    except (OSError, ValueError):
        raise ParameterStoreError("The existing org.json could not be read. Correct it before importing organization settings.") from None
    if not isinstance(existing, dict):
        raise ParameterStoreError("The existing org.json must contain a JSON object. Correct it before importing organization settings.")
    merged = dict(imported)
    for key, entry in existing.items():
        if key not in merged or (entry.strip() if isinstance(entry, str) else entry):
            merged[key] = entry
    merged["orgParameter"] = parameter
    merged["awsRegion"] = selected_region
    if profile is not None:
        merged["awsProfile"] = profile
    return _write_metadata(destination, merged)


def update_metadata(updates: dict) -> Path:
    """Merge validated configuration metadata atomically, preserving other settings."""
    from threatlint.parameter_store import ParameterStoreError  # noqa: PLC0415

    normalized = _metadata(updates, updates.get("awsRegion") or aws_region())
    destination = path()
    try:
        existing = json.loads(destination.read_text(encoding="utf-8"))
    except FileNotFoundError:
        existing = {}
    except (OSError, ValueError):
        raise ParameterStoreError("The existing org.json could not be read. Correct it before saving organization settings.") from None
    if not isinstance(existing, dict):
        raise ParameterStoreError("The existing org.json must contain a JSON object. Correct it before saving organization settings.")
    return _write_metadata(destination, {**existing, **normalized})


def _write_metadata(destination: Path, merged: dict) -> Path:
    from threatlint.parameter_store import ParameterStoreError  # noqa: PLC0415

    temporary = None
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(prefix=".org-", suffix=".tmp", dir=destination.parent)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(merged, handle, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    except OSError:
        raise ParameterStoreError("Organization settings could not be saved to org.json. Check the directory permissions and retry.") from None
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except OSError:
                pass
    return destination
