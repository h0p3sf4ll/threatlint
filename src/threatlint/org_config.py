"""Organization-specific settings: SSO portal, Parameter Store names, and the Semgrep deployment.

Threatlint ships with no organization defaults. Each value comes from its environment variable, then
from ~/.threatlint/org.json (THREATLINT_HOME relocates it), for example:

  {"ssoUrl": "https://sso.example.com/aws",
   "snowClientIdParameter": "/appsec/servicenow/client-id",
   "snowClientSecretParameter": "/appsec/servicenow/client-secret",
   "semgrepTokenParameter": "/appsec/semgrep-token",
   "semgrepDeployment": "12345",
   "dojoTokenParameter": "/appsec/defectdojo-token",
   "sonarTokenParameter": "/appsec/sonarqube-token"}

An unset Parameter Store name means that credential is not read from Parameter Store; it is entered with
`threatlint setup`, the matching login command, or the Workbench settings instead.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

ENV = {
    "ssoUrl": "THREATLINT_AWS_SSO_PORTAL_URL",
    "snowClientIdParameter": "THREATLINT_SNOW_CLIENT_ID_PARAMETER",
    "snowClientSecretParameter": "THREATLINT_SNOW_CLIENT_SECRET_PARAMETER",
    "semgrepTokenParameter": "THREATLINT_SEMGREP_TOKEN_PARAMETER",
    "semgrepDeployment": "THREATLINT_SEMGREP_DEPLOYMENT",
    # Parameter Store names of the DefectDojo and SonarQube API tokens (optional; see docs/*-integration.md).
    "dojoTokenParameter": "THREATLINT_DOJO_TOKEN_PARAMETER",
    "sonarTokenParameter": "THREATLINT_SONAR_TOKEN_PARAMETER",
    # Sidekick (reporting, ownership, bulk closure). A comma-separated list in the environment; a JSON list in org.json.
    "adoOrganizations": "THREATLINT_ADO_ORGANIZATIONS",
    "emailDomain": "THREATLINT_EMAIL_DOMAIN",
    "reportFooter": "THREATLINT_REPORT_FOOTER",
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
