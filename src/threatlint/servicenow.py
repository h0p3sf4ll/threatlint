"""ServiceNow Application Vulnerable Item (AVIT) import for findings triage.

The ServiceNow OAuth client is stored in AWS Systems Manager Parameter Store. Access is granted
through your organization's single sign-on; this module reads the parameters with the caller's existing AWS CLI
credentials and never stores them. Retrieved AVITs become an untrusted findings artifact for the
FP reviewer, in the same form as an attached SARIF or Markdown file.
"""

from __future__ import annotations

import base64
import datetime
import json
import os
import re
import shutil
import subprocess
import urllib.error
import urllib.parse
import urllib.request

from threatlint import servicenow_checkout, servicenow_cli, servicenow_markdown, servicenow_records
from threatlint import servicenow_credentials
from threatlint.servicenow_credentials import client_parameters, saved_config
from threatlint.servicenow_checkout import _ADO_NAME, _ADO_ORG, _BRANCH, _GH_NAME
from threatlint.servicenow_checkout import run_tool as _run_tool
from threatlint.servicenow_records import finding_kind, in_code_security_view, normalized as _normalized

PARAMETER_STORE_URL = "https://us-west-2.console.aws.amazon.com/systems-manager/parameters/?region=us-west-2&tab=Table"
AWS_REGION = "us-west-2"
INSTANCE_ENV = "THREATLINT_SNOW_INSTANCE"
CLIENT_ID_ENV = "THREATLINT_SNOW_CLIENT_ID"
CLIENT_SECRET_ENV = "THREATLINT_SNOW_CLIENT_SECRET"
ALLOWED_HOSTS_ENV = "THREATLINT_SNOW_ALLOWED_HOSTS"
SERVICENOW_DOMAINS = (".service-now.com", ".servicenowservices.com")

AVIT_TABLE = "sn_vul_app_vulnerable_item"
# AVIT numbers per ServiceNow numberIN query. Not a review limit: longer lists are fetched in several queries.
AVIT_QUERY_CHUNK = 50


def _chunks(values: list[str], size: int = AVIT_QUERY_CHUNK) -> list[list[str]]:
    return [values[index:index + size] for index in range(0, len(values), size)]
# AVIT numbers are "AVIT" plus 7 to 15 digits: AVIT000000095938462 (CodeSecurity) or AVIT0042599 (other tools/views).
_AVIT_PATTERN = re.compile(r"AVIT\d{7,15}")
AVIT_EXAMPLE = "AVIT000000095938462"
_HTTP_TIMEOUT_S = 120
_AWS_TIMEOUT_S = 60
_MAX_FIELD_CHARS = servicenow_records.MAX_FIELD_CHARS
_INLINE_LIMIT = servicenow_markdown.INLINE_LIMIT
# Reference fields worth following for finding context (the vulnerability definition and rule).
_FOLLOW_REFERENCES = ("vulnerability",)
_LEADING_FIELDS = servicenow_markdown.LEADING_FIELDS
# Only AVITs shown in AVR's CodeSecurity form view are triaged. Their Security Finding Source (SAST,
# SCA, or Secrets) does not affect scope; it only selects the Semgrep product to tune.
VIEW_ENV = "THREATLINT_SNOW_VIEW"
DEFAULT_VIEW = "CodeSecurity"
# AVIT form labels and the column names they commonly have (custom columns carry a u_ prefix).
_CONTEXT_FIELDS = servicenow_records.CONTEXT_FIELDS
_LABEL_TABLES = ("sn_vul_app_vulnerable_item", "sn_vul_app_vul_entry", "sn_vul_entry", "task")
_SKIPPED_FIELDS = servicenow_records.SKIPPED_FIELDS

def access_help() -> str:
    return servicenow_credentials.access_help(
        client_parameters=client_parameters, region=AWS_REGION, console_url=PARAMETER_STORE_URL,
    )


class ServiceNowError(RuntimeError):
    """A user-actionable failure; messages never contain credential values."""


def parse_avit_numbers(values) -> list[str]:
    """Normalize comma/space/newline separated AVIT numbers, preserving order and removing duplicates."""
    text = " ".join(values) if isinstance(values, (list, tuple)) else str(values or "")
    tokens = [token for token in re.split(r"[\s,;]+", text.upper()) if token]
    invalid = [token for token in tokens if not _AVIT_PATTERN.fullmatch(token)]
    if invalid:
        raise ServiceNowError(f"Not an AVIT number: {', '.join(invalid[:5])} (expected AVIT followed by 7 to 15 digits, e.g. {AVIT_EXAMPLE} or AVIT0042599)")
    numbers = list(dict.fromkeys(tokens))
    if not numbers:
        raise ServiceNowError("Enter at least one AVIT number")
    return numbers


def validate_instance_url(value: str) -> str:
    """HTTPS origin of the ServiceNow instance, without credentials, path, or query."""
    try:
        url = urllib.parse.urlsplit((value or "").strip())
    except ValueError as exc:
        raise ServiceNowError("Invalid ServiceNow instance URL") from exc
    if url.scheme != "https" or not url.hostname or url.username or url.password or url.query or url.fragment or url.path not in ("", "/"):
        raise ServiceNowError("Use the HTTPS ServiceNow instance URL, e.g. https://<instance>.service-now.com")
    # The OAuth client secret is sent to this host, so only ServiceNow-hosted or explicitly allowed hosts qualify.
    host = url.hostname.lower()
    extra = {item.strip().lower() for item in os.environ.get(ALLOWED_HOSTS_ENV, "").split(",") if item.strip()}
    if host not in extra and not host.endswith(SERVICENOW_DOMAINS):
        raise ServiceNowError(f"{host} is not a ServiceNow host. Add custom instance domains to {ALLOWED_HOSTS_ENV}.")
    return f"https://{host}" + (f":{url.port}" if url.port and url.port != 443 else "")


def read_parameter_store(profile: str | None = None) -> tuple[str, str]:
    """Client ID and secret from Parameter Store via the AWS CLI and the caller's own credentials."""
    return servicenow_credentials.read_parameter_store(
        profile, client_parameters=client_parameters, access_help=access_help,
        region=AWS_REGION, timeout=_AWS_TIMEOUT_S, error_type=ServiceNowError,
    )


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """urllib forwards Authorization on redirect; credentials must reach only the validated instance."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _opener():
    from threatlint.tls import ssl_context  # noqa: PLC0415
    return urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=ssl_context()))


_OPENER = _opener()


def _request_json(url: str, *, data: bytes | None = None, headers: dict[str, str], method: str | None = None) -> dict:
    request = urllib.request.Request(url, data=data, headers={"Accept": "application/json", **headers}, method=method)
    try:
        with _OPENER.open(request, timeout=_HTTP_TIMEOUT_S) as response:  # noqa: S310 - HTTPS origin validated
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        hint = {401: " Check the client ID and secret.", 403: " The OAuth client may not read the AVIT table.",
                302: " The instance redirected (likely an SSO page); use the instance's direct URL."}.get(exc.code, "")
        raise ServiceNowError(f"ServiceNow returned HTTP {exc.code}.{hint}") from exc
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        raise ServiceNowError(f"ServiceNow request failed: {exc}") from exc


def access_token(instance: str, client_id: str, client_secret: str) -> str:
    """OAuth 2.0 client-credentials token for the instance."""
    body = urllib.parse.urlencode({"grant_type": "client_credentials", "client_id": client_id,
                                   "client_secret": client_secret}).encode()
    payload = _request_json(f"{instance}/oauth_token.do", data=body,
                            headers={"Content-Type": "application/x-www-form-urlencoded"})
    token = payload.get("access_token")
    if not isinstance(token, str) or not token:
        raise ServiceNowError("ServiceNow did not issue an access token (client-credentials grant may be disabled)")
    return token


def _field_value(raw) -> str:
    return servicenow_records.field_value(raw, _MAX_FIELD_CHARS)


def _flatten(record: dict) -> dict[str, str]:
    return servicenow_records.flatten(record, _field_value, _SKIPPED_FIELDS)


def _reference_url(instance: str, raw) -> str | None:
    """A referenced record's Table API link, only when it points back to the same instance."""
    link = raw.get("link") if isinstance(raw, dict) else None
    if not isinstance(link, str):
        return None
    url = urllib.parse.urlsplit(link)
    origin = f"{url.scheme}://{(url.hostname or '').lower()}" + (f":{url.port}" if url.port and url.port != 443 else "")
    if origin != instance or not url.path.startswith("/api/now/table/"):
        return None
    return f"{instance}{url.path}?sysparm_display_value=true&sysparm_exclude_reference_link=true"


def view_name() -> str:
    name = os.environ.get(VIEW_ENV, DEFAULT_VIEW).strip()
    if not re.fullmatch(r"[\w .-]{1,80}", name):
        raise ServiceNowError(f"{VIEW_ENV} is not a valid view name")
    return name


def view_members(instance: str, token: str, numbers: list[str]) -> set[str] | None:
    """AVIT numbers the CodeSecurity view rule selects, evaluated by ServiceNow; None when no rule is readable."""
    headers = {"Authorization": f"Bearer {token}"}
    query = urllib.parse.urlencode({"sysparm_query": f"table={AVIT_TABLE}^view.name={view_name()}^active=true",
                                    "sysparm_fields": "condition", "sysparm_limit": "20"})
    try:
        rules = _request_json(f"{instance}/api/now/table/sysrule_view?{query}", headers=headers).get("result", [])
    except ServiceNowError:
        return None
    conditions = [str(rule.get("condition", "")).strip() for rule in rules if isinstance(rule, dict) and str(rule.get("condition", "")).strip()]
    if not conditions:
        return None
    members: set[str] = set()
    for condition in conditions:
        for chunk in _chunks(numbers):
            query = urllib.parse.urlencode({"sysparm_query": f"numberIN{','.join(chunk)}^{condition}", "sysparm_fields": "number", "sysparm_limit": str(len(chunk))})
            rows = _request_json(f"{instance}/api/now/table/{AVIT_TABLE}?{query}", headers=headers).get("result", [])
            members |= {_field_value(row.get("number")) for row in rows if isinstance(row, dict)}
    return members


# Kept for callers that ask whether an AVIT is in scope.
is_code_security = in_code_security_view


def field_labels(instance: str, token: str) -> dict[str, str]:
    """Column name for each AVIT form label, from sys_documentation; empty when the client cannot read it."""
    labels = [label for label, _names in _CONTEXT_FIELDS.values()]
    query = urllib.parse.urlencode({"sysparm_query": f"nameIN{','.join(_LABEL_TABLES)}^language=en^labelIN{','.join(labels)}",
                                    "sysparm_fields": "name,element,label", "sysparm_limit": "200"})
    try:
        rows = _request_json(f"{instance}/api/now/table/sys_documentation?{query}", headers={"Authorization": f"Bearer {token}"}).get("result", [])
    except ServiceNowError:
        return {}
    rows = sorted((row for row in rows if isinstance(row, dict)), key=lambda row: _LABEL_TABLES.index(row.get("name")) if row.get("name") in _LABEL_TABLES else 99)
    found: dict[str, str] = {}
    for row in rows:
        found.setdefault(str(row.get("label", "")).strip().lower(), str(row.get("element", "")))
    return found


def avit_context(fields: dict[str, str], labels: dict[str, str] | None = None) -> dict[str, str]:
    """SCM, repository, branch, file, rule, and finding source, by form label first and column name second."""
    return servicenow_records.avit_context(fields, labels, context_fields=_CONTEXT_FIELDS, normalize=_normalized)


def fetch_avits(instance: str, token: str, numbers: list[str]) -> tuple[list[dict], list[str], list[str]]:
    """CodeSecurity-view AVIT records with references and repository context, numbers not found, and out-of-scope numbers."""
    headers = {"Authorization": f"Bearer {token}"}
    rows: list = []
    for chunk in _chunks(numbers):
        query = urllib.parse.urlencode({"sysparm_query": f"numberIN{','.join(chunk)}", "sysparm_display_value": "all",
                                        "sysparm_limit": str(len(chunk))})
        result = _request_json(f"{instance}/api/now/table/{AVIT_TABLE}?{query}", headers=headers).get("result", [])
        rows += result if isinstance(result, list) else []
    labels = field_labels(instance, token) if rows else {}
    items = []
    for row in rows if isinstance(rows, list) else []:
        item = {"fields": _flatten(row), "references": {}}
        item["context"] = avit_context(item["fields"], labels)
        for name in _FOLLOW_REFERENCES:
            url = _reference_url(instance, row.get(name))
            if url:
                result = _request_json(url, headers=headers).get("result")
                if isinstance(result, dict):
                    item["references"][name] = _flatten(result)
        items.append(item)
    order = {number: index for index, number in enumerate(numbers)}
    items.sort(key=lambda item: order.get(item["fields"].get("number", ""), len(order)))
    members = view_members(instance, token, numbers) if items else None
    for item in items:
        item["in_view"] = None if members is None else item["fields"].get("number") in members
    found = {item["fields"].get("number") for item in items}
    # Every AVIT is triaged. The CodeSecurity view only decides whether Semgrep is involved.
    for item in items:
        item["view"] = "CodeSecurity" if is_code_security(item) else "Other"
    return items, [number for number in numbers if number not in found], []


def _ordered(fields: dict[str, str]) -> list[tuple[str, str]]:
    return servicenow_markdown.ordered(fields, _LEADING_FIELDS)


def _field_lines(fields: dict[str, str]) -> list[str]:
    return servicenow_markdown.field_lines(fields, order=_ordered, inline_limit=_INLINE_LIMIT)


def avits_markdown(instance: str, items: list[dict], requested: list[str], missing: list[str], excluded: list[str] | None = None) -> str:
    """The AVITs as one findings artifact; each AVIT is one finding to triage."""
    retrieved = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return servicenow_markdown.avits_markdown(
        instance, items, requested, missing, excluded, retrieved=retrieved, table=AVIT_TABLE,
        render_context=_context_lines, render_fields=_field_lines,
    )


def _context_lines(item: dict) -> list[str]:
    """What to review: repository, branch, file, and rule from the AVIT, or its own evidence for other tools."""
    return servicenow_markdown.context_lines(
        item, finding_kind=finding_kind, repository_target=repository_target, error_type=ServiceNowError,
    )


# ── Repository targets ────────────────────────────────────────────────────────

def repository_target(context: dict[str, str]) -> dict[str, str]:
    """Clone/web URL and branch for the AVIT's SCM tool (Azure DevOps or GitHub)."""
    return servicenow_checkout.repository_target(context, error_type=ServiceNowError)


def git_credential(scm: str, organization: str = "") -> tuple[str, str]:
    """(Authorization header value, source) for one clone; ('', '') means fall back to git's own credential helper.

    Azure DevOps uses the PAT saved for the clone's organization; an organization with none uses the `az login`
    token (which spans every organization the user can reach) when one is available."""
    return servicenow_checkout.git_credential(scm, organization, run_tool=_run_tool)


def _git_auth_env(scm: str, organization: str = "") -> dict[str, str]:
    """Credentials as GIT_CONFIG_* variables, kept out of argv and .git/config."""
    header, _source = git_credential(scm, organization)
    if not header:
        return {}
    host = "https://dev.azure.com/" if scm == "azure-devops" else "https://github.com/"
    return {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": f"http.{host}.extraHeader", "GIT_CONFIG_VALUE_0": f"Authorization: {header}", "GIT_TERMINAL_PROMPT": "0"}


_CLONE_TIMEOUT_S = int(os.environ.get("THREATLINT_CLONE_TIMEOUT", "600"))


def _sparse_clone(git: str, target: dict[str, str], directory: str, file_path: str, env: dict[str, str]) -> subprocess.CompletedProcess:
    """Blobless, depth-1 clone that checks out only the flagged file's directory (for very large repositories)."""
    return servicenow_checkout.sparse_clone(git, target, directory, file_path, env, error_type=ServiceNowError)


def _ado_folder_download(target: dict[str, str], directory: str, file_path: str) -> None:
    """Fetch only the flagged file's folder (one level) through the Azure DevOps Items API, for repositories too
    large to clone. The result is a plain directory with no .git; only the files the review needs are present."""
    servicenow_checkout.ado_folder_download(
        target, directory, file_path, git_credential=git_credential, error_type=ServiceNowError,
    )


def checkout_repository(target: dict[str, str], directory: str, file_path: str = "") -> str:
    """Shallow, single-branch clone of the AVIT's repository and branch; returns the checkout path.

    When the clone exceeds THREATLINT_CLONE_TIMEOUT (default 600 s) and the AVIT names a file, Azure DevOps
    repositories fall back to downloading only that file's folder through the Items API (GitHub: a blobless
    sparse checkout), so very large repositories can still be reviewed."""
    return servicenow_checkout.checkout_repository(
        target, directory, file_path, auth_env=_git_auth_env, sparse_clone=_sparse_clone,
        folder_download=_ado_folder_download, timeout=_CLONE_TIMEOUT_S, error_type=ServiceNowError,
    )


def resolve_credentials(profile: str | None = None) -> tuple[str, str]:
    """Environment overrides first, then the saved Threatlint config, then Parameter Store."""
    client_id, client_secret = os.environ.get(CLIENT_ID_ENV, ""), os.environ.get(CLIENT_SECRET_ENV, "")
    if client_id and client_secret:
        return client_id, client_secret
    saved = saved_config()
    if saved.get("clientId") and saved.get("clientSecret"):
        return saved["clientId"], saved["clientSecret"]
    return read_parameter_store(profile)


def load_avits(instance: str, numbers: list[str], client_id: str, client_secret: str) -> tuple[str, int, list[str], list[str]]:
    """(Markdown artifact, retrieved count, missing numbers, excluded numbers — always empty; kept for callers)."""
    instance = validate_instance_url(instance)
    items, missing, excluded = fetch_avits(instance, access_token(instance, client_id, client_secret), numbers)
    if not items:
        raise ServiceNowError(f"No AVITs were returned for {', '.join(numbers)}. Check the numbers and table access.")
    return avits_markdown(instance, items, numbers, missing, excluded), len(items), missing, excluded


# ── CLI ───────────────────────────────────────────────────────────────────────

def add_avit_arguments(parser) -> None:
    """Options shared by `threatlint run fp-review` and `threatlint avit fetch`."""
    servicenow_cli.add_avit_arguments(parser, instance_env=INSTANCE_ENV, saved_config=saved_config)


def requested_avits(args) -> list[str]:
    """AVIT numbers from --avit and --avit-file; empty when neither was given."""
    return servicenow_cli.requested_avits(args, parse_numbers=parse_avit_numbers, error_type=ServiceNowError)


def _prompt_credentials(reason: ServiceNowError) -> tuple[str, str]:
    """Interactive fallback: values copied from the Parameter Store console after SSO sign-in."""
    return servicenow_cli.prompt_credentials(reason, error_type=ServiceNowError)


def collect_avits(args, numbers: list[str]) -> tuple[str, str]:
    """(label, Markdown artifact) for the requested AVITs, printing progress without secrets."""
    return servicenow_cli.collect_avits(
        args, numbers, instance_env=INSTANCE_ENV, validate_instance=validate_instance_url,
        resolve_credentials=resolve_credentials, prompt_credentials=_prompt_credentials,
        load_avits=load_avits, error_type=ServiceNowError,
    )


def add_avit_parser(sub) -> None:
    servicenow_cli.add_avit_parser(sub, add_arguments=add_avit_arguments)


def cmd_avit(args) -> int:
    return servicenow_cli.cmd_avit(
        args, requested_avits=requested_avits, collect_avits=collect_avits, error_type=ServiceNowError,
    )
