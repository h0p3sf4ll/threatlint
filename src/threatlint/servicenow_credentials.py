"""ServiceNow client credentials from organization settings, saved config, and AWS SSM."""

from __future__ import annotations

import json
import os
import shutil
import subprocess

from threatlint import parameter_store, tls


def client_parameters() -> tuple[str, str]:
    from threatlint.org_config import value
    return value("snowClientIdParameter"), value("snowClientSecretParameter")


def access_help(*, client_parameters, region, console_url) -> str:
    from threatlint.org_config import ENV, value
    client_id, client_secret = client_parameters()
    sso = value("ssoUrl")
    return (f"The ServiceNow client ID and secret are in AWS Parameter Store ({region}):\n"
            f"  client ID     : {client_id}\n  client secret : {client_secret}\n"
            + (f"Sign in through single sign-on and request access if you do not have it:\n  {sso}\n" if sso else "")
            + f"Then either view the values in the console:\n  {console_url}\n"
            "or obtain AWS CLI credentials for that account and rerun (use --aws-profile if needed)."
            if client_id and client_secret else
            f"No ServiceNow Parameter Store names are configured. Set {ENV['snowClientIdParameter']} and "
            f"{ENV['snowClientSecretParameter']} (or ~/.threatlint/org.json), or enter the client with `threatlint setup`.")


def read_parameter_store(profile, *, client_parameters, access_help, region, timeout, error_type):
    id_parameter, secret_parameter = client_parameters()
    if not id_parameter or not secret_parameter:
        raise error_type(access_help())
    try:
        for name in (id_parameter, secret_parameter):
            parameter_store.validate_reference(name, profile, region)
    except parameter_store.ParameterStoreError as exc:
        raise error_type(str(exc)) from None
    aws = shutil.which("aws")
    if not aws:
        raise error_type("The AWS CLI v2 was not found on PATH, so Parameter Store cannot be read.\n" + access_help())
    command = [aws, "ssm", "get-parameters", "--names", id_parameter, secret_parameter,
               "--with-decryption", "--region", region, "--output", "json"]
    if profile:
        command += ["--profile", profile]
    try:
        # Pass arguments directly, without shell interpretation or shell quoting.
        result = subprocess.run(command, shell=False, capture_output=True, text=True,
                                timeout=timeout, check=False, env=tls.tool_env())
    except subprocess.TimeoutExpired:
        raise error_type("AWS CLI timed out while reading Parameter Store.\n" + access_help()) from None
    except (OSError, subprocess.SubprocessError):
        raise error_type("AWS CLI could not run while reading Parameter Store.\n" + access_help()) from None
    if result.returncode != 0:
        reason = parameter_store.safe_error(result.stderr)
        raise error_type(f"Parameter Store access failed: {reason}\n{access_help()}")
    try:
        payload = json.loads(result.stdout)
        if not isinstance(payload, dict) or not isinstance(payload.get("Parameters"), list):
            raise TypeError
        values = {}
        for item in payload["Parameters"]:
            if not isinstance(item, dict) or not isinstance(item.get("Name"), str) or not isinstance(item.get("Value"), str):
                raise TypeError
            values[item["Name"]] = item["Value"]
    except (ValueError, KeyError, TypeError):
        raise error_type("Unexpected AWS CLI response from Parameter Store") from None
    client_id, client_secret = values.get(id_parameter, ""), values.get(secret_parameter, "")
    if not client_id or not client_secret:
        raise error_type("Your AWS identity cannot read both ServiceNow parameters.\n" + access_help())
    return client_id, client_secret


def saved_config() -> dict[str, str]:
    """Workbench connection; THREATLINT_HOME overrides the default location."""
    home = os.environ.get("THREATLINT_HOME") or os.path.join(os.path.expanduser("~"), ".threatlint")
    try:
        with open(os.path.join(home, "servicenow.json"), encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, ValueError):
        return {}
    return {key: str(value.get(key) or "") for key in ("instance", "clientId", "clientSecret")} if isinstance(value, dict) else {}
