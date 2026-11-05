"""Read named AWS parameters without exposing credential values in diagnostics."""

from __future__ import annotations

import json
import re
import shutil
import subprocess

from threatlint import tls

_PARAMETER = re.compile(r"(?:[A-Za-z0-9_./][A-Za-z0-9_./-]*|arn:aws(?:-[a-z]+)*:ssm:[a-z0-9-]+:\d{12}:parameter/[A-Za-z0-9_./-]+)\Z")
_REGION = re.compile(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)+-\d+\Z")
_PROFILE = re.compile(r"[\w.@+][\w.@+-]{0,127}\Z")
_TIMEOUT = 60


class ParameterStoreError(RuntimeError):
    """A safe, actionable failure reading a parameter."""


def safe_error(stderr: str) -> str:
    """Classify known AWS failures, without returning AWS output or credential data."""
    text = stderr if isinstance(stderr, str) else ""
    if any(phrase in text.lower() for phrase in ("token has expired", "sso session", "sso token", "expiredtoken", "unauthorizedssotoken")):
        return "Token has expired or the AWS SSO session is unavailable. Run `threatlint aws login --profile <profile>` and retry."
    messages = {
        "AccessDeniedException": "AWS access was denied. Request permission to read the parameter and decrypt its KMS key, if applicable.",
        "AccessDenied": "AWS access was denied. Request permission to read the parameter and decrypt its KMS key, if applicable.",
        "ParameterNotFound": "The parameter was not found. Check its name, AWS account, and region.",
        "InvalidKeyId": "AWS could not use the parameter's KMS key. Check the key and decryption permissions.",
        "InvalidClientTokenId": "AWS credentials are invalid. Sign in again with `threatlint aws login --profile <profile>`.",
        "UnrecognizedClientException": "AWS credentials are invalid. Sign in again with `threatlint aws login --profile <profile>`.",
        "ValidationException": "AWS rejected the parameter request. Check the parameter name and region.",
        "ThrottlingException": "AWS temporarily throttled the request. Retry shortly.",
        "InternalServerError": "AWS could not complete the request. Retry shortly.",
    }
    match = re.search(r"\(([A-Za-z0-9]+)\)", text)
    if match and match.group(1) in messages:
        code = match.group(1)
        return f"{code}: {messages[code]}"
    if "unable to locate credentials" in text.lower():
        return "AWS credentials are unavailable. Configure or sign in to the selected AWS profile and retry."
    if "certificate_verify_failed" in text.lower() or "ssl validation failed" in text.lower():
        return "AWS certificate validation failed. Configure the organization's approved CA bundle and retry."
    return "AWS could not read the parameter. Check your sign-in, permissions, region, and network connection."


def validate_region(region: str) -> str:
    """Validate a configured AWS region before any CLI calls or setup prompts."""
    if not isinstance(region, str) or not _REGION.fullmatch(region):
        raise ParameterStoreError("Invalid AWS region. Set THREATLINT_AWS_REGION or pass a valid region.")
    return region


def validate_reference(name: str, profile: str | None = None, region: str | None = None) -> None:
    """Validate the shared single- and multi-parameter reader inputs."""
    from threatlint.org_config import aws_region  # noqa: PLC0415 - avoids the bootstrap import cycle

    if not isinstance(name, str) or len(name) > 2048 or not _PARAMETER.fullmatch(name):
        raise ParameterStoreError("Invalid Parameter Store name. Supply a parameter name, path, or SSM parameter ARN.")
    validate_region(aws_region() if region is None else region)
    if profile is not None and (not isinstance(profile, str) or not _PROFILE.fullmatch(profile)):
        raise ParameterStoreError("Invalid AWS profile name.")


def read_parameter(name: str, profile: str | None = None, region: str | None = None) -> str:
    """Return one decrypted parameter through the caller's AWS CLI credentials."""
    from threatlint.org_config import aws_region  # noqa: PLC0415 - avoids the bootstrap import cycle

    selected_region = aws_region() if region is None else region
    validate_reference(name, profile, selected_region)
    aws = shutil.which("aws")
    if not aws:
        raise ParameterStoreError("AWS CLI v2 was not found on PATH. Install it, reopen your terminal, and verify `aws --version`.")
    command = [aws, "ssm", "get-parameter", "--name", name, "--with-decryption", "--region", selected_region, "--output", "json"]
    if profile:
        command += ["--profile", profile]
    try:
        result = subprocess.run(command, shell=False, capture_output=True, text=True, timeout=_TIMEOUT,
                                check=False, env=tls.tool_env())
    except subprocess.TimeoutExpired:
        raise ParameterStoreError("AWS Parameter Store request timed out. Check the network connection and retry.") from None
    except (OSError, subprocess.SubprocessError):
        raise ParameterStoreError("The AWS CLI could not run. Verify `aws --version` and retry.") from None
    if result.returncode:
        raise ParameterStoreError(safe_error(result.stderr))
    try:
        value = json.loads(result.stdout)["Parameter"]["Value"]
    except (ValueError, KeyError, TypeError):
        raise ParameterStoreError("AWS returned an unexpected Parameter Store response.") from None
    if not isinstance(value, str) or not value.strip():
        raise ParameterStoreError("The requested AWS parameter is empty or is not a string.")
    return value
