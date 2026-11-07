"""Opt-in installed scanners. No installs, project hooks, or secret validation."""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import tempfile
import time
from pathlib import Path

from threatlint.assurance.sast import _severity

from .normalize import finding, MAX_FINDINGS
from .snapshot import ScannerError

ENGINE_CATEGORIES = {"semgrep": ["sast"], "trivy": ["sca", "secrets", "iac"]}


class EngineUnavailable(ScannerError):
    pass


def _path(raw: str, root: str, files: dict) -> str:
    value = str(raw or "").replace("\\", "/")
    prefix = str(root).replace("\\", "/") + "/"
    if value.startswith(prefix):
        value = value[len(prefix):]
    if value.startswith("./"):
        value = value[2:]
    # Never propagate an engine-supplied outside path into a fix plan.
    return value if value in files else ""


def normalize_semgrep(payload: dict, root: str, files: dict) -> list[dict]:
    result = []
    for item in payload.get("results", []):
        extra = item.get("extra") or {}
        metadata = extra.get("metadata") or {}
        path = _path(item.get("path"), root, files)
        line = (item.get("start") or {}).get("line", 1)
        source = files.get(path, b"").decode("utf-8", errors="replace").splitlines()
        cwe = metadata.get("cwe") or []
        result.append(finding(source="semgrep", category="sast", rule=item.get("check_id", "semgrep"),
                              title=extra.get("message", "Semgrep finding"), severity=_severity(item), path=path,
                              line=line, snippet=source[line - 1] if 0 < line <= len(source) else "",
                              cwe=[cwe] if isinstance(cwe, str) else cwe,
                              references=metadata.get("references") if isinstance(metadata.get("references"), list) else [],
                              confidence="ENGINE_REPORTED"))
        if len(result) >= MAX_FINDINGS:
            return result
    return result


def normalize_trivy(payload: dict, root: str, files: dict) -> list[dict]:
    result = []
    for target in payload.get("Results", []):
        path = _path(target.get("Target", ""), root, files)
        for item in target.get("Vulnerabilities") or []:
            result.append(finding(source="trivy", category="sca", rule=item.get("VulnerabilityID", "trivy-vulnerability"),
                                  title=item.get("Title") or item.get("VulnerabilityID"), severity=item.get("Severity"), path=path,
                                  impact=item.get("Description", "Known dependency vulnerability reported by Trivy."),
                                  recommendation=f"Upgrade {item.get('PkgName', 'dependency')} to a verified fixed version: {item.get('FixedVersion') or 'not supplied by engine'}.",
                                  references=item.get("References", []), confidence="ENGINE_REPORTED",
                                  package={"name": item.get("PkgName", ""), "version": item.get("InstalledVersion", ""), "fixedVersion": item.get("FixedVersion", "")}))
            if len(result) >= MAX_FINDINGS:
                return result
        for item in target.get("Misconfigurations") or []:
            cause = item.get("CauseMetadata") or {}
            result.append(finding(source="trivy", category="iac", rule=item.get("ID", "trivy-misconfiguration"),
                                  title=item.get("Title", "Infrastructure misconfiguration"), severity=item.get("Severity"), path=path,
                                  line=cause.get("StartLine", 1), impact=item.get("Description"),
                                  recommendation=item.get("Resolution"), references=item.get("References", []), confidence="ENGINE_REPORTED"))
            if len(result) >= MAX_FINDINGS:
                return result
        for item in target.get("Secrets") or []:
            result.append(finding(source="trivy", category="secrets", rule=item.get("RuleID", "trivy-secret"),
                                  title="Credential-like value reported by Trivy", severity=item.get("Severity"), path=path,
                                  line=item.get("StartLine", 1), recommendation="Revoke and rotate the credential; remove it from source and use a secret store.",
                                  confidence="ENGINE_REPORTED"))
            if len(result) >= MAX_FINDINGS:
                return result
    return result


def _run(args: list[str], root: str, env: dict):
    """Bound output and drain an engine process group even when Python is cancelled."""
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        process = subprocess.Popen(args, cwd=root, env=env, stdout=stdout, stderr=stderr,
                                   shell=False, start_new_session=os.name != "nt")
        deadline = time.monotonic() + 300
        try:
            while True:
                if time.monotonic() >= deadline or max(os.fstat(stdout.fileno()).st_size, os.fstat(stderr.fileno()).st_size) > 20_000_000:
                    raise ScannerError("Engine exceeded its runtime or output budget")
                try:
                    process.wait(timeout=0.1)
                    break
                except subprocess.TimeoutExpired:
                    continue
            if max(os.fstat(stdout.fileno()).st_size, os.fstat(stderr.fileno()).st_size) > 20_000_000:
                raise ScannerError("Engine exceeded its output budget")
            stdout.seek(0)
            return subprocess.CompletedProcess(args, process.returncode, stdout.read(20_000_001).decode("utf-8", errors="replace"), "")
        finally:
            if os.name != "nt":
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            elif process.poll() is None:
                subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"], capture_output=True, timeout=10, check=False)
            process.wait(timeout=10)


def run_engine(engine: str, root: str):
    from threatlint.tls import tool_env
    environment = tool_env()
    if engine == "semgrep":
        from threatlint import semgrep_platform
        try:
            flags = semgrep_platform.engine_flags("pro")
        except semgrep_platform.SemgrepError as exc:
            raise EngineUnavailable("Matching Semgrep Pro engine is unavailable; no Community Edition fallback was used.") from exc
        try:
            environment["SEMGREP_APP_TOKEN"] = semgrep_platform.resolve_token()[0]
        except semgrep_platform.SemgrepError:
            pass  # The explicitly requested Pro scan fails closed if authentication is required.
        environment.update(SEMGREP_SEND_METRICS="off", SEMGREP_ENABLE_VERSION_CHECK="0")
        return _run([shutil.which("semgrep") or "semgrep", "scan", *flags, "--config", "p/security-audit", "--json", "--quiet", "--metrics", "off",
                     "--disable-version-check", "--no-secrets-validation", "."], root, environment)
    # Do not interpret a scanned repository's trivy.yaml or .trivyignore as trusted scanner policy.
    with tempfile.TemporaryDirectory(prefix="threatlint-trivy-policy-") as directory:
        config = Path(directory) / "config.yaml"
        ignore = Path(directory) / "ignore"
        config.write_text("{}\n", encoding="utf-8")
        ignore.write_text("", encoding="utf-8")
        return _run([shutil.which("trivy") or "trivy", "fs", "--config", str(config), "--ignorefile", str(ignore),
                     "--scanners", "vuln,misconfig,secret", "--format", "json", "--quiet", "."], root, environment)


def external_scans(files: dict[str, bytes], requested: list[str], *, runner=run_engine, which=shutil.which) -> tuple[list, list]:
    findings, statuses = [], []
    for engine, categories in ENGINE_CATEGORIES.items():
        status = {"id": engine, "categories": categories, "status": "not_requested", "findings": 0,
                  "detail": "Available but not requested; opt-in may download rules or vulnerability databases."}
        if engine == "semgrep":
            status["mode"] = "pro"
        if not which(engine):
            status.update(status="unavailable", detail=f"{engine} is not installed; its detection coverage was not evaluated.")
        elif engine in requested:
            try:
                # Engines see only the bounded captured text snapshot, never repository hooks/config outside it.
                with tempfile.TemporaryDirectory(prefix="threatlint-security-scan-") as directory:
                    for name, data in files.items():
                        target = Path(directory) / name
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.write_bytes(data)
                    completed = runner(engine, directory)
                    if completed.returncode != 0:
                        raise ScannerError("Engine exited unsuccessfully")
                    payload = json.loads(completed.stdout)
                    if not isinstance(payload, dict):
                        raise ScannerError("Engine returned an invalid object")
                    normalized = (normalize_semgrep if engine == "semgrep" else normalize_trivy)(payload, directory, files)
                    findings.extend(normalized)
                    partial = (bool(payload.get("errors")) if engine == "semgrep" else False) or len(normalized) >= MAX_FINDINGS
                    status.update(status="partial" if partial else "completed", findings=len(normalized),
                                  detail="Engine reported incomplete coverage." if partial else "Scanned the bounded text snapshot; engine matches require review." + (" Semgrep Pro was required; no Community Edition fallback." if engine == "semgrep" else ""))
            except EngineUnavailable as exc:
                status.update(status="unavailable", detail=str(exc))
            except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
                # stderr may contain credentials or source; report only the failure class.
                status.update(status="failed", detail="Engine failed or returned invalid output; no clean result is claimed.")
        statuses.append(status)
    return findings, statuses
