"""Reuse Guard for source/secrets; small explicit configuration checks, not a CVE database."""

from __future__ import annotations

import json
import re
from pathlib import PurePosixPath

from threatlint.guard.scanning import scan_text

from .normalize import finding, MAX_FINDINGS

IAC_RULES = (
    ("TL-IAC-PRIVILEGED", r"^\s*privileged\s*:\s*true\b", "HIGH", "Container requests privileged execution", "A compromised container may access host devices and bypass container isolation.", "Remove privileged mode and grant only the required capabilities.", "CWE-250"),
    ("TL-IAC-HOST-NETWORK", r"^\s*hostNetwork\s*:\s*true\b", "MEDIUM", "Pod shares the host network", "Workload compromise can expose host network services.", "Use the pod network unless a documented system workload requires host networking.", "CWE-668"),
    ("TL-IAC-PUBLIC-INGRESS", r"(?:cidr_blocks|cidr|CidrIp)\s*[:=].*(?:0\.0\.0\.0/0|::/0)", "MEDIUM", "Infrastructure allows an unrestricted network range", "Internet-wide reachability may expose a service if this range controls ingress.", "Check ingress versus egress context and constrain ingress to approved clients.", "CWE-284"),
)


def baseline(files: dict[str, bytes]) -> list[dict]:
    result = []
    for path, data in files.items():
        text = data.decode("utf-8", errors="replace")
        for item in scan_text(text, path):
            category = "secrets" if item.rule_id.startswith("TL-SECRET") else "sast"
            result.append(finding(source="guard", category=category, rule=item.rule_id, title=item.message,
                                  severity=item.severity, path=path, line=item.line, column=item.column,
                                  snippet=item.snippet, recommendation=item.fix, cwe=[item.cwe],
                                  impact=item.message))
            if len(result) >= MAX_FINDINGS:
                return result
        if PurePosixPath(path).suffix in {".yml", ".yaml", ".tf", ".tfvars"}:
            for number, line in enumerate(text.splitlines(), 1):
                if len(line) > 4000:
                    continue
                for rule, pattern, severity, title, impact, fix, cwe in IAC_RULES:
                    if re.search(pattern, line):
                        result.append(finding(source="baseline-iac", category="iac", rule=rule, title=title,
                                              severity=severity, path=path, line=number, snippet=line,
                                              impact=impact, recommendation=fix, cwe=[cwe]))
                        if len(result) >= MAX_FINDINGS:
                            return result
        # Dependency hygiene is reported separately from known-vulnerability coverage.
        if PurePosixPath(path).name == "package.json":
            try:
                manifest = json.loads(text)
            except ValueError:
                continue
            if not isinstance(manifest, dict):
                continue
            lock_dir = str(PurePosixPath(path).parent)
            prefix = "" if lock_dir == "." else lock_dir + "/"
            if not any(prefix + name in files for name in ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml")):
                for section in ("dependencies", "devDependencies"):
                    dependencies = manifest.get(section, {})
                    if not isinstance(dependencies, dict):
                        continue
                    for name, version in dependencies.items():
                        if isinstance(version, str) and (version.startswith(("^", "~", ">", "*")) or version in {"latest", "next"}):
                            result.append(finding(source="baseline-dependencies", category="sca", rule="TL-SCA-FLOATING-NO-LOCK",
                                                  title=f"Floating dependency without a captured lockfile: {name}", severity="LOW", path=path,
                                                  impact="Installations may resolve different dependency versions; this is not a known-CVE assertion.",
                                                  recommendation="Commit the package manager's lockfile and use its frozen installation mode.",
                                                  package={"name": name, "version": version}))
                            if len(result) >= MAX_FINDINGS:
                                return result
    return result
