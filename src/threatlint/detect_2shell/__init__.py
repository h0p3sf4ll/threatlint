"""detect-2shell: deterministic detection of *-2Shell exposure (React2Shell CVE-2025-55182, Next.js CVE-2025-66478 and
follow-ups) and *-4Shell exposure (Log4Shell CVE-2021-44228 and follow-ups, Spring4Shell CVE-2022-22965, Text4Shell
CVE-2022-42889).

`scan_path` checks one checkout; `fleet.run_fleet` checks many repositories and branches
through the GitHub and Azure DevOps APIs. Both are read-only.
"""
from .scanner import scan_path, scan_source

__all__ = ["scan_path", "scan_source"]
