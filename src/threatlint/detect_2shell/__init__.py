"""detect-2shell: deterministic detection of the React2Shell family (CVE-2025-55182, CVE-2025-66478 and follow-ups).

`scan_path` checks one checkout; `fleet.run_fleet` checks many repositories and branches
through the GitHub and Azure DevOps APIs. Both are read-only.
"""
from .scanner import scan_path, scan_source

__all__ = ["scan_path", "scan_source"]
