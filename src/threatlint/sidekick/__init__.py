"""Sidekick: portfolio reporting and bulk operations over ServiceNow AVR, Azure DevOps and Semgrep.

Ported from the standalone Sidekick desktop app into Threatlint's CLI and Workbench. Modules:
  sidekick.store      data directory, loadouts, saved queries, report history, action journal (sqlite)
  sidekick.clients    Azure DevOps and ServiceNow calls (branch stats, counts, batch close, users)
  sidekick.reports    vReports, branch reports, trends, scope accountability, xlsx output
  sidekick.ops        ownership lookup, AVIT bulk closure and reversal, Semgrep bulk triage
  sidekick.cli        `threatlint sidekick …`

Organization values (Azure DevOps organizations, email domain, report footer) come from environment
variables or ~/.threatlint/org.json via threatlint.org_config; nothing organization-specific is built in.
Credentials reuse Threatlint's: the per-organization ADO PAT, the saved ServiceNow client, the Semgrep token.
"""
