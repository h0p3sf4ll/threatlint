# Threatlint MCP

Threatlint exposes the current Workbench profile through the Model Context Protocol.
Tools can inspect specialists, existing workspaces, source accounts, repositories, findings,
review history, saved reports, and scan results. Starting a scan requires `confirm: true`.
Tools do not return saved integration credentials or apply source edits.

## Local stdio

Install Workbench dependencies with `npm --prefix web ci`. Configure your MCP client with
an absolute path to the checkout:

```json
{
  "mcpServers": {
    "threatlint": {
      "command": "node",
      "args": ["/absolute/path/to/threatlint/web/scripts/mcp.cjs"]
    }
  }
}
```

The process uses the normal local Workbench profile, or `THREATLINT_STATE_DIR` when set.
Open a workspace in the Workbench before requesting findings or starting a scan.
Avoid running separate processes that write the same profile concurrently.

## Streamable HTTP

Running Workbench servers expose `POST /api/mcp` using stateless Streamable HTTP and JSON
responses. Local servers remain bound to loopback with their existing host and origin checks.
For hosted Workbench, the endpoint remains behind the existing Auth0 session and profile
authorization. HTTP clients must supply an authorized session cookie; this endpoint does not
provide a separate OAuth registration flow. Viewer accounts cannot invoke this endpoint.
Use the stdio integration when a client cannot supply the existing session authentication.

`GET` and `DELETE` return 405 because transports do not keep independent MCP sessions.
Requests are bounded to 128 KB and eight concurrent requests per profile. Results are bounded
to 2 MB; narrow requests when a profile has a large history.

## Tools

| Tool | Purpose |
| --- | --- |
| `list_agents` | Available review specialists |
| `list_workspaces` | Current profile's workspace IDs |
| `list_findings`, `get_finding` | Workspace and revision-bound findings and evidence |
| `list_reports`, `get_report` | Saved structured review reports |
| `list_sources`, `list_repositories` | Existing source sessions and repository discovery |
| `start_scan`, `get_scan` | Explicitly authorized scanning and result polling |

Finding and scan requests require the workspace's `sessionId`. IDs from another profile
or workspace do not authorize access. Scanner observations remain unreviewed until evidence
and a human review decision are recorded in the Findings workflow.
