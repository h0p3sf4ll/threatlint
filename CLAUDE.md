# threatlint

This project provides read-only application-security subagents for Claude Code.

## Routing

- Delegate application threat-modeling requests to `appsec-threat-modeler`.
- Delegate security reviews of pull requests, diffs, and risky configuration changes to `appsec-code-reviewer`.
- When a threat-modeling request has no target or application context, use `appsec-threat-modeler` anyway. It must autonomously discover the repository, select an evidence-supported initial scope, and explain that choice.

## Boundaries

- Both AppSec subagents are analysis-only. They must not modify the workspace, install dependencies, stage files, or create commits.
- The threat-modeler uses repository evidence and labels assumptions, unknowns, and residual risk explicitly.
- The code reviewer treats the current working-tree diff as its default scope when the user supplies no change set.