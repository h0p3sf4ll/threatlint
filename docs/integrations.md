# Organization connections and centralized findings

ThreatLint can manage findings in **Jira Cloud**, **Azure Boards**, and **GitHub Issues**, alongside the existing ServiceNow AVIT workflow. Settings → Integrations stores multiple named tracker and source connections. You can keep several connections to the same provider for different teams, projects, repositories, or credentials. Choose an enabled default for each connection kind; disable unused connections to preserve their ticket history.

Source connections currently support GitHub.com and Azure DevOps cloud. Activate a saved source connection to make it available in Sources for the current profile. Activating different connections preserves the existing source manager's ability to work with multiple connected accounts and organizations.

On the web, the gateway stores connections and ticket records in the authenticated organization's scope; personal users receive their own scope. Review reports and repository checkouts remain in the signed-in user's isolated profile. The gateway reads a selected report through an authenticated internal worker route when creating or closing a ticket. The local desktop uses its local Workbench scope.

## Configure providers

| Provider | Required settings | Credential permissions | Closure configuration |
| --- | --- | --- | --- |
| Jira Cloud | Site origin such as `https://company.atlassian.net`, account email, project key, API token | Browse project, create/edit issues, add comments, transition issues | Set the transition ID for your false-positive workflow. It must be available from the current status and lead to a Done status category. |
| Azure Boards | Organization slug, project name, PAT | Work Items read and write (`vso.work_write`) for the selected project | Configure the closed state used by your process; default `Closed`. Work item type defaults to `Bug`. |
| GitHub Issues | `owner/repository`, API token | Repository metadata and Issues read/write for the selected repository | ThreatLint comments with the review, then closes using `state_reason: not_planned`. |
| GitHub source | API token, optional organization filter | Metadata and Contents read | Existing Sources checkout and review behavior applies. |
| Azure DevOps source | Organization slug, PAT | Code read | Existing Sources checkout and review behavior applies. |

Jira issue type defaults to `Task`. Required custom create fields, required resolution fields, or workflow validators must be supplied by your provider's project defaults/automation. An unsupported workflow produces a visible provider error and does not produce a confirmed local closure. Jira Data Center, GitHub Enterprise, and Azure DevOps Server/custom hosts are not supported by these new connections.

The new connection registry encrypts saved API tokens with AES-256-GCM. Its encryption key is stored separately in the same private scope directory, so backups must preserve **both** `integration-management.json` and `integration-management.key` and restrict host access to them. Encryption does not protect against an administrator who can read both files. Browser responses expose only `hasToken`; a blank token during an edit preserves the saved credential. Rotate a token by editing its connection. Existing ServiceNow, Semgrep, and legacy source settings retain their existing storage behavior.

## Work with tickets

Use Issue management to create a ticket from a saved report finding, or import specific provider ticket IDs. You can also create a ticket directly from a finding in a saved report. Imports and status sync retain provider scope and a link to the native ticket. Sync updates the existing record; it does not erase records when one provider call fails. Each response lists individual failures so partial updates are visible.

Imports accept at most 100 IDs per request. Status sync pages through at most 100 saved tickets per request using `nextCursor`, supporting up to 10,000 tracked tickets per organization. Connections support up to 100 named instances. These limits bound individual work; they do not reduce a provider's project inventory.

A create request is deduplicated by connection, saved report ID, and finding ID. A pending operation is saved **before** the provider POST. An explicit rejected POST (for example, authentication or validation failure) can be retried after fixing the connection. A network failure or failed readback can leave creation uncertain, so ThreatLint blocks another POST. Check the provider for the embedded `ThreatLint reference: <report-id>/<finding-id>` and import the resulting ticket. An import with the exact stored reference reconciles that pending operation. If the provider returned a ticket ID before readback failed, the error includes that ID.

A connection with ticket history or creation operations cannot change its destination site, organization, project, or repository. Add another named connection instead. Such connections can be disabled but cannot be deleted while history references them.

## Close a false positive

Closure requires an explicit confirmation and a **saved Finding Review** report from `appsec-fp-reviewer`. The selected finding must have disposition `FALSE POSITIVE`, must not be unverified, and must contain both **Evidence** and **Verified Safe Behavior**. ThreatLint reparses the saved report server-side; changing a browser field does not change the verdict.

For a later review or an imported ticket, its `Original finding` field must name the exact scoped reference shown in Findings:

| Provider | Example exact reference |
| --- | --- |
| Jira Cloud | `https://company.atlassian.net/browse/SEC-123` |
| GitHub Issues | `owner/repository#123` or the full issue URL |
| Azure Boards | `organization/project#123` or the full work item URL |

Bare numeric ticket IDs, repeated report-local IDs such as `F-001`, and bare Jira keys do not establish cross-report identity. The same original report/finding pair can be used directly only for a ticket ThreatLint created from it. Duplicate finding IDs or multiple Original finding fields are rejected.

The review evidence is posted to the provider as a comment or history note. ThreatLint then reads the ticket back and records `FALSE POSITIVE` only after the provider confirms its closed state. If the closing mutation succeeded but its readback failed, ThreatLint persists the provider acknowledgement with the exact review/finding and actor. Retrying with that same proof can confirm the closed state without another mutation, including after a restart. An unacknowledged network failure stays conservative, and observing an open ticket during sync clears an older acknowledgement. A ticket that was already closed externally without a matching acknowledged ThreatLint closure is not automatically reclassified as a false positive. Sync it to see the provider status. Jira/ADO false-positive semantics vary by organization; the explicit review note records the reason even where no native false-positive resolution value exists.

ServiceNow keeps its existing AVIT closure, report attachment, and Semgrep tuning flow.

## API summary

All routes are under `/api/management`. The web gateway enforces authenticated organization roles before these routes run; the desktop remains a single-user local application.

| Method and path | Purpose |
| --- | --- |
| `GET /connections` | Public connection metadata and provider field definitions |
| `POST /connections` | Create/update `{id?, name, kind, provider, token?, enabled?, isDefault?, ...providerFields}` |
| `DELETE /connections/:id` | Delete a connection without tracked history |
| `POST /connections/:id/test` | Test provider credentials and configured scope |
| `POST /connections/:id/activate` | Activate an enabled source connection in the caller's profile |
| `GET /findings` | Central ticket records and public connections |
| `POST /findings/create` | Create from `{connectionId, reportId, findingId}` |
| `POST /findings/import` | Import `{connectionId, ids}` |
| `POST /findings/sync` | Sync `{connectionId?, cursor?}`; returns `{findings, errors, nextCursor, total}` |
| `POST /findings/:id/close` | Confirm closure with `{reportId, findingId, confirm: true}` |
| `GET /audit` | Bounded recent action history, without credentials or report bodies |

Provider requests use fixed cloud API destinations, HTTPS, disabled redirects, 15-second timeouts, and a 4 MiB response bound. Jira site origins are restricted to `*.atlassian.net`. Error messages include fixed explanations and HTTP status codes rather than raw provider response text. Remote issue descriptions are untrusted evidence.

## Validation and provider references

Run `node --test web/tests/management.test.cjs` from the repository root. The tests cover provider request/response behavior, isolated scopes, multiple instances, encrypted persistence, proof and identity gates, destination immutability, partial sync, uncertain creation recovery, idempotency, and saved source activation. They use fake provider transports and do not create or close real tickets.

The adapters implement the documented [Jira Cloud v3 issue and transition APIs](https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issues/), [Azure Boards work item creation](https://learn.microsoft.com/en-us/rest/api/azure/devops/wit/work-items/create?view=azure-devops-rest-7.1), [Azure Boards work item updates](https://learn.microsoft.com/en-us/rest/api/azure/devops/wit/work-items/update?view=azure-devops-rest-7.1), and [GitHub Issues create/update APIs](https://docs.github.com/en/rest/issues/issues?apiVersion=2022-11-28).
