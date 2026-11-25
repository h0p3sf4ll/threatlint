---
title: Manage connections and tickets
description: Connect source providers and issue trackers, create tickets from findings, and close reviewed false positives.
---

# Manage connections and tickets

Use **Settings → Integrations** to save named source and tracker connections. You can keep multiple connections for different projects, repositories, or credentials and choose an enabled default for each kind.

On the web, company connections and tracked ticket records are shared within the company, subject to your role. Personal users have their own scope. Repository checkouts and review reports remain in each user's profile. Desktop connections use the local Workbench scope.

## Configure providers

1. Open **Settings → Integrations** and add a named connection.
2. Select the provider and enter its destination and credentials.
3. Set the enabled and default choices, then save the connection.
4. Choose **Test** on its saved card to check access. For a source connection, choose **Use in Connect source** to activate it for your profile.

| Provider | Required settings and access |
| --- | --- |
| Jira Cloud | `https://company.atlassian.net`, account email, project key, and API token with browse/create/edit/comment/transition access. Issue type defaults to `Task`. |
| Azure Boards | Organization slug, project, and PAT with Work Items read/write. Work item type defaults to `Bug`; closed state defaults to `Closed`. |
| GitHub Issues | `owner/repository` and token with repository metadata and Issues read/write. |
| GitHub source | Token with Metadata and Contents read; optional organization filter. |
| Azure DevOps source | Organization slug and PAT with Code read. |

These connections support the listed cloud services. Jira Data Center, GitHub Enterprise, and Azure DevOps Server or custom hosts are not supported here. For ServiceNow, use the [AVIT integration guide](avit-integration.md).

For Jira false-positive closure, set a transition ID available from the ticket's current status that leads to a Done status category. Project defaults or automation must supply required custom fields and workflow validators. Unsupported workflows return a provider error rather than a confirmed closure.

When editing a connection, a blank token preserves the saved credential. Enter a replacement to rotate it. A connection with ticket history cannot change destination or be deleted while referenced. Disable it and add another named connection instead.

## Work with tickets

Use **Issue management** to create a ticket from a saved report finding, or create it directly from that finding. To track existing work, import specific provider ticket IDs. Imported records retain their provider scope and native ticket link.

Use status sync to refresh tracked records. Check individual errors when an update is partial; a failed provider request does not erase existing records. Imports accept up to 100 IDs per request. Large status lists are paged.

### Recover an uncertain ticket creation

Threatlint deduplicates creation by connection, saved report, and finding. If a provider explicitly rejects a request, correct the connection or fields and retry.

If the request times out or confirmation fails, check the provider before creating another ticket:

1. Look for the ticket ID in the error, if one was returned.
2. Otherwise search the provider for `ThreatLint reference: <report-id>/<finding-id>`.
3. Import that ticket with its exact stored reference to reconcile the pending operation.

Threatlint blocks another create request while the first result is uncertain to avoid duplicate tickets.

## Close a false positive

Closure requires your confirmation and a saved **Finding Review** report from `appsec-fp-reviewer`. Its finding must be **FALSE POSITIVE**, verified, and include both **Evidence** and **Verified Safe Behavior**.

1. Select the tracked ticket and the saved review finding.
2. For an imported ticket or later review, ensure **Original finding** identifies the exact scoped ticket reference shown in Findings.
3. Inspect the evidence and confirm closure.
4. Check the confirmed provider status.

| Provider | Example exact reference |
| --- | --- |
| Jira Cloud | `https://company.atlassian.net/browse/SEC-123` |
| GitHub Issues | `owner/repository#123` or the full issue URL |
| Azure Boards | `organization/project#123` or the full work item URL |

Bare numeric IDs, bare Jira keys, and report-local IDs such as `F-001` do not establish identity across reports. The original report/finding pair is sufficient only for a ticket Threatlint created from it.

Threatlint posts the review as a comment or history note, requests closure, and reads the ticket back before recording **FALSE POSITIVE**. If confirmation fails after an acknowledged closure, retry with the same review proof to check the result without repeating that mutation. An unacknowledged network failure stays uncertain.

A ticket closed externally is not automatically reclassified as a false positive. Sync it to see the provider status. ServiceNow uses its separate [AVIT closure and tuning workflow](avit-integration.md).
