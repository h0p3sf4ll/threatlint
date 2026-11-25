'use strict';

/** Headless source discovery uses exactly the same refreshed connections as HTTP. */
function registerSourceTools({ tool, z, id, sources }) {
  const page = z.number().int().min(1).max(100).optional();
  const provider = z.enum(['github', 'azure-devops']);
  tool('list_source_providers', 'List supported source providers, paging limits, and required read permissions.', {}, () => sources.providers());
  tool('list_sources', 'Activate saved GitHub App and Azure DevOps credentials and list connected source accounts. Credentials are never returned.', {}, () => sources.list());
  tool('connect_source', 'Connect a read-only source account with a session-only token. Saved GitHub App and Azure DevOps credentials are activated by list_sources instead.', {
    provider, token: z.string().min(1).max(4096), organization: z.string().min(1).max(200).optional(), confirm: z.literal(true),
  }, ({ confirm, ...input }) => sources.connect(input), { readOnly: false, openWorld: true });
  tool('reconnect_source', 'Refresh the saved GitHub App connection after its configuration or credentials change.', {
    provider: z.literal('github'), confirm: z.literal(true),
  }, ({ provider }) => sources.reconnect({ provider }), { readOnly: false, openWorld: true });
  tool('disconnect_source', 'Disconnect a source account in this profile. Saved credential configuration is retained.', {
    connectionId: id, confirm: z.literal(true),
  }, ({ connectionId }) => ({ disconnected: !!sources.disconnect(connectionId) }), { readOnly: false, destructive: true });
  tool('list_repositories', 'Browse repositories using a connected source account, refreshing saved credentials before access. Use returned repository IDs for branches and checkout.', {
    connectionId: id, search: z.string().max(200).optional(), page,
  }, ({ connectionId, ...input }) => sources.repositories(connectionId, input), { openWorld: true });
  tool('list_branches', 'List short branch names for a repository discovered through this connection.', {
    connectionId: id, repositoryId: id, page,
  }, ({ connectionId, repositoryId, ...input }) => sources.branches(connectionId, repositoryId, input), { openWorld: true });
  tool('checkout_repository', 'Check out a discovered repository into a managed workspace at a pinned revision. Returns the sessionId for scans and reviews.', {
    connectionId: id, repositoryId: id, branch: z.string().min(1).max(255).optional(), confirm: z.literal(true),
  }, ({ confirm, ...input }) => sources.checkout(input), { readOnly: false, openWorld: true });
}

module.exports = { registerSourceTools };
