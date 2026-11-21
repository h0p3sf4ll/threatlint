'use strict';
const { HttpError } = require('./http.cjs');

function sourceLink(value) {
  if (!value) return null;
  let url;
  try { url = new URL(value); } catch { throw new HttpError('Use a GitHub or Azure DevOps HTTPS repository link'); }
  if (url.protocol !== 'https:' || url.port || url.username || url.password || url.search || url.hash) throw new HttpError('Source links must use HTTPS without credentials, custom ports, queries, or fragments');
  const parts = url.pathname.replace(/\.git\/?$/, '').split('/').filter(Boolean).map(decodeURIComponent);
  if (url.hostname === 'github.com' && parts.length === 2) return { url: url.href, provider: 'github', repository: parts.join('/') };
  if (url.hostname === 'dev.azure.com' && parts.length === 4 && parts[2] === '_git') return { url: url.href, provider: 'azure-devops', organization: parts[0], repository: `${parts[0]}/${parts[1]}/${parts[3]}` };
  throw new HttpError('Use the repository root URL from GitHub or dev.azure.com; choose the branch separately');
}
function createSourceResolver({ scm, store }) {
  return async (link, branch = '') => {
    const target = sourceLink(link);
    if (!target) return null;
    for (const connection of scm.list().filter(item => item.provider === target.provider && (!target.organization || item.account.toLowerCase() === target.organization.toLowerCase()))) {
      for (let page = 1; page <= 100; page++) {
        const result = await scm.repositories(connection.id, { page });
        const repository = result.repositories.find(item => item.fullName.toLowerCase() === target.repository.toLowerCase() || item.webUrl?.replace(/\/$/, '').toLowerCase() === target.url.replace(/\/$/, '').toLowerCase());
        if (repository) {
          const checkout = await scm.checkout(connection.id, { repositoryId: repository.id, ...(branch ? { branch } : {}) });
          const id = store.create(checkout.repoPath, true, checkout.tempDir);
          store.sessions.get(id).provenance = checkout.provenance; store.save();
          return { id, repoPath: checkout.repoPath, provenance: checkout.provenance };
        }
        if (!result.hasMore) break;
      }
    }
    throw new HttpError('Connect the source account under Review code → Connect source first, or select an existing workspace. The repository was not accessible with a connected account.', 412);
  };
}
module.exports = { sourceLink, createSourceResolver };
