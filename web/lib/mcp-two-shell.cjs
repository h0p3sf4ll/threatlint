'use strict';

/** Headless detect-2shell fleet scans over the same validated service as the Workbench page. */
function registerTwoShellTools({ tool, z, id, twoShellFleet }) {
  const repositoryName = z.string().min(3).max(300);
  const branches = z.union([z.enum(['default', 'all']), z.array(z.string().min(1).max(200)).min(1).max(20)]);
  const paging = { offset: z.number().int().min(0).optional(), limit: z.number().int().min(1).max(100).optional() };
  const page = (items, { offset = 0, limit = 25 }) => ({ items: items.slice(offset, offset + limit), total: items.length,
    nextOffset: offset + limit < items.length ? offset + limit : null });
  tool('start_2shell_scan', 'Scan many repositories for React2Shell-family exposure (CVE-2025-55182, CVE-2025-66478 and RSC follow-ups) using connected GitHub and Azure DevOps sources. Choose all repositories or named ones, and the default branch, all branches, or named branches/wildcards per source. Reads lockfiles through provider APIs without cloning; poll get_2shell_scan.', {
    connections: z.array(z.object({
      connectionId: id,
      repositories: z.union([z.literal('all'), z.array(repositoryName).min(1).max(1000)]).default('all')
        .describe('"all", or owner/name (GitHub) and project/repository or organization/project/repository (Azure DevOps).'),
      branches: branches.default('default'),
    }).strict()).min(1).max(16).describe('Connection IDs from list_sources.'),
    workers: z.number().int().min(1).max(8).optional(),
    maxRepositories: z.number().int().min(1).max(10000).optional(),
    maxBranchesPerRepository: z.number().int().min(1).max(500).optional(),
    confirm: z.literal(true),
  }, ({ confirm, ...input }) => twoShellFleet.start(input), { readOnly: false, openWorld: true });
  tool('list_2shell_scans', 'List retained detect-2shell fleet scans with status, progress and summary counts.', { ...paging },
    input => page(twoShellFleet.list().map(({ recent, ...job }) => job), input));
  tool('get_2shell_scan', 'Read a detect-2shell fleet scan. Use section=results with offset/limit to page per-branch results, or section=recent for live progress events.', {
    scanId: id, section: z.enum(['results', 'recent']).optional(), status: z.enum(['vulnerable', 'clean', 'not-applicable', 'error']).optional(), ...paging,
  }, ({ scanId, section, status, ...input }) => {
    const job = twoShellFleet.get(scanId);
    if (section === 'recent') return { scanId, section, ...page(job.recent || [], input) };
    if (section === 'results') {
      const results = (job.result?.results || []).filter(item => !status || item.status === status);
      return { scanId, section, status: job.status, ...page(results, input) };
    }
    const { result, recent, ...overview } = job;
    return { ...overview, resultCount: result?.results?.length || 0 };
  });
  tool('cancel_2shell_scan', 'Cancel a running detect-2shell fleet scan. Partial results are never reported as clean.', { scanId: id, confirm: z.literal(true) },
    ({ scanId }) => twoShellFleet.cancel(scanId), { readOnly: false });
}

module.exports = { registerTwoShellTools };
