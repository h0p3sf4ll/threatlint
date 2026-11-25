const path = require('node:path');
const { publishedIds, retired } = require('./navigation.cjs');
const docsRoot = path.resolve(__dirname, '../docs');
const retiredFiles = new Set(retired.map(item => path.resolve(docsRoot, item.file)));

module.exports = {
  title: 'Threatlint Docs', tagline: 'Connect evidence to action',
  url: 'https://threatlint.dev', baseUrl: '/docs/', trailingSlash: true,
  favicon: '/assets/mark.svg', onBrokenLinks: 'throw', onBrokenAnchors: 'throw',
  organizationName: 'h0p3sf4ll', projectName: 'threatlint',
  presets: [['classic', {
    docs: { path: '../docs', routeBasePath: '/', sidebarPath: './sidebars.js',
      include: publishedIds.map(id => `${id}.md`),
      editUrl: 'https://github.com/h0p3sf4ll/threatlint/edit/main/docs/' },
    blog: false, theme: { customCss: './src/css/custom.css' },
  }]],
  markdown: { format: 'md',
    preprocessor: ({ filePath, fileContent }) => fileContent.replace(/^#\s+(.+)$/gm, (_match, title) => `# ${title.replace(/<[^>]*>/g, '').trim()}`).replace(/(\]\()([^\s)#]+)(#[^\s)]*)?(\))/g, (match, before, target, anchor = '', after) => {
      if (/^(?:[a-z]+:|\/|#)/i.test(target)) return match;
      const absolute = path.resolve(path.dirname(filePath), target);
      if (!target.endsWith('/') && absolute.startsWith(docsRoot + path.sep) && !retiredFiles.has(absolute)) return match;
      return `${before}https://github.com/h0p3sf4ll/threatlint/${target.endsWith('/') ? 'tree' : 'blob'}/main/${path.relative(path.resolve(__dirname, '..'), absolute).replaceAll(path.sep, '/')}${anchor}${after}`;
    }),
    parseFrontMatter: async params => {
      const result = await params.defaultParseFrontMatter(params);
      const heading = /^#\s+(.+)$/m.exec(result.content);
      if (!result.frontMatter.title && heading) result.frontMatter.title = heading[1].replace(/<[^>]*>/g, '').trim();
      if (params.filePath.replaceAll(path.sep, '/').endsWith('/integrations/README.md')) result.frontMatter.slug = '/integrations/overview';
      return result;
    },
    hooks: { onBrokenMarkdownLinks: 'throw' } },
  themeConfig: {
    docs: { sidebar: { hideable: true, autoCollapseCategories: true } },
    colorMode: { defaultMode: 'dark', respectPrefersColorScheme: true },
    navbar: { title: 'Threatlint', logo: { alt: 'Threatlint', src: '/assets/mark.svg', href: 'https://threatlint.dev/' }, items: [
      { href: 'https://threatlint.dev/', label: 'Home', position: 'left' },
      { type: 'docSidebar', sidebarId: 'docs', label: 'Docs', position: 'left' },
      { href: 'https://app.threatlint.dev', label: 'Open workbench', position: 'right' },
      { href: 'https://github.com/h0p3sf4ll/threatlint', label: 'GitHub', position: 'right' },
    ] },
    footer: { style: 'dark', copyright: 'Threatlint · Evidence-led application security' },
  },
};
