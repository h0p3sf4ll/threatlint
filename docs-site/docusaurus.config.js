const path = require('node:path');

module.exports = {
  title: 'Threatlint Docs', tagline: 'Connect evidence to action',
  url: 'https://threatlint.dev', baseUrl: '/docs/', trailingSlash: true,
  favicon: '/assets/mark.svg', onBrokenLinks: 'throw',
  organizationName: 'h0p3sf4ll', projectName: 'threatlint',
  presets: [['classic', {
    docs: { path: '../docs', routeBasePath: '/', sidebarPath: './sidebars.js',
      editUrl: 'https://github.com/h0p3sf4ll/threatlint/edit/main/docs/' },
    blog: false, theme: { customCss: './src/css/custom.css' },
  }]],
  markdown: { format: 'md',
    preprocessor: ({ filePath, fileContent }) => fileContent.replace(/^#\s+(.+)$/gm, (_match, title) => `# ${title.replace(/<[^>]*>/g, '').trim()}`).replace(/(\]\()([^\s)#]+)(#[^\s)]*)?(\))/g, (match, before, target, anchor = '', after) => {
      if (/^(?:[a-z]+:|\/|#)/i.test(target)) return match;
      const absolute = path.resolve(path.dirname(filePath), target);
      if (!target.endsWith('/') && absolute.startsWith(path.resolve(__dirname, '../docs') + path.sep)) return match;
      return `${before}https://github.com/h0p3sf4ll/threatlint/${target.endsWith('/') ? 'tree' : 'blob'}/main/${path.relative(path.resolve(__dirname, '..'), absolute).replaceAll(path.sep, '/')}${anchor}${after}`;
    }),
    parseFrontMatter: async params => {
      const result = await params.defaultParseFrontMatter(params);
      const heading = /^#\s+(.+)$/m.exec(result.content);
      if (!result.frontMatter.title && heading) result.frontMatter.title = heading[1].replace(/<[^>]*>/g, '').trim();
      if (params.filePath.replaceAll(path.sep, '/').endsWith('/integrations/README.md')) result.frontMatter.slug = '/integrations/overview';
      return result;
    },
    hooks: { onBrokenMarkdownLinks: ({ sourceFilePath, url }) => {
    const absolute = path.resolve(__dirname, sourceFilePath, '..', url.split('#')[0]);
    const relative = path.relative(path.resolve(__dirname, '..'), absolute).replaceAll(path.sep, '/');
    return `https://github.com/h0p3sf4ll/threatlint/blob/main/${relative}${url.includes('#') ? '#' + url.split('#')[1] : ''}`;
  } } },
  themeConfig: {
    colorMode: { defaultMode: 'dark', respectPrefersColorScheme: true },
    navbar: { title: 'Threatlint', logo: { alt: 'Threatlint', src: '/assets/mark.svg', href: '/' }, items: [
      { href: '/', label: 'Home', position: 'left' },
      { type: 'docSidebar', sidebarId: 'docs', label: 'Docs', position: 'left' },
      { href: 'https://app.threatlint.dev', label: 'Open workbench', position: 'right' },
      { href: 'https://github.com/h0p3sf4ll/threatlint', label: 'GitHub', position: 'right' },
    ] },
    footer: { style: 'dark', copyright: 'Threatlint · Evidence-led application security' },
  },
};
