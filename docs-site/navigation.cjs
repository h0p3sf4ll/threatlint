'use strict';

// Keep repository runbooks and review reports outside the user documentation.
const category = (label, items, collapsed = true) => ({ type: 'category', label, collapsed, items });
const sidebar = [
  'index',
  category('Getting started', ['learning', 'setup', 'profiles', 'model-providers', 'troubleshooting'], false),
  category('Core workflows', ['workbench', 'security-scanner', 'threat-modeling', 'finding-intelligence', 'reports', 'dashboards', 'sidekick']),
  category('Integrations', ['integrations', 'github-app', 'aws-parameters', 'avit-integration', 'integrations/defectdojo', 'integrations/sonarqube', 'teams', 'mcp']),
  category('Automation', ['ide', 'github-actions', 'ci-templates', 'review-orchestration', 'avit-orchestrator']),
  category('Reference', ['mcp-tools', 'agents', 'runtime-redteam', 'assurance', 'semgrep-policies', 'integrations/README', 'integrations/authoring', 'web-app']),
];
const publishedIds = sidebar.flatMap(item => typeof item === 'string' ? [item] : item.items);
const retired = [
  { file: 'architecture.md', route: 'architecture' },
  { file: 'development.md', route: 'development' },
  { file: 'code-quality-review.md', route: 'code-quality-review' },
  { file: 'platform-validation.md', route: 'platform-validation' },
  { file: 'request-completion.md', route: 'request-completion' },
  { file: 'narration.md', route: 'narration' },
  { file: 'media/README.md', route: 'media' },
  { file: 'marketing-site.md', route: 'marketing-site' },
  { file: 'spaceship-deployment.md', route: 'spaceship-deployment' },
  { file: 'security-platform.md', route: 'security-platform', redirect: '/docs/security-scanner/' },
  { file: 'web-vps-deployment.md', route: 'web-vps-deployment' },
];
module.exports = { sidebar, publishedIds, retired };
