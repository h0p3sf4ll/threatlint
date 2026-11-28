'use strict';

// Focused entry points reuse the existing source, model, evidence, and execution workflow.
(async () => {
  const groups = {
    designreviews: [
      ['model', 'Threat model', 'Map assets, actors, trust boundaries, and source-grounded threats.', ['threat-modeler']],
      ['paths', 'Attack paths', 'Examine how defenses and prerequisites combine into attack paths.', ['attack-tree']],
      ['scenarios', 'Adversarial scenarios', 'Develop bounded scenarios and validation plans grounded in the system.', ['red-team']],
    ],
    specialistreviews: [
      ['application', 'Application security', 'Review changes and the application boundaries that protect users and data.', ['code-reviewer', 'api-security-reviewer', 'auth-reviewer', 'business-logic-reviewer', 'client-security-reviewer', 'crypto-reviewer']],
      ['data', 'AI & data', 'Review AI authority, generated code, and sensitive data flows.', ['ai-security-reviewer', 'privacy-reviewer', 'secure-codegen-reviewer']],
      ['delivery', 'Delivery & infrastructure', 'Review dependencies, exposed credentials, infrastructure, and build pipelines.', ['dependency-auditor', 'xshell-detector', 'secrets-scanner', 'iac-reviewer', 'cicd-auditor']],
      ['verification', 'Verification & assurance', 'Verify fixes, compare revisions, correlate runtime evidence, and plan security acceptance.', ['verify-fix', 'threat-delta', 'runtime-reviewer', 'security-test-planner', 'compliance-checker']],
    ],
  };
  const node = (tag, className, text) => {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (text) element.textContent = text;
    return element;
  };
  const prepare = ids => document.dispatchEvent(new CustomEvent('threatlint:configure-review', { detail: { agents: ids } }));
  try {
    await window.ThreatlintProfile?.ready;
    const response = await (window.ThreatlintProfile?.fetch || fetch)('/api/agents');
    if (!response.ok) throw new Error('Specialists could not be loaded. Reload to retry.');
    const agents = await response.json();
    for (const [view, sections] of Object.entries(groups)) {
      const root = document.getElementById(`view-${view}`);
      const tabs = root.querySelector('[role=tablist]');
      const panels = root.querySelector('.specialist-panels'); panels.replaceChildren();
      const buttons = [];
      function select(index, focus = false) {
        buttons.forEach((button, i) => {
          button.setAttribute('aria-selected', String(index === i)); button.tabIndex = index === i ? 0 : -1;
          document.getElementById(button.getAttribute('aria-controls')).hidden = index !== i;
        });
        if (focus) buttons[index].focus();
      }
      for (const [key, title, description, names] of sections) {
        const ids = names.map(name => `appsec-${name}`);
        const available = ids.map(id => agents.find(agent => agent.id === id)).filter(Boolean);
        const tab = node('button', '', title); tab.type = 'button'; tab.id = `${view}-${key}-tab`;
        tab.setAttribute('role', 'tab'); tab.setAttribute('aria-controls', `${view}-${key}-panel`);
        const index = buttons.length; buttons.push(tab); tabs.append(tab);
        tab.addEventListener('click', () => select(index));
        tab.addEventListener('keydown', event => {
          const keys = { ArrowRight: (index + 1) % buttons.length, ArrowLeft: (index + buttons.length - 1) % buttons.length, Home: 0, End: buttons.length - 1 };
          if (Object.hasOwn(keys, event.key)) { event.preventDefault(); select(keys[event.key], true); }
        });
        const panel = node('section'); panel.id = `${view}-${key}-panel`; panel.setAttribute('role', 'tabpanel'); panel.setAttribute('aria-labelledby', tab.id);
        const heading = node('div', 'specialist-panel-heading'), intro = node('div');
        intro.append(node('h2', '', title), node('p', '', description)); heading.append(intro);
        if (available.length > 1) {
          const all = node('button', 'button secondary', `Prepare ${title.toLowerCase()} review →`); all.type = 'button';
          all.dataset.reviewAgents = available.map(agent => agent.id).join(',');
          all.addEventListener('click', () => prepare(available.map(agent => agent.id))); heading.append(all);
        }
        const grid = node('div', 'specialist-review-grid');
        for (const agent of available) {
          const card = node('article', 'specialist-review-card'); card.dataset.agentId = agent.id;
          card.append(node('h3', '', agent.label), node('p', '', agent.description), node('p', 'specialist-deliverable', `Deliverable: ${agent.deliverable}`));
          const button = node('button', 'button primary', 'Prepare review →'); button.type = 'button'; button.setAttribute('aria-label', `Prepare review: ${agent.label}`);
          button.dataset.reviewAgents = agent.id; button.addEventListener('click', () => prepare([agent.id])); card.append(button); grid.append(card);
        }
        if (!available.length) grid.append(node('p', '', 'These specialists are unavailable in this installation.'));
        panel.append(heading, grid); panels.append(panel);
      }
      select(0);
    }
    function lock(running = false) {
      for (const button of document.querySelectorAll('[data-review-agents]')) button.disabled = running || window.ThreatlintProfile?.permissions?.review === false;
    }
    document.addEventListener('threatlint:context', event => lock(event.detail.running)); lock();
    document.dispatchEvent(new CustomEvent('threatlint:request-context'));
  } catch (error) {
    for (const panels of document.querySelectorAll('.specialist-panels')) panels.replaceChildren(node('p', '', error.message));
  }
})();
