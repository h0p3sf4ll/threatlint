'use strict';

/** Bounded, text-only activity rendering shared by event and interleaved agent streams. */
(() => {
  function createActivityLog(container, { document, labelFor = id => id, maxEntries = 500, maxCharacters = 200_000 } = {}) {
    let characters = 0;
    const length = node => node.textContent.length;
    function trim() {
      while (container.childElementCount > maxEntries || characters > maxCharacters) {
        const first = container.firstElementChild;
        if (!first) break;
        characters -= length(first);
        first.remove();
      }
    }
    const following = () => container.scrollHeight - container.scrollTop - container.clientHeight < 100;
    const follow = yes => { if (yes) container.scrollTop = container.scrollHeight; };
    function element(className, text) {
      const node = document.createElement('div');
      node.className = className; node.textContent = text;
      return node;
    }
    function event(message, kind = '') {
      const atBottom = following();
      const node = element(`log-event ${kind}`, String(message).slice(-Math.min(maxCharacters, 20_000)));
      container.append(node); characters += length(node); trim(); follow(atBottom);
    }
    function text(chunk, agentId = '') {
      const atBottom = following(), label = agentId ? `${labelFor(agentId)}\n` : '';
      let node = container.lastElementChild;
      if (!node?.classList.contains('log-text') || node.dataset.agentId !== agentId) {
        node = element('log-text', label); node.dataset.agentId = agentId;
        container.append(node); characters += length(node);
      }
      const previous = length(node);
      node.append(document.createTextNode(String(chunk).slice(-80_000)));
      if (length(node) > 100_000) node.textContent = `${label}[Earlier output omitted]\n${node.textContent.slice(-80_000)}`;
      characters += length(node) - previous;
      trim(); follow(atBottom);
    }
    return { event, text, clear() { container.replaceChildren(); characters = 0; } };
  }
  if (typeof module !== 'undefined' && module.exports) module.exports = { createActivityLog };
  else window.ThreatlintActivityLog = { createActivityLog };
})();
