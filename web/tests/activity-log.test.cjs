'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { createActivityLog } = require('../public/activity-log.js');

class Node {
  constructor(text = '') { this.value = text; this.children = []; this.dataset = {}; this.className = ''; this.classList = { contains: name => this.className.split(' ').includes(name) }; this.scrollHeight = 0; this.scrollTop = 0; this.clientHeight = 100; }
  get textContent() { return this.value + this.children.map(child => child.textContent).join(''); }
  set textContent(value) { this.value = value; this.children = []; }
  append(child) { child.parent = this; this.children.push(child); }
  replaceChildren() { this.children = []; this.value = ''; }
  remove() { this.parent.children.splice(this.parent.children.indexOf(this), 1); }
  get childElementCount() { return this.children.length; }
  get firstElementChild() { return this.children[0]; }
  get lastElementChild() { return this.children.at(-1); }
}
function fixture() {
  const container = new Node();
  return { container, log: createActivityLog(container, { document: { createElement: () => new Node(), createTextNode: text => new Node(text) }, labelFor: id => `Agent ${id}` }) };
}

test('six thousand alternating agent chunks keep recent labels within the shared DOM budget', () => {
  const { container, log } = fixture();
  for (let index = 0; index < 6000; index++) log.text(`fixture ${index}`, String(index % 2));
  assert.equal(container.childElementCount, 500);
  assert.match(container.lastElementChild.textContent, /Agent 1\nfixture 5999/);
  assert.match(container.firstElementChild.textContent, /Agent 0/);
  assert.ok(container.textContent.length <= 200_000);
  log.event('complete'); assert.equal(container.childElementCount, 500);
});

test('large streaming messages obey a total character budget and clear resets accounting', () => {
  const { container, log } = fixture();
  for (let index = 0; index < 30; index++) log.text('x'.repeat(100000), String(index % 2));
  assert.ok(container.textContent.length <= 200_000);
  log.clear(); assert.equal(container.childElementCount, 0);
  log.text('new run', 'fresh'); assert.equal(container.childElementCount, 1);
  assert.equal(container.textContent, 'Agent fresh\nnew run');
});
