'use strict';

/**
 * Minimal safe XML parser shared by the scan-report importer and design inputs: no DTDs, no entity declarations,
 * predefined and numeric character references only, and bounded element count and depth. Untrusted input in, a
 * plain { name, attrs, children, text } tree out; nothing is fetched or expanded.
 */

const { HttpError } = require('./http.cjs');

const MAX_XML_ELEMENTS = 500_000;
const MAX_XML_DEPTH = 200;

const fail = (message, status = 400) => { throw new HttpError(message, status); };
const norm = name => String(name).toLowerCase().replace(/[^a-z0-9]/g, '');

const XML_ENTITIES = { lt: '<', gt: '>', amp: '&', quot: '"', apos: "'" };
const xmlFail = message => fail(`The XML could not be parsed: ${message}`);

function decodeEntities(text) {
  if (!text.includes('&')) return text;
  let out = '', index = 0;
  while (index < text.length) {
    const amp = text.indexOf('&', index);
    if (amp < 0) { out += text.slice(index); break; }
    out += text.slice(index, amp);
    const semi = text.indexOf(';', amp);
    if (semi < 0 || semi - amp > 12) xmlFail('a bare "&" or malformed character reference');
    const name = text.slice(amp + 1, semi);
    if (Object.hasOwn(XML_ENTITIES, name)) out += XML_ENTITIES[name];
    else if (/^#(?:x[0-9a-f]{1,6}|\d{1,7})$/i.test(name)) {
      const code = name[1].toLowerCase() === 'x' ? Number.parseInt(name.slice(2), 16) : Number.parseInt(name.slice(1), 10);
      if (code > 0x10ffff) xmlFail('a character reference out of range');
      out += String.fromCodePoint(code);
    } else fail('XML with a DOCTYPE or entity declarations is not accepted (undefined entity reference found)');
    index = semi + 1;
  }
  return out;
}

function tagEnd(text, from) {
  let quote = null;
  for (let index = from; index < text.length; index++) {
    const char = text[index];
    if (quote) { if (char === quote) quote = null; }
    else if (char === '"' || char === "'") quote = char;
    else if (char === '>') return index;
    else if (char === '<') return -1;
  }
  return -1;
}

const NAME = /^[A-Za-z_][\w.:-]*$/;
function parseTag(raw) {
  let index = 0;
  const skip = () => { while (index < raw.length && ' \t\r\n'.includes(raw[index])) index++; };
  const word = () => { const start = index; while (index < raw.length && !' \t\r\n=/'.includes(raw[index])) index++; return raw.slice(start, index); };
  const name = word();
  if (!NAME.test(name)) xmlFail('an invalid element name');
  const attrs = {};
  for (;;) {
    skip();
    if (index >= raw.length) break;
    const key = word();
    if (!NAME.test(key)) xmlFail(`an invalid attribute on <${name}>`);
    skip();
    if (raw[index] !== '=') xmlFail(`attribute ${key} without a value`);
    index++; skip();
    const quote = raw[index];
    if (quote !== '"' && quote !== "'") xmlFail(`unquoted attribute ${key}`);
    const close = raw.indexOf(quote, index + 1);
    if (close < 0) xmlFail(`unterminated attribute ${key}`);
    attrs[key] = decodeEntities(raw.slice(index + 1, close));
    index = close + 1;
  }
  return { name, attrs };
}

/** A DOM of { name, attrs, children, text }; rejects any <!DOCTYPE>/<!ENTITY> markup before doing anything else. */
function parseXml(text) {
  const documentNode = { name: '#document', attrs: {}, children: [], text: '' };
  const stack = [documentNode];
  const top = () => stack[stack.length - 1];
  let index = 0, count = 0;
  while (index < text.length) {
    const lt = text.indexOf('<', index);
    const chunk = text.slice(index, lt < 0 ? text.length : lt);
    if (chunk) {
      if (stack.length === 1) { if (chunk.trim()) xmlFail('text outside the root element'); }
      else top().text += decodeEntities(chunk);
    }
    if (lt < 0) break;
    if (text.startsWith('<!--', lt)) { const end = text.indexOf('-->', lt + 4); if (end < 0) xmlFail('an unterminated comment'); index = end + 3; continue; }
    if (text.startsWith('<![CDATA[', lt)) {
      const end = text.indexOf(']]>', lt + 9);
      if (end < 0 || stack.length === 1) xmlFail('a misplaced or unterminated CDATA section');
      top().text += text.slice(lt + 9, end); index = end + 3; continue;
    }
    if (text.startsWith('<!', lt)) fail('XML with a DOCTYPE or entity declarations is not accepted');
    if (text.startsWith('<?', lt)) { const end = text.indexOf('?>', lt + 2); if (end < 0) xmlFail('an unterminated processing instruction'); index = end + 2; continue; }
    const gt = tagEnd(text, lt + 1);
    if (gt < 0) xmlFail('an unterminated tag');
    const raw = text.slice(lt + 1, gt);
    index = gt + 1;
    if (raw.startsWith('/')) {
      const name = raw.slice(1).trim();
      if (stack.length === 1 || top().name !== name) xmlFail(`mismatched closing tag </${name.slice(0, 60)}>`);
      stack.pop(); continue;
    }
    const selfClosing = raw.endsWith('/');
    const { name, attrs } = parseTag(selfClosing ? raw.slice(0, -1) : raw);
    if (stack.length === 1 && documentNode.children.length) xmlFail('more than one root element');
    if (++count > MAX_XML_ELEMENTS) xmlFail('too many elements');
    if (stack.length > MAX_XML_DEPTH) xmlFail('elements nested too deeply');
    const node = { name, attrs, children: [], text: '' };
    top().children.push(node);
    if (!selfClosing) stack.push(node);
  }
  if (stack.length !== 1) xmlFail(`<${top().name}> is not closed`);
  if (!documentNode.children.length) xmlFail('no root element');
  return documentNode.children[0];
}

const localName = name => norm(String(name).split(':').pop());
const child = (node, ...names) => { const wanted = names.map(norm); return node?.children.find(item => wanted.includes(localName(item.name))) || null; };
const textOf = (node, ...names) => { const found = names.length ? child(node, ...names) : node; return found ? found.text.trim() : ''; };
function descendants(node, name, found = []) {
  for (const item of node.children) { if (localName(item.name) === norm(name)) found.push(item); else descendants(item, name, found); }
  return found;
}

module.exports = { parseXml, descendants, localName, child, textOf, decodeEntities };
