'use strict';

/** Shared, evidence-derived grouping. Unknown classifications remain visible. */
function findingType(item = {}) {
  for (const text of [item.findingType, item.cwe, item.title, item.rule].filter(Boolean).map(value => String(value).toLowerCase())) {
  for (const [pattern, label] of [
    [/cwe[- :]*(?:798|259|321|522)\b|exposed.secret|hardcoded|secret.detect|credential.leak/, 'Exposed secrets'],
    [/cwe[- :]*89\b|sql.?injection|\bsqli\b/, 'SQL injection'],
    [/cwe[- :]*(?:79|80)\b|cross.site.script|\bxss\b/, 'Cross-site scripting (XSS)'],
    [/cwe[- :]*78\b|command.injection|os.injection/, 'Command injection'],
    [/cwe[- :]*918\b|server.side.request|\bssrf\b/, 'Server-side request forgery'],
    [/cwe[- :]*22\b|path.traversal|directory.traversal/, 'Path traversal'],
    [/cwe[- :]*(?:284|285|639|862|863)\b|access.control|authorization|\bidor\b/, 'Access control'],
    [/cwe[- :]*(?:287|306)\b|authentication|session.fixation/, 'Authentication'],
    [/\bcve-\d|vulnerable.depend|outdated.package/, 'Vulnerable dependencies'],
    [/cwe[- :]*(?:327|328)\b|weak.crypto|insecure.hash/, 'Cryptography'],
  ]) if (pattern.test(text)) return label;
  }
  return 'Other / unclassified';
}
module.exports = { findingType };
