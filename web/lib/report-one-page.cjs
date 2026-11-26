'use strict';

/** Which finding a one-page summary covers when none is named: genuine findings first, then by severity. */
const SEVERITY = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'UNSPECIFIED'];

function primaryFinding(findings) {
  return [...findings].sort((left, right) => {
    const rank = finding => finding.disposition === 'FALSE POSITIVE' ? 2 : finding.unverified ? 1 : 0;
    return rank(left) - rank(right) || SEVERITY.indexOf(left.severity) - SEVERITY.indexOf(right.severity);
  })[0];
}

module.exports = { primaryFinding };
