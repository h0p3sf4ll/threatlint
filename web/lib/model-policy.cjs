'use strict';

/**
 * Claude model policy: Sonnet for security scanning, Opus for everything else. Mirrors src/threatlint/models.py.
 *
 * SCAN_MODEL is the default for review/triage runs (pipeline playbooks, FP review, AVIT and scanner batches,
 * scan imports); GENERAL_MODEL for chat and other assistance. THREATLINT_SCAN_MODEL / THREATLINT_GENERAL_MODEL,
 * then the scanModel / generalModel keys of ~/.threatlint/org.json, override them. An explicit model chosen in
 * Settings or sent with a request always wins. Only the Claude provider uses these defaults.
 */

const { orgValue } = require('./org-config.cjs');

const SCAN_MODEL = 'claude-sonnet-5-5';
const GENERAL_MODEL = 'claude-opus-5-5';

function scanModel() { return orgValue('scanModel') || SCAN_MODEL; }
function generalModel() { return orgValue('generalModel') || GENERAL_MODEL; }

/** Default Claude model for a run purpose: 'chat' (and any non-review purpose) uses the general model. */
function defaultModel(purpose = 'review') { return purpose === 'review' ? scanModel() : generalModel(); }

/** The configured defaults, as shown in Settings. */
function modelPolicy() { return { scan: scanModel(), general: generalModel() }; }

module.exports = { SCAN_MODEL, GENERAL_MODEL, scanModel, generalModel, defaultModel, modelPolicy };
