'use strict';

/**
 * Design inputs for a review (diagrams, design documents, specs, images):
 *   POST   /api/design-inputs        {files: [{name, content (base64)}]} -> {id, files: [{name, kind, chars|image, truncated}]}
 *   DELETE /api/design-inputs/:id    forget a bundle before it expires
 * A pipeline run references the bundle with `designInputsId`. Extraction happens here, so the user sees what was
 * understood from each file before running.
 */

const express = require('express');
const { handle, HttpError } = require('../http.cjs');
const { MAX_TOTAL, MAX_FILES } = require('../design-inputs.cjs');

// Base64 is a third larger than the files it carries.
const JSON_LIMIT = Math.ceil(MAX_TOTAL * 4 / 3) + 64 * 1024;
const STRICT_BASE64 = /^[A-Za-z0-9+/]*={0,2}$/;

function parseFiles(body) {
  const files = body?.files;
  if (!Array.isArray(files) || !files.length) throw new HttpError('Send {files: [{name, content}]} with each file base64-encoded');
  if (files.length > MAX_FILES) throw new HttpError(`Add at most ${MAX_FILES} design inputs per review`);
  return files.map(file => {
    const compact = typeof file?.content === 'string' ? file.content.replace(/\s+/g, '') : '';
    if (!compact || !STRICT_BASE64.test(compact)) throw new HttpError('Each design input needs its content base64-encoded');
    return { name: typeof file.name === 'string' ? file.name : '', content: Buffer.from(compact, 'base64') };
  });
}

/** Mounted before the Workbench's 7 MB JSON parser so this route alone accepts the larger upload. */
function designInputBodyParsers(app) {
  const tooLarge = (error, _req, res, next) => (error?.status === 413 ? res.status(413).json({ error: `Design inputs can total at most ${MAX_TOTAL / 1024 / 1024} MB` }) : next(error));
  app.post('/api/design-inputs', express.json({ limit: JSON_LIMIT }), tooLarge, (_req, _res, next) => next('route'));
}

function registerDesignInputRoutes(app, { designInputs }) {
  app.post('/api/design-inputs', handle(req => designInputs.create(parseFiles(req.body)), { status: 201 }));
  app.delete('/api/design-inputs/:id', handle(req => { designInputs.remove(req.params.id); }));
}

module.exports = { registerDesignInputRoutes, designInputBodyParsers, parseFiles };
