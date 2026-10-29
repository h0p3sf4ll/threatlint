'use strict';

/**
 * Manual Invicti / MobSF report upload: POST creates a queued import (triage runs in the background), GET polls it,
 * and POST /:id/servicenow posts the finished report to ServiceNow only with {confirm: true}.
 */

const express = require('express');
const { handle, HttpError } = require('../http.cjs');
const { MAX_UPLOAD } = require('../scan-import.cjs');

const MAX_FIELD = 64 * 1024;
const MAX_PARTS = 40;
// JSON uploads carry the file base64-encoded (a third larger): 25 MB of report fits in 36 MiB of JSON.
const JSON_LIMIT = 36 * 1024 * 1024;

/** Minimal multipart/form-data reader for one file part plus small text fields. */
function parseMultipart(body, contentType) {
  const boundary = /boundary=(?:"([^"]{1,70})"|([^\s;]{1,70}))/i.exec(contentType || '');
  if (!boundary) throw new HttpError('multipart/form-data upload without a boundary');
  if (!Buffer.isBuffer(body) || !body.length) throw new HttpError('The upload is empty');
  const delimiter = Buffer.from(`--${boundary[1] || boundary[2]}`);
  const fields = {};
  let file = null, position = body.indexOf(delimiter), parts = 0;
  if (position < 0) throw new HttpError('Malformed multipart upload');
  for (;;) {
    position += delimiter.length;
    if (body.subarray(position, position + 2).toString() === '--') break;
    if (++parts > MAX_PARTS) throw new HttpError('Too many multipart fields');
    const headerEnd = body.indexOf('\r\n\r\n', position);
    const next = body.indexOf(Buffer.concat([Buffer.from('\r\n'), delimiter]), headerEnd);
    if (headerEnd < 0 || next < 0) throw new HttpError('Malformed multipart upload');
    const headers = body.subarray(position, headerEnd).toString('utf8');
    const content = body.subarray(headerEnd + 4, next);
    const disposition = /content-disposition:\s*form-data;([^\r\n]*)/i.exec(headers)?.[1] || '';
    const name = /\bname="([^"]*)"/i.exec(disposition)?.[1];
    const filename = /\bfilename="([^"]*)"/i.exec(disposition)?.[1];
    if (filename !== undefined) {
      if (file) throw new HttpError('Upload one report file at a time');
      file = { filename, content };
    } else if (name) {
      if (content.length > MAX_FIELD) throw new HttpError(`The ${name} field is too long`);
      fields[name] = content.toString('utf8');
    }
    position = next + 2;
  }
  if (!file) throw new HttpError('Attach the scan report as a file field');
  return { ...file, fields };
}

const STRICT_BASE64 = /^[A-Za-z0-9+/]*={0,2}$/;
function parseJsonUpload(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw new HttpError('Send {filename, content} with the report base64-encoded in content');
  const { filename, content, ...fields } = body;
  if (typeof content !== 'string' || !content) throw new HttpError('content (the base64-encoded report) is required');
  const compact = content.replace(/\s+/g, '');
  if (!STRICT_BASE64.test(compact)) throw new HttpError('content must be the base64-encoded report');
  const buffer = Buffer.from(compact, 'base64');
  if (buffer.length > MAX_UPLOAD) throw new HttpError(`The upload exceeds the ${MAX_UPLOAD / 1024 / 1024} MB limit`, 413);
  for (const [key, value] of Object.entries(fields)) if (typeof value === 'string' && value.length > MAX_FIELD) throw new HttpError(`The ${key} field is too long`);
  return { filename: typeof filename === 'string' ? filename : '', content: buffer, fields };
}

/** Upload-sized body parsers for this route only; mounted before the Workbench's 7 MB JSON parser. */
function scanImportBodyParsers(app) {
  const tooLarge = (error, _req, res, next) => (error?.status === 413 ? res.status(413).json({ error: `The upload exceeds the ${MAX_UPLOAD / 1024 / 1024} MB limit` }) : next(error));
  app.post('/api/scan-import', express.raw({ type: 'multipart/form-data', limit: MAX_UPLOAD + MAX_FIELD * 8 }), express.json({ limit: JSON_LIMIT }), tooLarge, (_req, _res, next) => next('route'));
}

function registerScanImportRoutes(app, { scanImports }) {
  app.post('/api/scan-import', handle(req => {
    const type = String(req.headers['content-type'] || '');
    const upload = /^multipart\/form-data/i.test(type) ? parseMultipart(req.body, type) : /json/i.test(type) ? parseJsonUpload(req.body) : (() => { throw new HttpError('Upload as multipart/form-data or JSON {filename, content}', 415); })();
    const { job } = scanImports.create(upload);
    return { id: job.id, status: job.status };
  }, { status: 201 }));
  app.get('/api/scan-import', handle(() => scanImports.list()));
  app.get('/api/scan-import/:id', handle(req => scanImports.get(req.params.id)));
  app.post('/api/scan-import/:id/servicenow', handle(req => scanImports.post(req.params.id, req.body || {})));
}

module.exports = { registerScanImportRoutes, scanImportBodyParsers, parseMultipart, parseJsonUpload, JSON_LIMIT };
