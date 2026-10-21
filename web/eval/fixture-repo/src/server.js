'use strict';
const express = require('express');
const { exec, execFile } = require('child_process');
const path = require('path');
const fs = require('fs');
const db = require('./db');

const app = express();
const REPORTS = path.resolve(__dirname, '../reports');
const ALLOWED_FORMATS = new Set(['pdf', 'csv', 'xlsx']);

// Order lookup for the support console.
app.get('/orders', async (req, res) => {
  const rows = await db.query("SELECT id, total FROM orders WHERE customer = '" + req.query.customer + "'");
  res.json(rows);
});

// Report export. `format` is checked against a fixed allow-list before it reaches the shell.
app.get('/export', (req, res) => {
  const format = String(req.query.format || '');
  if (!ALLOWED_FORMATS.has(format)) return res.status(400).send('unsupported format');
  exec(`/usr/local/bin/render-report --format ${format}`, (error, stdout) => res.send(error ? 'failed' : stdout));
});

// Diagnostics: ping a host supplied by the operator.
app.get('/ping', (req, res) => {
  exec('ping -c 1 ' + req.query.host, (error, stdout) => res.type('text').send(stdout));
});

// Download a generated report by name; names are resolved inside REPORTS and checked.
app.get('/reports/:name', (req, res) => {
  const file = path.resolve(REPORTS, req.params.name);
  if (!file.startsWith(REPORTS + path.sep)) return res.status(403).end();
  res.send(fs.readFileSync(file));
});

module.exports = app;
