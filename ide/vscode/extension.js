'use strict';

// Dependency-free: only the VS Code API and Node built-ins.
const vscode = require('vscode');
const { execFile } = require('node:child_process');
const path = require('node:path');

const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'];
const LEVEL = {
  critical: vscode.DiagnosticSeverity.Error, high: vscode.DiagnosticSeverity.Error,
  medium: vscode.DiagnosticSeverity.Warning, low: vscode.DiagnosticSeverity.Information,
  info: vscode.DiagnosticSeverity.Hint,
};
const DOCS = 'https://github.com/h0p3sf4ll/threatlint/blob/main/docs/ide.md';

let diagnostics;
let statusItem;
const fixes = new Map(); // `${uri}:${line}:${rule}` -> secure alternative

const GUARD_MAX_OUTPUT_BYTES = 32 * 1024 * 1024;
const GUARD_TIMEOUT_MS = 120_000;

function config() { return vscode.workspace.getConfiguration('threatlint'); }

function guard(targets, cwd) {
  // execFile with an argument array: file names never pass through a shell.
  return new Promise((resolve, reject) => {
    execFile(config().get('executable'), ['guard', '--format', 'json', '--fail-on', 'none', ...targets],
      { cwd, maxBuffer: GUARD_MAX_OUTPUT_BYTES, timeout: GUARD_TIMEOUT_MS, windowsHide: true }, (error, stdout, stderr) => {
        if (error && !stdout) return reject(new Error(error.code === 'ENOENT'
          ? 'threatlint CLI not found. Install it with `pip install threatlint` or set threatlint.executable.'
          : (stderr || error.message).trim()));
        try { resolve(JSON.parse(stdout).findings || []); } catch { reject(new Error('threatlint guard returned unreadable output')); }
      });
  });
}

function publish(findings, scannedUris, cwd) {
  const minimum = SEVERITIES.indexOf(config().get('minimumSeverity'));
  const byFile = new Map(scannedUris.map(uri => [uri.toString(), []]));
  for (const finding of findings) {
    if (SEVERITIES.indexOf(finding.severity) < minimum) continue;
    const uri = vscode.Uri.file(path.isAbsolute(finding.path) ? finding.path : path.join(cwd, finding.path));
    const line = Math.max(0, finding.line - 1);
    const range = new vscode.Range(line, Math.max(0, finding.column - 1), line, Number.MAX_SAFE_INTEGER);
    const item = new vscode.Diagnostic(range, `${finding.message}\nSecure alternative: ${finding.fix}`, LEVEL[finding.severity]);
    item.source = 'threatlint';
    item.code = { value: `${finding.rule_id} (${finding.cwe})`, target: vscode.Uri.parse(DOCS) };
    fixes.set(`${uri.toString()}:${line}:${finding.rule_id}`, finding.fix);
    if (!byFile.has(uri.toString())) byFile.set(uri.toString(), []);
    byFile.get(uri.toString()).push(item);
  }
  for (const [uri, items] of byFile) diagnostics.set(vscode.Uri.parse(uri), items);
  updateStatus();
}

function updateStatus() {
  let total = 0, blocking = 0;
  diagnostics.forEach((_uri, items) => {
    total += items.length;
    blocking += items.filter(item => item.severity === vscode.DiagnosticSeverity.Error).length;
  });
  statusItem.text = total ? `$(shield) Threatlint ${blocking ? `$(error) ${blocking}` : ''} $(warning) ${total - blocking}` : '$(shield) Threatlint $(check)';
  statusItem.tooltip = total
    ? `${total} insecure pattern(s) in scanned files. Click to rescan the workspace.`
    : 'No known-insecure patterns in scanned files. This is not a security approval — run a specialist review for sensitive changes.';
}

async function scanDocument(document) {
  if (document.uri.scheme !== 'file' || document.isUntitled) return;
  const folder = vscode.workspace.getWorkspaceFolder(document.uri);
  const cwd = folder ? folder.uri.fsPath : path.dirname(document.uri.fsPath);
  try { publish(await guard([document.uri.fsPath], cwd), [document.uri], cwd); }
  catch (error) { statusItem.text = '$(shield) Threatlint $(alert)'; statusItem.tooltip = error.message; }
}

async function scanWorkspace() {
  const folders = vscode.workspace.workspaceFolders || [];
  if (!folders.length) return vscode.window.showWarningMessage('Open a folder to scan with Threatlint.');
  await vscode.window.withProgress({ location: vscode.ProgressLocation.Window, title: 'Threatlint: scanning workspace' }, async () => {
    diagnostics.clear(); fixes.clear();
    for (const folder of folders) {
      try { publish(await guard([folder.uri.fsPath], folder.uri.fsPath), [], folder.uri.fsPath); }
      catch (error) { vscode.window.showErrorMessage(`Threatlint: ${error.message}`); return; }
    }
  });
  let total = 0; diagnostics.forEach((_u, items) => { total += items.length; });
  vscode.window.showInformationMessage(total ? `Threatlint found ${total} insecure pattern(s). See the Problems panel for secure alternatives.` : 'Threatlint: no known-insecure patterns matched.');
}

// Hover shows the secure alternative next to the finding; a quick fix inserts a justified suppression.
class SecureAlternativeHover {
  provideHover(document, position) {
    const items = (diagnostics.get(document.uri) || []).filter(item => item.range.contains(position));
    if (!items.length) return null;
    const markdown = new vscode.MarkdownString();
    for (const item of items) {
      const rule = String(item.code.value).split(' ')[0];
      markdown.appendMarkdown(`**Threatlint ${rule}**\n\n`);
      markdown.appendMarkdown(`✅ Secure alternative: ${fixes.get(`${document.uri.toString()}:${item.range.start.line}:${rule}`) || 'see docs'}\n\n`);
    }
    markdown.appendMarkdown(`[How Threatlint works in the IDE](${DOCS})`);
    return new vscode.Hover(markdown);
  }
}

class SuppressAction {
  provideCodeActions(document, _range, context) {
    return context.diagnostics.filter(item => item.source === 'threatlint').map(item => {
      const rule = String(item.code.value).split(' ')[0];
      const line = document.lineAt(item.range.start.line);
      const comment = ['python', 'ruby', 'yaml', 'shellscript', 'dotenv', 'toml'].includes(document.languageId) ? '#' : '//';
      const action = new vscode.CodeAction(`Threatlint: suppress ${rule} with a justification`, vscode.CodeActionKind.QuickFix);
      action.edit = new vscode.WorkspaceEdit();
      action.edit.insert(document.uri, line.range.start,
        `${line.text.slice(0, line.firstNonWhitespaceCharacterIndex)}${comment} threatlint-ignore: ${rule} REPLACE-WITH-VERIFIED-REASON\n`);
      action.diagnostics = [item];
      return action;
    });
  }
}

function activate(context) {
  diagnostics = vscode.languages.createDiagnosticCollection('threatlint');
  statusItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  statusItem.command = 'threatlint.scanWorkspace';
  updateStatus(); statusItem.show();
  context.subscriptions.push(diagnostics, statusItem,
    vscode.commands.registerCommand('threatlint.scanWorkspace', scanWorkspace),
    vscode.commands.registerCommand('threatlint.scanFile', () => vscode.window.activeTextEditor && scanDocument(vscode.window.activeTextEditor.document)),
    vscode.commands.registerCommand('threatlint.openWorkbench', () => vscode.env.openExternal(vscode.Uri.parse(config().get('workbenchUrl')))),
    vscode.commands.registerCommand('threatlint.installInstructions', () => {
      const folder = vscode.workspace.workspaceFolders?.[0];
      if (!folder) return vscode.window.showWarningMessage('Open a folder first.');
      execFile(config().get('executable'), ['ide', 'install', '--target', folder.uri.fsPath], { windowsHide: true }, (error, stdout) => {
        if (error) vscode.window.showErrorMessage(`Threatlint: ${error.message}`);
        else vscode.window.showInformationMessage('Threatlint secure-by-default instructions installed for Copilot, Cursor, Claude Code, and Windsurf.', 'Show details')
          .then(choice => { if (choice) { const out = vscode.window.createOutputChannel('Threatlint'); out.append(stdout); out.show(); } });
      });
    }),
    vscode.languages.registerHoverProvider({ scheme: 'file' }, new SecureAlternativeHover()),
    vscode.languages.registerCodeActionsProvider({ scheme: 'file' }, new SuppressAction(), { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }),
    vscode.workspace.onDidSaveTextDocument(document => { if (config().get('scanOnSave')) scanDocument(document); }),
    vscode.workspace.onDidOpenTextDocument(document => { if (config().get('scanOnOpen')) scanDocument(document); }),
    vscode.workspace.onDidCloseTextDocument(document => { diagnostics.delete(document.uri); updateStatus(); }),
  );
  for (const editor of vscode.window.visibleTextEditors) if (config().get('scanOnOpen')) scanDocument(editor.document);
}

function deactivate() {}

module.exports = { activate, deactivate };
