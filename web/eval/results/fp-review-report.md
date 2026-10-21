# False Positive Review: fixture-repo (Orders service evaluation fixture)

| Field | Value |
|---|---|
| **Date** | Report date not independently established. The artifact says the AVITs were retrieved 2026-10-21 23:13 UTC. |
| **Reviewer** | appsec-fp-reviewer |
| **Input** | `servicenow-avits-7.md`: an export of ServiceNow `sn_vul_app_vulnerable_item` records, supplied by the user as untrusted evidence. |
| **Scanner** | Semgrep (CodeSecurity source). The scanner version used for the scan was not supplied. Validation commands below target the user's installed Semgrep Community Edition 1.107.0. |
| **Scan revision** | Not supplied in any AVIT field. |
| **Current revision** | Parent repository HEAD is `ea6adbff397f3a51a651562f5e795d974814735e` and the working tree is dirty. The `fixture-repo` files are **not tracked by git** (`git ls-files --error-unmatch src/server.js` fails), so they have no commit revision. The review used their current on-disk contents. |
| **Scope** | In scope: AVIT0090001–AVIT0090006 (the CodeSecurity view). Out of scope: AVIT0090007, which the artifact and the user both exclude from the AVR CodeSecurity view. It is mentioned here only and was not triaged. |
| **Files inspected** | `src/server.js` (all 38 lines), `app/views.py` (all 19 lines), `src/db.js`, `README.md`. There is no `package.json`, `requirements.txt`, Semgrep rule file, `.semgrepignore`, test suite, or server bootstrap/listener in the fixture. |
| **Findings reviewed** | 6 of 6 in scope |

---

## TIER 1 — EXECUTIVE SUMMARY

**Risk and decision**: Three of the six AVITs are real, high-impact vulnerabilities and need code fixes before anything else.
- **AVIT0090002** (`/ping`) and **AVIT0090006** (`/archive`) pass request parameters straight into a shell. Anyone who can reach the route can run arbitrary OS commands.
- **AVIT0090005** (`/greet`) was filed as raw-HTML XSS, but the real problem is worse. The HTML-escaped name is concatenated into the *template source* passed to `render_template_string`. HTML escaping does not neutralise Jinja2 `{{ }}` syntax, so this is a server-side template injection (SSTI). It allows XSS and very likely remote code execution.

No authentication middleware is registered on any inspected route. Whether the routes are reachable from the internet could not be established, because the fixture has no listener or deployment configuration.

The other three AVITs are scanner noise, each disproved by code on the same value and path:
- **AVIT0090001**: an exact-match allow-list limits the shell argument to three constant strings.
- **AVIT0090003**: a correct `path.resolve` + `startsWith(base + sep)` check confines the path.
- **AVIT0090004**: the response body is file content sent as a Buffer (`application/octet-stream`), not reflected request data.

These FP verdicts do **not** pre-approve any suppression. The proposed tuning is line-scoped, not validated, and needs scanner-owner approval.

**Finding Summary**

| Disposition | Count | AVITs |
|---|---|---|
| TRUE POSITIVE | 3 | AVIT0090002 (CRITICAL), AVIT0090005 (CRITICAL), AVIT0090006 (CRITICAL) |
| FALSE POSITIVE | 3 | AVIT0090001 (INFO), AVIT0090003 (INFO), AVIT0090004 (INFO) |
| AMBIGUOUS | 0 | — |

Severity is my own assessment. All six AVITs came in as "3 - Medium", which understates the three true positives.

| Accounting | Count |
|---|---|
| AVITs requested in artifact | 7 |
| Excluded by scope (AVIT0090007) | 1 |
| In-scope input findings | 6 |
| Malformed records | 0 |
| Duplicates | 0. AVIT0090001/0002 share a rule but have different root causes; AVIT0090003/0004 share a handler but are different rules. |
| Unique findings | 6 |
| Reviewed | 6 |
| Unreviewed | 0 |

**Original-to-review mapping**: FP-001 = AVIT0090001, FP-002 = AVIT0090002, FP-003 = AVIT0090003, FP-004 = AVIT0090004, FP-005 = AVIT0090005, FP-006 = AVIT0090006.

**Priority Actions**

| Priority | FP ID / Original | Decision | Required action | Business impact | Suggested owner | Effort | Acceptance criterion |
|---|---|---|---|---|---|---|---|
| P0 | FP-006 / AVIT0090006 | TP | Replace `shell=True` string with an argv list, add `--`, and confine the path to an archive root. Interim: block or disable `/archive` at the edge. | Unauthenticated RCE on the Flask host. Arbitrary files can be archived. | Orders service – Python/Flask team | 0.5–1 day | `;id` and `--checkpoint-action=…` payloads run no command; `../` and absolute paths return 403 |
| P0 | FP-002 / AVIT0090002 | TP | Validate the host, switch to `execFile` with argv, add `--` and a timeout. Interim: block `/ping` or put it behind operator auth. | Unauthenticated RCE on the Node host | Orders service – Node/Express team | 0.5 day | `127.0.0.1;id`, `$(id)` and `-f` return 400 with no child process; a valid host still pings |
| P0 | FP-005 / AVIT0090005 | TP | Pass the name as a template variable instead of concatenating it into template source. Interim: block `{`/`}` in `name` at the WAF. | SSTI, which gives XSS and likely RCE in the Flask process | Orders service – Python/Flask team | 1–2 hours | `name={{7*7}}` renders literally, not `49`; `<script>` is escaped |
| P2 | FP-001 / AVIT0090001 | FP | Optional: line-scoped `nosemgrep` with rationale, plus optional `execFile` hardening | Noise only | AppSec scanner owners + Node team | 1 hour | Scanner owner approves; line 27 is still reported |
| P2 | FP-003 / AVIT0090003 | FP | Optional: line-scoped `nosemgrep` with rationale | Noise only | AppSec scanner owners | 1 hour | Approved; traversal fixtures still flagged |
| P3 | FP-004 / AVIT0090004 | FP | Optional: explicit `Content-Type`/`nosniff`/`attachment` hardening, then a scoped suppression | Noise only; small defence-in-depth gain | Node team + scanner owners | 1–2 hours | Response headers verified; approved |

---

## TIER 2 — DETAILED FINDINGS

#### [FP-001] — Shell `exec` in `/export` with an allow-listed format argument

**Original finding**: AVIT0090001; javascript.lang.security.detect-child-process.detect-child-process; Semgrep (scan version not supplied); src/server.js:22
**Disposition**: FALSE POSITIVE
**Severity**: INFO
**Confidence**: CONFIRMED (in the disposition)
**Owner**: AppSec scanner owners (tuning); Orders service Node/Express team (optional hardening)
**Effort**: About 1 hour for a reviewed inline suppression. About 1 hour more for the optional `execFile` refactor. Both estimates assume a one-line, single-handler change.

**Finding and impact**: The rule claims that a value from a function argument (here, the `req` object) reaches `child_process.exec`, which could allow command injection. `GET /export` takes `req.query.format` and interpolates it into a shell command string. The scanner metadata rates this Medium. My independent assessment is that the interpolated value can only be one of three constant literals by the time it reaches the sink, so no injection is possible.

**Evidence**

```js
// src/server.js:10
const ALLOWED_FORMATS = new Set(['pdf', 'csv', 'xlsx']);
// src/server.js:20-22
const format = String(req.query.format || '');
if (!ALLOWED_FORMATS.has(format)) return res.status(400).send('unsupported format');
exec(`/usr/local/bin/render-report --format ${format}`, (error, stdout) => res.send(error ? 'failed' : stdout));
```

| Stage | Observation | Location |
|---|---|---|
| Source | `req.query.format` (unauthenticated query string) | src/server.js:20 |
| Transform | `String(... \|\| '')`. Arrays become comma-joined strings and objects become `[object Object]`. | src/server.js:20 |
| Control | `Set.has` does an exact SameValueZero comparison against `'pdf'`, `'csv'`, `'xlsx'`. On failure the handler returns early. | src/server.js:10, 21 |
| Sink | `exec` with a template literal, after the guard, using the same `format` variable | src/server.js:22 |
| Impact | Only `--format pdf|csv|xlsx` reaches the shell | — |

**Assessment and alternative interpretation**: The control acts on the same variable, sits before the sink, and leaves the rejected path with `return`. The variable is never reassigned. I considered three bypasses:
- **Array/object query values** (`format[]=pdf`, `format[a]=1`). `String(['pdf'])` is `'pdf'`, which is still a constant. Anything else fails `has`.
- **Encoding.** Express decodes the query before the handler runs, so the comparison sees the decoded value.
- **Whitespace or metacharacters.** An exact match rejects them.

The strongest counter-argument is "shell use is risky even with constants." That is a hardening point, not support for the rule's injection claim. The `/usr/local/bin/render-report` binary was not inspected. Its own behaviour is outside this rule.

- **Verified Safe Behavior**: The only strings that can reach the shell are `/usr/local/bin/render-report --format pdf`, `... csv` and `... xlsx`. The exact-match allow-list on the same value (src/server.js:21) runs before the sink and returns on rejection.
- **Proposed Tuning**: **Exact rule required** for any rule-level change; the original rule YAML was not supplied and no rule file exists in the repository. The lowest-risk option, which is not validated and needs approval, is a single-line, rule-ID-scoped inline suppression on line 22:
  ```js
  // nosemgrep: javascript.lang.security.detect-child-process.detect-child-process -- format restricted to ALLOWED_FORMATS (line 21); owner: AppSec; review if ALLOWED_FORMATS or the guard changes
  exec(`/usr/local/bin/render-report --format ${format}`, ...);
  ```
  A better long-term fix is to remove the shell entirely. This is optional hardening, not required to close the FP:
  ```diff
  -  exec(`/usr/local/bin/render-report --format ${format}`, (error, stdout) => res.send(error ? 'failed' : stdout));
  +  execFile('/usr/local/bin/render-report', ['--format', format], (error, stdout) => res.send(error ? 'failed' : stdout));
  ```
  `execFile` is already imported (src/server.js:3). Re-scan after this change. Do not assume the rule stops matching `execFile`.
- **Coverage and Blast Radius**: The inline suppression covers only line 22 and only this rule ID. Line 27 (FP-002) stays detected. Possible false negative: if someone later weakens or removes the guard on line 21 but leaves the comment in place, a real injection would be hidden. The review trigger mitigates this. A rule-level "allow-list guard sanitizer" would have a much larger blast radius, because `$SET.has($X)` guards are not always exact allow-lists. It is not recommended without the rule text.
- **Rule Regression Tests**: These fixtures are **ILLUSTRATIVE — NOT VALIDATED**. They only apply if a rule-level sanitizer is ever written.
  ```js
  // ruleid: javascript.lang.security.detect-child-process.detect-child-process
  app.get('/a', (req, res) => { exec('ping ' + req.query.host); });
  // ruleid: javascript.lang.security.detect-child-process.detect-child-process
  app.get('/b', (req, res) => { const f = String(req.query.f); if (f.length < 5) { exec(`x ${f}`); } });   // non-allow-list guard
  // ruleid: javascript.lang.security.detect-child-process.detect-child-process
  app.get('/c', (req, res) => { const f = String(req.query.f); if (!ALLOWED.has(f)) { log(); } exec(`x ${f}`); }); // guard without return
  // ok: javascript.lang.security.detect-child-process.detect-child-process
  app.get('/d', (req, res) => { const f = String(req.query.f); if (!ALLOWED.has(f)) return res.status(400).end(); exec(`x ${f}`); });
  ```
  Commands (NOT RUN): `semgrep --validate --config detect-child-process.yaml`; `semgrep --test --config detect-child-process.yaml tests/`. For the inline option, run `semgrep scan --config r/javascript.lang.security.detect-child-process.detect-child-process src/server.js` (NOT RUN; it fetches the rule from the registry). The expected result is that line 27 is reported and line 22 is not.
- **Approval and Rollback**: A scanner owner must approve. Scope is one line. Review the suppression whenever lines 10, 20–22 change. Roll back by deleting the comment line; detection comes back on the next scan.

---

#### [FP-002] — OS command injection in `/ping` via unvalidated `host` query parameter

**Original finding**: AVIT0090002; javascript.lang.security.detect-child-process.detect-child-process; Semgrep (scan version not supplied); src/server.js:27
**Disposition**: TRUE POSITIVE
**Severity**: CRITICAL
**Confidence**: CONFIRMED (complete source-to-sink path observed in code). Network exposure is not established.
**Owner**: Orders service – Node/Express team
**Effort**: About 0.5 day: one handler, validation, and tests. A test stack has to be added because none exists.

**Finding and impact**: `GET /ping` concatenates `req.query.host` straight into a shell command string. A request such as `/ping?host=127.0.0.1;id` (illustrative; not executed) runs arbitrary commands as the Node service account. The comment says the host is "supplied by the operator", but no authentication or authorization middleware is registered anywhere in `src/server.js`, so the comment is not an enforced control. Impact: full compromise of the service host, including access to the `pg` pool credentials loaded from the environment (`src/db.js:3`), and a foothold for lateral movement.

**Evidence**

```js
// src/server.js:26-28
app.get('/ping', (req, res) => {
  exec('ping -c 1 ' + req.query.host, (error, stdout) => res.type('text').send(stdout));
});
```

| Stage | Observation | Location |
|---|---|---|
| Source | `req.query.host`, a query string | src/server.js:27 |
| Transform | String concatenation, no validation | src/server.js:27 |
| Control | None. No `app.use` auth middleware exists in the file. | src/server.js:8–37 |
| Sink | `child_process.exec` (runs through `/bin/sh -c`) | src/server.js:3, 27 |
| Impact | Arbitrary command execution | — |

**Assessment and alternative interpretation**: The strongest alternative is that the route is internal-only or behind an operator gateway. There is no evidence of that: the fixture has no listener or deployment config, and even if there were, being internal does not remove an injection boundary. Switching to `execFile` alone would still let an attacker inject ping options (for example `-f` or `-s 65507`), so validation is part of the fix.

- **Proposed Fix** — **PROPOSED — NOT APPLIED**
  ```diff
   const { exec, execFile } = require('child_process');
  +const net = require('net');
  +const HOSTNAME_RE = /^(?!-)[A-Za-z0-9-]{1,63}(?:\.(?!-)[A-Za-z0-9-]{1,63})*$/;
  ...
   app.get('/ping', (req, res) => {
  -  exec('ping -c 1 ' + req.query.host, (error, stdout) => res.type('text').send(stdout));
  +  const host = req.query.host;
  +  if (typeof host !== 'string' || host.length > 253 || !(net.isIP(host) || HOSTNAME_RE.test(host))) {
  +    return res.status(400).type('text').send('invalid host');
  +  }
  +  execFile('ping', ['-c', '1', '--', host], { timeout: 5000 }, (error, stdout) => {
  +    if (error) return res.status(502).type('text').send('ping failed');
  +    res.type('text').send(stdout);
  +  });
   });
  ```
- **Implementation Notes**: `execFile` with an argv array removes the shell, which is the root cause. The validation rejects metacharacters, whitespace, leading `-`, arrays, and objects. `--` is a second guard against option injection. iputils and BSD `ping` both use getopt-style parsing that honours `--`; confirm this on the target image. On some distributions IPv6 needs `ping6` or `ping -6`. The timeout stops hung children. Rollout is a single deploy with no data migration; rollback restores the vulnerable code, so do not roll back without the interim block in place. Remaining risks: an unauthenticated user can still probe the network (SSRF-like reconnaissance), so also require operator authentication on this route.
- **Regression Tests** (**NOT RUN**). No test stack exists in the fixture, so Jest + supertest is assumed.
  - Allowed: `GET /ping?host=127.0.0.1` gives 200 with `text/plain`, and `execFile` is called with `['-c','1','--','127.0.0.1']` (mock `child_process`).
  - Attack: `host=127.0.0.1;id`, `host=$(id)`, `host=127.0.0.1|cat /etc/passwd`, `host=a%0aid` each give 400, and no child process is spawned.
  - Option injection: `host=-f` and `host=-s65507` give 400.
  - Boundary: a 254-character host gives 400; a 63-character label gives 200; `host=::1` gives 200.
  - Type bypass: `host[]=a&host[]=b` and `host[x]=1` give 400.
- **Acceptance Criteria**: Code review confirms no `exec` call takes request data on this route. The tests above pass in CI, and the CI evidence is attached. A re-scan no longer reports line 27, or any remaining report is re-triaged against the new code. Operator authentication on `/ping` is confirmed, or its absence is risk-accepted in writing.

---

#### [FP-003] — `path.resolve` with route parameter in `/reports/:name` (traversal check present)

**Original finding**: AVIT0090003; javascript.express.security.audit.express-path-join-resolve-traversal.express-path-join-resolve-traversal; Semgrep (scan version not supplied); src/server.js:32
**Disposition**: FALSE POSITIVE
**Severity**: INFO
**Confidence**: CONFIRMED (in the disposition)
**Owner**: AppSec scanner owners
**Effort**: About 1 hour for a reviewed inline suppression

**Finding and impact**: The rule claims that request input reaching `path.join`/`path.resolve` can allow directory traversal. The value does flow into `path.resolve`, but the result is checked against the base directory before it is used.

**Evidence**

```js
// src/server.js:9
const REPORTS = path.resolve(__dirname, '../reports');
// src/server.js:31-35
app.get('/reports/:name', (req, res) => {
  const file = path.resolve(REPORTS, req.params.name);
  if (!file.startsWith(REPORTS + path.sep)) return res.status(403).end();
  res.send(fs.readFileSync(file));
});
```

| Stage | Observation | Location |
|---|---|---|
| Source | `req.params.name` (Express percent-decodes it, so `%2F` becomes `/`) | src/server.js:32 |
| Transform | `path.resolve` produces an absolute, normalised path with `..` and `.` collapsed | src/server.js:32 |
| Control | `startsWith(REPORTS + path.sep)`, with an early `return` on failure | src/server.js:33 |
| Sink | `fs.readFileSync(file)`, using the same `file` variable | src/server.js:34 |
| Impact | Reads are confined to descendants of `REPORTS` | — |

**Assessment and alternative interpretation**: `path.resolve` normalises the path before the check, so `..%2F..%2Fetc%2Fpasswd` resolves outside `REPORTS` and gets a 403. An absolute input (`%2Fetc%2Fpasswd`) resolves to `/etc/passwd`, which also gets a 403. Appending `path.sep` blocks sibling-prefix bypasses such as `../reports-old/x`. The input `.` resolves to `REPORTS` itself and is rejected. A NUL byte makes `readFileSync` throw, which Express turns into a 500, not a read. A case-variant path on a case-insensitive filesystem would fail closed. The remaining gap is symlinks *inside* `REPORTS` that point elsewhere. Exploiting that needs write access to the reports directory, which no inspected code provides; this is a hardening note (use `fs.realpathSync` before the check). Separate from the rule's claim: no authorization limits *which* report a caller may download. That is an access-control question for the service owner, not traversal.

- **Verified Safe Behavior**: The containment check runs on the resolved path, before the read, and uses a separator-terminated prefix. Node's `path.resolve` semantics guarantee normalisation.
- **Proposed Tuning**: **Exact rule required**; the rule YAML is unavailable. The lowest-risk option, not validated and needing approval, is a line-scoped suppression on line 32:
  ```js
  // nosemgrep: javascript.express.security.audit.express-path-join-resolve-traversal.express-path-join-resolve-traversal -- resolved path confined by startsWith(REPORTS + path.sep) on line 33; review if guard changes
  ```
- **Coverage and Blast Radius**: One line, one rule ID. Possible false negative: the guard is later removed or changed (for example, the `+ path.sep` is dropped). A rule-level sanitizer keyed on `startsWith` is **not** recommended: `startsWith(BASE)` without a separator, or a check before normalisation, would be wrongly treated as safe.
- **Rule Regression Tests**: These fixtures are **ILLUSTRATIVE — NOT VALIDATED**.
  ```js
  // ruleid: javascript.express.security.audit.express-path-join-resolve-traversal.express-path-join-resolve-traversal
  app.get('/a/:n', (req, res) => { res.send(fs.readFileSync(path.join(BASE, req.params.n))); });
  // ruleid: javascript.express.security.audit.express-path-join-resolve-traversal.express-path-join-resolve-traversal
  app.get('/b/:n', (req, res) => { const f = path.resolve(BASE, req.params.n); if (!f.startsWith(BASE)) return res.end(); res.send(fs.readFileSync(f)); }); // no separator
  // ruleid: javascript.express.security.audit.express-path-join-resolve-traversal.express-path-join-resolve-traversal
  app.get('/c/:n', (req, res) => { if (!req.params.n.startsWith('x')) return res.end(); res.send(fs.readFileSync(path.join(BASE, req.params.n))); }); // check on raw input
  // ok: javascript.express.security.audit.express-path-join-resolve-traversal.express-path-join-resolve-traversal
  app.get('/d/:n', (req, res) => { const f = path.resolve(BASE, req.params.n); if (!f.startsWith(BASE + path.sep)) return res.status(403).end(); res.send(fs.readFileSync(f)); });
  ```
  Commands (NOT RUN): `semgrep --validate --config <rule.yaml>`; `semgrep --test --config <rule.yaml> <fixtures>`.
- **Approval and Rollback**: A scanner owner must approve. Review whenever lines 9 or 31–35 change. Roll back by deleting the comment.

---

#### [FP-004] — `res.send` of report file Buffer flagged as direct response write (XSS)

**Original finding**: AVIT0090004; javascript.express.security.audit.xss.direct-response-write.direct-response-write; Semgrep (scan version not supplied); src/server.js:34
**Disposition**: FALSE POSITIVE
**Severity**: INFO
**Confidence**: PLAUSIBLE (in the disposition). The named assumption is that the deployed Express version sets `application/octet-stream` for Buffer bodies. That is documented behaviour in Express 4 and 5, but the version is not pinned because there is no `package.json`.
**Owner**: AppSec scanner owners; Node team for optional header hardening
**Effort**: 1–2 hours

**Finding and impact**: The rule claims request data is written directly into the response, which could cause reflected XSS. The scanner most likely propagated taint from `req.params.name` through `file` and `readFileSync(file)` into `res.send`. What is actually written is the *content* of a file inside `REPORTS` (contained per FP-003), not request data. It is a `Buffer`.

**Evidence**

```js
// src/server.js:34
res.send(fs.readFileSync(file));
```

| Stage | Observation | Location |
|---|---|---|
| Source | `req.params.name` controls only *which* file is read | src/server.js:32 |
| Control | Containment check | src/server.js:33 |
| Transform | `fs.readFileSync(file)` with no encoding, which returns a `Buffer` | src/server.js:34 |
| Sink | `res.send(Buffer)`. No `Content-Type` is set earlier in the handler, and there is no global middleware. | src/server.js:8–35 |
| Impact | Express defaults Buffer bodies to `application/octet-stream`, which browsers do not render as HTML | — (dependency not inspected) |

**Assessment and alternative interpretation**: The strongest alternative is stored XSS: if a report contained attacker-influenced HTML and were served as `text/html`, it would run. With a Buffer body and no explicit type, Express sends `application/octet-stream`, which modern browsers treat as a download. The allow-listed export formats (`pdf`, `csv`, `xlsx`) are not HTML. The request value does not appear in the body. The verdict depends on the named Express behaviour, which is why confidence is PLAUSIBLE rather than CONFIRMED.

- **Verified Safe Behavior**: No request-derived bytes reach the body. The body is a Buffer with no HTML content type. *Not established*: the Express version, and whether a reverse proxy rewrites content types.
- **Proposed Tuning**: **Exact rule required**. Optional defence-in-depth first, **PROPOSED — NOT APPLIED**:
  ```diff
  -  res.send(fs.readFileSync(file));
  +  res.set('X-Content-Type-Options', 'nosniff');
  +  res.attachment(path.basename(file));
  +  res.type('application/octet-stream').send(fs.readFileSync(file));
  ```
  Then apply a line-scoped `// nosemgrep: javascript.express.security.audit.xss.direct-response-write.direct-response-write -- binary file body, octet-stream + attachment; review if content type changes`.
- **Coverage and Blast Radius**: One line. Possible false negative: a future change sets `res.type('html')` or reads with `'utf8'` while the suppression stays in place. Do not add a rule-wide sanitizer for `fs.readFileSync`, because file content can be attacker-influenced elsewhere.
- **Rule Regression Tests**: These fixtures are **ILLUSTRATIVE — NOT VALIDATED**.
  ```js
  // ruleid: javascript.express.security.audit.xss.direct-response-write.direct-response-write
  app.get('/a', (req, res) => { res.send('<p>' + req.query.q + '</p>'); });
  // ruleid: javascript.express.security.audit.xss.direct-response-write.direct-response-write
  app.get('/b/:n', (req, res) => { res.type('html').send(fs.readFileSync(path.join(BASE, req.params.n), 'utf8')); });
  // ok: javascript.express.security.audit.xss.direct-response-write.direct-response-write
  app.get('/c/:n', (req, res) => { res.type('application/octet-stream').send(fs.readFileSync(safePath(req.params.n))); });
  ```
  Commands (NOT RUN): `semgrep --validate --config <rule.yaml>`; `semgrep --test --config <rule.yaml> <fixtures>`. Header check (NOT RUN): a supertest assertion that `GET /reports/sample.pdf` returns `content-type: application/octet-stream` and `x-content-type-options: nosniff`.
- **Approval and Rollback**: Needs scanner-owner and Node-team approval, plus evidence of the Express version (lockfile) before the suppression is accepted. Remove the comment to restore detection.

---

#### [FP-005] — Server-side template injection in `/greet`: escaped input concatenated into `render_template_string` source

**Original finding**: AVIT0090005; python.flask.security.injection.raw-html-concat.raw-html-format; Semgrep (scan version not supplied); app/views.py:12
**Disposition**: TRUE POSITIVE
**Severity**: CRITICAL
**Confidence**: CONFIRMED (complete path observed in code; not executed)
**Owner**: Orders service – Python/Flask team
**Effort**: 1–2 hours

**Finding and impact**: The rule flags user input concatenated into a hand-built HTML string, which could cause XSS. The code comment presents `markupsafe.escape` as the defence. That defence is wrong for this sink: the concatenated string is the **Jinja2 template source** passed to `render_template_string`, not finished HTML. `escape` encodes only `& < > " '`, so Jinja syntax such as `{{ ... }}` and `{% ... %}` reaches the template engine and is evaluated.
- `name={{7*7}}` would render `49`.
- Payloads without quotes can reach Python internals through objects such as `request` and use `request.args` to supply strings. In an unsandboxed Jinja environment that commonly means code execution.
- The rule's XSS claim also holds through the same path (for example `{{ request.args.x|safe }}`).

The real issue (SSTI) is more severe than the rule's label.

**Evidence**

```python
# app/views.py:8-12
@app.route("/greet")
def greet():
    # The name is HTML-escaped before it is placed in the template source.
    name = escape(request.args.get("name", "guest"))
    return render_template_string("<h1>Hello " + str(name) + "</h1>")
```

| Stage | Observation | Location |
|---|---|---|
| Source | `request.args["name"]` (unauthenticated) | app/views.py:11 |
| Transform | `markupsafe.escape` (HTML-entity encoding only), then `str()` | app/views.py:3, 11–12 |
| Control | HTML escaping, which is the wrong context for template source. `{`, `}`, `%` and `.` pass through unchanged. | app/views.py:11 |
| Sink | `render_template_string(<concatenated source>)` | app/views.py:12 |
| Impact | Template evaluation, giving XSS and likely RCE | — |

**Assessment and alternative interpretation**: The alternative reading is "escaped, so safe," which is exactly what the code comment asserts. It fails because the sanitizer and the sink are in different contexts. No sandboxed environment and no other Jinja configuration is set (`app = Flask(__name__)`, app/views.py:5).

- **Proposed Fix** — **PROPOSED — NOT APPLIED**
  ```diff
   @app.route("/greet")
   def greet():
  -    # The name is HTML-escaped before it is placed in the template source.
  -    name = escape(request.args.get("name", "guest"))
  -    return render_template_string("<h1>Hello " + str(name) + "</h1>")
  +    # The name is passed as template data; Flask autoescapes string templates.
  +    name = request.args.get("name", "guest")
  +    return render_template_string("<h1>Hello {{ name }}</h1>", name=name)
  ```
- **Implementation Notes**: The template source becomes a constant, so user data can never be parsed as template syntax. That closes the root cause. Flask enables autoescaping for templates rendered from strings, so HTML escaping is kept. Do not pass a pre-escaped `Markup` value as well, or the output will be double-escaped. The `escape` import (app/views.py:3) becomes unused and can be removed. Behaviour does not change for normal names. The fix can be rolled back on its own, but rolling back reintroduces SSTI.
- **Regression Tests** (**NOT RUN**). pytest with the Flask test client is assumed.
  - Allowed: `GET /greet?name=Alice` returns a body containing `<h1>Hello Alice</h1>`. A request with no `name` returns `Hello guest`.
  - SSTI rejection: `name={{7*7}}` returns a body containing `{{7*7}}` and **not** `49`. `name={% raw %}x` renders literally with no 500.
  - XSS: `name=<script>alert(1)</script>` returns a body containing `&lt;script&gt;`.
  - Bypass: `name={{request.application}}` and `name={{config}}` render literally, and no config values appear in the body.
- **Acceptance Criteria**: No `render_template_string` call in the repository builds its source from request data (verify with a grep). The tests pass in CI and the evidence is attached. A re-scan is re-triaged.

---

#### [FP-006] — OS command injection in `/archive` via `subprocess.check_output(..., shell=True)`

**Original finding**: AVIT0090006; python.flask.security.injection.subprocess-injection.subprocess-injection; Semgrep (scan version not supplied); app/views.py:18
**Disposition**: TRUE POSITIVE
**Severity**: CRITICAL
**Confidence**: CONFIRMED (complete path observed; not executed). Exposure is not established.
**Owner**: Orders service – Python/Flask team
**Effort**: 0.5–1 day, because the permitted archive root has to be agreed with the service owner

**Finding and impact**: `GET /archive?path=...` concatenates the query value into a shell command run with `shell=True`. `path=.;id` (illustrative) runs arbitrary commands as the Flask process user. Even without shell metacharacters, `target` could archive any readable path (for example `/etc`) into a world-writable, predictable location (`/tmp/out.tgz`). No authentication is present.

**Evidence**

```python
# app/views.py:15-18
@app.route("/archive")
def archive():
    target = request.args.get("path", ".")
    return subprocess.check_output("tar -czf /tmp/out.tgz " + target, shell=True)
```

| Stage | Observation | Location |
|---|---|---|
| Source | `request.args["path"]` | app/views.py:17 |
| Transform | String concatenation | app/views.py:18 |
| Control | None | — |
| Sink | `subprocess.check_output(str, shell=True)` | app/views.py:18 |
| Impact | Command execution; arbitrary file archiving | — |

**Assessment and alternative interpretation**: No control exists. Removing `shell=True` alone is not enough: an argv element such as `--checkpoint-action=exec=sh` would still inject a GNU tar option that runs commands. The fix therefore needs `--` plus path confinement.

- **Proposed Fix** — **PROPOSED — NOT APPLIED**. `ARCHIVE_ROOT` is an assumed configuration value; the service owner must supply the real permitted root.
  ```diff
  -import subprocess
  -from flask import Flask, request, render_template_string
  +import os
  +import subprocess
  +from flask import Flask, abort, request, render_template_string
  ...
  +ARCHIVE_ROOT = os.path.realpath(os.environ["ARCHIVE_ROOT"])
  +
   @app.route("/archive")
   def archive():
  -    target = request.args.get("path", ".")
  -    return subprocess.check_output("tar -czf /tmp/out.tgz " + target, shell=True)
  +    requested = request.args.get("path", ".")
  +    target = os.path.realpath(os.path.join(ARCHIVE_ROOT, requested))
  +    if os.path.commonpath([ARCHIVE_ROOT, target]) != ARCHIVE_ROOT:
  +        abort(403)
  +    rel = os.path.relpath(target, ARCHIVE_ROOT)
  +    return subprocess.check_output(
  +        ["tar", "-czf", "/tmp/out.tgz", "-C", ARCHIVE_ROOT, "--", rel],
  +        timeout=60,
  +    )
  ```
- **Implementation Notes**:
  - The argv list removes shell interpretation, which is the root cause.
  - `--` stops tar option injection.
  - `realpath` + `commonpath` blocks `..`, absolute paths and symlink escapes.
  - Deployment order: provision the `ARCHIVE_ROOT` environment variable first. The proposed code fails at startup if it is missing, which is a deliberate fail-closed choice.
  - Remaining risk: the fixed `/tmp/out.tgz` path is predictable and shared, and other local users could pre-create or symlink it. Switch to `tempfile.mkstemp` or a private directory in a follow-up.
  - Add authentication.
  - Rolling back restores RCE, so keep the edge block in place during rollout.
- **Regression Tests** (**NOT RUN**). pytest + Flask test client is assumed, with `subprocess.check_output` monkeypatched.
  - Allowed: `path=subdir` calls argv `['tar','-czf','/tmp/out.tgz','-C',ROOT,'--','subdir']` with no `shell=True`.
  - Injection: `path=.;id`, `path=$(id)` and `path=. && id` result in no shell. In an integration test with a temporary root, no `id` output appears.
  - Option injection: `path=--checkpoint-action=exec=id` is passed after `--` as a literal filename, and tar fails with a "not found" error rather than executing anything.
  - Traversal: `path=../../etc`, `path=/etc`, and a symlink inside the root pointing to `/etc` each return 403.
  - Boundary: `path=.` archives the root and returns 200.
- **Acceptance Criteria**: No `shell=True` in `app/`. The tests pass in CI with evidence attached. The owner has documented `ARCHIVE_ROOT`. A re-scan is re-triaged.

---

## TIER 3 — ENGINEERING ACTION PLAN

**Suppression Impact Assessment**

| Proposal | IDs | Rule / scope | TPs retained | Possible false negatives | Validation | Approval | Rollback trigger |
|---|---|---|---|---|---|---|---|
| Inline `nosemgrep` at src/server.js:22 | FP-001 / AVIT0090001 | detect-child-process; 1 line | src/server.js:27 (FP-002) still reported | Guard on line 21 later weakened | NOT RUN | Unapproved | Any edit to lines 10, 20–22 |
| Inline `nosemgrep` at src/server.js:32 | FP-003 / AVIT0090003 | express-path-join-resolve-traversal; 1 line | All other resolve/join uses | Guard on line 33 changed | NOT RUN | Unapproved | Any edit to lines 9, 31–35 |
| Inline `nosemgrep` at src/server.js:34 (after header hardening) | FP-004 / AVIT0090004 | direct-response-write; 1 line | All other `res.send` uses | Content type changed to HTML or text | NOT RUN | Unapproved; needs Express version evidence | Content-type or encoding change |
| No path exclusions or `.semgrepignore` changes are proposed | — | — | — | — | — | — | — |

**Systemic Root Causes**
1. **Shell-string command construction** (FP-002, FP-006; also the FP-001 pattern). The same anti-pattern appears in both languages. A team standard should require argv APIs (`execFile`, `subprocess.run([...])`) and `--` before user operands, and ban `exec`/`shell=True` with any non-constant string.
2. **Sanitizer used in the wrong context** (FP-005). HTML escaping was trusted for a template-source sink. Coding guidance should state that template source must be constant.
3. **Missing authentication across all routes** (all `src/server.js` and `app/views.py` routes). Comments such as "supplied by the operator" are not enforced controls.
4. **Scanner noise** (FP-001, FP-003, FP-004): taint is reported despite an allow-list, a path-containment guard, or a binary body. Each is a local case, so line-scoped suppressions are the proportionate response, not rule-wide sanitizers.

**Remediation Roadmap**

| Priority | Finding | Action | Suggested owner | Effort | Dependencies | Acceptance | Residual risk |
|---|---|---|---|---|---|---|---|
| 0 (now) | FP-002, FP-005, FP-006 | Edge/WAF block or disable `/ping` and `/archive`; filter `{`/`}` in `/greet?name` | Platform/SRE | Hours | Deployment topology | Blocked requests confirmed in edge logs | Bypass via unfiltered internal paths |
| 1 | FP-006 | argv + `--` + `ARCHIVE_ROOT` confinement | Python/Flask team | 0.5–1 d | `ARCHIVE_ROOT` decision | Tests green; no `shell=True` | `/tmp/out.tgz` predictability |
| 1 | FP-002 | Validation + `execFile` + `--` + timeout | Node team | 0.5 d | Test stack (none exists) | Tests green | Network reconnaissance without auth |
| 1 | FP-005 | Constant template + context variable | Python/Flask team | 1–2 h | — | `{{7*7}}` rendered literally | None known |
| 2 | All routes | Add authN/authZ for operator and diagnostic routes | Service owner | TBD | Identity design | Unauthenticated requests get 401/403 | — |
| 3 | FP-001/003/004 | Scanner-owner review of line-scoped suppressions; optional hardening | AppSec scanner owners | 1–3 h | Rule text; Express lockfile | Re-scan shows only intended suppressions | Future guard regressions |

**Acceptance Matrix**

| Item | Criterion | Expected result | Status | Evidence required |
|---|---|---|---|---|
| FP-002 fix | Injection, option and type-bypass tests | 400, no spawn | NOT RUN | CI log + diff |
| FP-005 fix | SSTI/XSS tests | Literal rendering | NOT RUN | CI log + diff |
| FP-006 fix | Injection, option and traversal tests | No shell; 403 on escape | NOT RUN | CI log + diff + `ARCHIVE_ROOT` doc |
| FP-001 tuning | Scan of src/server.js | Line 27 reported, line 22 not | NOT RUN | `semgrep scan` output (1.107.0) |
| FP-003 tuning | Rule fixtures | ruleid/ok annotations behave as expected | Blocked (rule YAML unavailable) | Original rule + `semgrep --test` output |
| FP-004 tuning | Header test + Express version | octet-stream + nosniff | Blocked (no lockfile) | Lockfile + supertest output |

**Limitations and Open Questions**
- **AVIT0090007** was out of scope as instructed; it was not triaged.
- **No scan revision was supplied.** The fixture files are untracked in git, so I could not confirm that the code scanned matches the code inspected. All AVIT line numbers matched the expected constructs in the current files.
- **Original Semgrep rule YAML was not available**, so the tuning is limited to line-scoped suppressions and illustrative fixtures. The registry rules can be fetched for validation with `semgrep scan --config r/<rule-id> <path>` (NOT RUN; needs registry access).
- **Runtime facts not established**: Express and Flask versions, how the services are started and exposed, reverse-proxy behaviour, and any authentication outside the repository.
- **Other observation outside the supplied findings (not triaged, not numbered)**: src/server.js:14 builds a SQL query by concatenating `req.query.customer` (`"... WHERE customer = '" + req.query.customer + "'"`). That looks like SQL injection with no AVIT covering it. Open a separate tracker item and triage it with the same rigour.
- **Next step**: Platform/SRE should put the interim edge blocks for `/ping`, `/archive` and `/greet` in place now. In parallel, the service teams should implement the fixes for FP-006, FP-002 and FP-005.

All fixes, suppressions, fixtures and commands in this report are advisory proposals. **Nothing was applied to the repository, and no test, scan or exploit was run.**