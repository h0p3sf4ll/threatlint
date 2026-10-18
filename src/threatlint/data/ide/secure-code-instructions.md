# Threatlint secure-by-default coding rules

These rules apply to every piece of code you generate or edit in this repository. Apply them
without being asked. When a rule conflicts with a request, follow the rule, say so briefly, and
offer the secure alternative.

## Inputs and injection
- Treat all request data, files, environment-supplied URLs, model output, and third-party API
  responses as untrusted. Validate type, length, and format at the boundary with an allowlist.
- SQL: always use parameterized queries or the ORM query builder. Never build SQL with string
  concatenation, f-strings, `%`, `.format`, or template literals.
- Commands: never use `shell=True`, `os.system`, or `child_process.exec` with variables. Use
  `subprocess.run([...], shell=False)` or `execFile`/`spawn` with an argument array.
- Never call `eval`, `exec`, `new Function`, or similar on dynamic values. Use `json.loads`,
  `JSON.parse`, or an explicit dispatch table.
- Do not deserialize untrusted data with `pickle`, `marshal`, `yaml.load` (use `yaml.safe_load`),
  Java native serialization, or `BinaryFormatter`.
- File paths built from input must be resolved and confirmed to stay inside an allowed base
  directory before use.
- HTML: render text with `textContent`/JSX/auto-escaping templates. Do not use `innerHTML`,
  `dangerouslySetInnerHTML`, `v-html`, or `|safe` with dynamic values unless sanitized with
  DOMPurify (or the framework's sanitizer) immediately before use.
- Outbound requests to user-supplied URLs need an allowlist of hosts and must block private,
  loopback, and link-local addresses (SSRF).

## Authentication, authorization, and sessions
- Enforce authorization on the server for every endpoint and every object access: check that the
  caller owns or is permitted to act on the specific resource ID (no IDOR), including tenant ID.
- Verify every JWT signature with a pinned algorithm list; validate `iss`, `aud`, `exp`. Never
  accept `alg: none` or decode without verification for authorization decisions.
- Hash passwords with argon2id, bcrypt, or scrypt. Never MD5/SHA-1/unsalted SHA-256.
- Session cookies: `HttpOnly`, `Secure`, `SameSite=Lax` or `Strict`. Protect state-changing
  cookie-authenticated requests against CSRF.
- Rate-limit authentication, password reset, OTP, and other expensive endpoints.

## Secrets and cryptography
- Never hardcode credentials, tokens, keys, or connection strings. Read them from environment
  variables or a secrets manager, and add example values only as obvious placeholders.
- Generate tokens, IDs, and nonces with a CSPRNG: Python `secrets`, Node `crypto.randomBytes` /
  `crypto.randomUUID`, Go `crypto/rand`. Never `random` or `Math.random`.
- Use vetted high-level libraries (libsodium, `cryptography` Fernet/AESGCM, Web Crypto). Use
  authenticated encryption (AES-GCM, ChaCha20-Poly1305) with unique nonces. Never ECB.
- Never disable TLS verification (`verify=False`, `rejectUnauthorized: false`,
  `InsecureSkipVerify: true`). Trust a private CA explicitly instead.

## Configuration and errors
- Default to secure configuration: debug off, explicit CORS origin allowlist (never `*` with
  credentials), security headers on, least-privilege IAM and tokens.
- Return generic error messages to clients; log details server-side without secrets or PII.
- Do not log credentials, tokens, full request bodies, or personal data.

## Dependencies and CI
- Prefer the standard library or well-maintained packages; pin versions in lockfiles. Do not add
  install scripts that download and execute remote code.
- In CI, pin third-party actions to a commit SHA, grant the minimal `permissions:`, and never
  interpolate untrusted `${{ github.event.* }}` values directly into `run:` scripts.

## AI/LLM features
- Treat model output as untrusted input: validate before using it in SQL, shells, file paths,
  HTML, or tool calls. Enforce tool authorization in code, not in the prompt.

## Working with threatlint
- After generating or editing code, run `threatlint guard <changed files>` (or rely on the
  configured hook) and fix every finding by applying the listed secure alternative.
- Only suppress a verified false positive with `threatlint-ignore: RULE-ID <reason>` on the same
  line or the line above. Never add blanket suppressions.
- For security-sensitive changes (auth, crypto, payments, tenancy, file handling), recommend a
  review with the `appsec-code-reviewer` agent before merge.
