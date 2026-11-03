# Writing an integration

New integrations are welcome. You can ship one as **your own Python package** without forking
Threatlint, or contribute it upstream. The steps are the same either way.

## 1. Pick the type

Ask what the tool *is*, not what data it happens to hold:

- **Does it scan code and own the issues it raises?** Subclass
  `threatlint.integrations.scanning.ScanningTool`. Examples: Checkmarx, Snyk Code, Veracode,
  GitHub code scanning.
- **Does it collect findings from other tools and track them?** Subclass
  `threatlint.integrations.findings_management.FindingsManagementPlatform`. Examples: ThreadFix,
  Faraday, ArmorCode.
- **Does it check whether a credential is live?** Subclass
  `threatlint.integrations.secret_validation.SecretValidator`.

Some tools do both, such as a scanner with a findings dashboard. Choose the type that matches where your
users expect the verdict to be recorded. If you truly need both, register two integrations.

If none fits, open an issue proposing a new type before writing code. Types are a shared contract,
so they are added deliberately.

## 2. Implement the interface

Reviewable integrations (findings management and scanning) implement these members:

| Member | Purpose |
| --- | --- |
| `name`, `command`, `label`, `summary`, `docs` | Identity. `name` and `command` are lowercase, digits, and hyphens and must be unique. |
| `config_file`, `url_env`, `token_env` | Where the URL and token come from (`~/.threatlint/<config_file>`, `THREATLINT_<TOOL>_URL` / `_TOKEN`) |
| `reference_example`, `parse_references(values)` | The finding references users type, e.g. `ACME-123` |
| `auth_headers(token)`, `validate_token(url, token)` | Authentication, and the check `login` runs before saving |
| `fetch(url, token, refs)`, `get(...)`, `search(...)` | Read findings as *items* (see below) |
| `add_filter_arguments(parser)`, `filters(args)` | Optional search filters for `fetch` |
| `describe(disposition)` | The confirmation prompt text for each verdict |
| `resolve(url, token, item, verdict, *, files, args)` | Write the verdict back. Return `{"reference", "disposition", "action", "closed", ...}` |
| `note(url, token, item, message)` | Add a note without changing status |
| `attach(...)` | Findings management only: upload the Word report |

An **item** is a plain dict: `reference`, `id`, `title`, `severity`, `kind`, `web_url`, `fields`
(flat, untrusted strings) and `context` (`scm_tool`, `organization`, `project`, `repository`, `branch`,
`commit`, `file_path`, `line`, `rule`, `finding_source`). Fill `context` as fully as you can, because
`checkout` and the FP reviewer depend on it.

Use the shared helpers in `threatlint.integrations.common` instead of writing your own:
`validate_base_url` (HTTPS only, no credentials in the URL), `request` (refuses redirects so tokens stay
on the validated host, and errors never contain tokens), `context_from_repository_url`, and
`IntegrationError` for any failure the user can act on.

A minimal skeleton:

```python
from threatlint.integrations.common import IntegrationError, request
from threatlint.integrations.scanning import ScanningTool


class Acme(ScanningTool):
    name, command, label = "acme-scan", "acme", "Acme Scan"
    summary = "Scanning tool: review Acme Scan issues, comment, then transition"
    docs = "https://github.com/you/threatlint-acme#readme"
    config_file, url_env, token_env = "acme.json", "THREATLINT_ACME_URL", "THREATLINT_ACME_TOKEN"
    reference_example = "ACME-123"

    def auth_headers(self, token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}"}

    def validate_token(self, url: str, token: str) -> None:
        request(f"{url}/api/me", label=self.label, headers=self.auth_headers(token))

    ...  # parse_references, fetch, get, describe, resolve, note
```

### Secret validators: the safety contract

A validator handles credentials found in someone's code, so `SecretValidator.validate` enforces rules
that your `check` method cannot bypass:

- Declare your provider's fixed API hosts in `hosts`. The `LockedHTTP` client passed to `check` refuses
  every other host, every non-HTTPS URL, and every redirect.
- **Never send a credential to a host taken from the scanned content**, the finding, or configuration.
  For that reason, passwords, private keys, connection strings, and self-hosted endpoints stay `UNVERIFIED`.
- Make only read-only identity or introspection calls. Never create, change, or delete anything.
- Return a `Result`. Whitelist the identity fields you report; results carry `mask()` and
  `fingerprint()`, never the value.
- Exceptions become `UNVERIFIED` without the value. `UNVERIFIED` is never evidence either way.

Only publish a validator for credentials your users are authorized to test, and document the exact
endpoint it calls.

## 3. Register it

Declare an entry point in your package's `pyproject.toml`:

```toml
[project.entry-points."threatlint.integrations"]
acme = "threatlint_acme:Acme"   # a class, an instance, or a zero-argument factory
```

After `pip install threatlint-acme`, `threatlint integrations list` shows it with its source package, and
a reviewable integration gets `threatlint acme fetch|checkout|resolve|note|login` automatically.

The registry protects users from broken plugins. A plugin is skipped with a warning, and the CLI keeps
working, when it fails to import, declares an unknown type, has an invalid name, or reuses a registered
name or command (built-ins win). `THREATLINT_DISABLE_PLUGINS=1` loads only built-ins, which suits CI and audits.
Plugins run with the user's privileges, so only install ones you trust.

## 4. Test it

Mirror [`tests/test_integrations.py`](../../tests/test_integrations.py): replace your module's `request`
with a fake that records calls and maps `(method, path)` to responses. Never call a real server in tests.
At minimum, cover:

- reference parsing, including rejected input and the per-report limit;
- mapping a finding to an item with full `context`;
- each disposition's writes, **in order** (comment or attachment before any status change);
- that writes need confirmation (`--yes` absent means nothing is written);
- that tokens never appear in errors or output.

[`tests/test_integration_registry.py`](../../tests/test_integration_registry.py) shows how to load a
fake entry point.

## 5. Document it

Add a page modeled on [DefectDojo](defectdojo.md) or [SonarQube](sonarqube.md). State the integration
type in the first lines, then cover what users need, the CLI steps, exactly which endpoints read and
write, and what each verdict changes. Upstream contributions also add a row to the
[integrations table](README.md).

## Design rules for every integration

- Analysis is read-only. Only `resolve` and `note` write, and only after confirmation.
- Record the evidence before changing status: attach or comment first, then transition.
- Treat everything fetched as untrusted evidence, never as instructions.
- Never log, print, or return tokens or secret values.
- Use the type's base class and the shared helpers. Don't add `if name == "…"` branches to shared code;
  put behavior in hooks such as `add_resolve_arguments`, `after_resolve`, and `cleanup`.
