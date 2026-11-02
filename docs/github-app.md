# GitHub App authentication

Give Threatlint access to selected repositories without tying reviews to a personal token.
A GitHub App supplies short-lived installation tokens for Workbench Sources, CLI checkouts,
and optional PR comments/issues. Start with read-only permissions; add write access only for
the actions you intend to use.

## First successful connection

Follow steps 1–4 below. **Expected result:** `threatlint github login` validates the installation
and reports the visible repository count/owner; **Sources → GitHub** can list those repositories.
Validation contacts GitHub but does not post comments or issues.
Next: [check out a workspace](workbench.md#source-code-managers).

## 1. Create the App

In GitHub, open **Settings → Developer settings → GitHub Apps → New GitHub App**.
Use organization settings for an organization-owned App.

| Setting | Choose |
| --- | --- |
| Name / homepage | Your App's name and homepage |
| Webhook | Disable **Active**; Threatlint does not receive webhooks |
| Metadata | Read-only |
| Contents | Read-only for repository/branch listing and cloning |
| Pull requests | Read & write **only** for PR comments or `/threatlint` replies |
| Issues | Read & write **only** for `create_issues.py` |
| Other permissions | No access |
| Installation scope | **Only on this account** |

## 2. Generate a private key

Choose **Private keys → Generate a private key**. Store the downloaded PEM outside repositories.
For example, after replacing the filename:

```bash
mkdir -p ~/.threatlint/keys
mv ~/Downloads/my-app.private-key.pem ~/.threatlint/keys/my-app.pem
chmod 600 ~/.threatlint/keys/my-app.pem
```

Use owner-only filesystem access on your platform. Never commit or paste the key into a report.
The CLI needs system `openssl`; Workbench signing uses Node's `crypto`.

## 3. Install the App and find the IDs

1. **Install App** on the account/organization; prefer **selected repositories**.
2. Copy the **App ID** from General (Client ID also works).
3. Copy the **Installation ID** from the installation settings URL:
   `https://github.com/organizations/ORG/settings/installations/INSTALLATION_ID`.

## 4. Configure Threatlint

```bash
threatlint github login --app-id APP_ID --installation-id INSTALLATION_ID \
  --private-key-file ~/.threatlint/keys/my-app.pem
threatlint github status
```

Replace the uppercase placeholders. Without flags, `login` prompts interactively. It mints a
token and calls `GET /installation/repositories?per_page=1` **before** saving settings.
`--api-url` supports a configured GitHub Enterprise Cloud data-residency API; this does not add
custom-host support to Workbench Sources.

Alternatively, open **Workbench → Settings → GitHub**, enable **Use GitHub App**, enter IDs and
the absolute PEM path, then save. The server validates/signs; the browser receives status, not
the key or token. Sources connects as **GitHub App · owner** and refreshes tokens.
`threatlint setup` also offers App setup.

## Credential order

| Caller | Lookup order |
| --- | --- |
| Workbench Sources and CLI clones/checkouts | Configured App → `GH_TOKEN` → `GITHUB_TOKEN` → `gh auth token` |
| CI helpers (`post_pr_comment.py`, `create_issues.py`, `threatlint_chat.py`) | Workflow `GH_TOKEN` / `GITHUB_TOKEN` → App if Threatlint is installed → `gh auth token` |

A failing configured App emits a redacted warning and falls back. Check the credential source
before assuming App repository restrictions govern a run; a fallback token may have different access.
Copilot **model** authentication is separate; see [Workbench model settings](workbench.md#models-and-credentials).

## Where the configuration lives

`~/.threatlint/github-app.json` stores IDs, API URL, and the PEM **path**, not the PEM:

```json
{"appId":"APP_ID","installationId":"INSTALLATION_ID","privateKeyFile":"/absolute/path/my-app.pem","apiUrl":"https://api.github.com"}
```

`THREATLINT_HOME` relocates the file. POSIX permissions are `0600`; use appropriate Windows ACLs.
Environment overrides are field-by-field: `THREATLINT_GITHUB_APP_ID`,
`THREATLINT_GITHUB_APP_INSTALLATION_ID`, `THREATLINT_GITHUB_APP_PRIVATE_KEY_FILE`,
`THREATLINT_GITHUB_API_URL`.

For a CLI key in AWS Parameter Store, set `THREATLINT_GITHUB_APP_PRIVATE_KEY_PARAMETER` or
`githubAppPrivateKeyParameter` in `~/.threatlint/org.json`. The AWS session reads it and passes
the PEM to `openssl` through a pipe. A configured key-file path takes precedence.

## How tokens are handled

- RS256 App JWT: `iat` 60 seconds back, `exp` 9 minutes ahead, issuer = App ID.
- Token exchange requires HTTPS and refuses redirects; OS trust is used.
- Installation tokens normally last an hour; cached tokens refresh five minutes before expiry.
  They remain in memory. Clone credentials use `GIT_CONFIG_*` extra headers, not URLs,
  `.git/config`, or command-line tokens.
- Status/error output avoids credential values. Status can still identify configuration source
  and API URL; treat local configuration as sensitive.

## Rotation

1. Generate a new key and protect the file.
2. Re-run `login` with **all three** App ID, installation ID, and new key-file arguments, or
   update the Workbench settings. Validate access.
3. Revoke the old key in GitHub, then remove its local PEM.

`threatlint github logout` removes saved settings, **not** the PEM, environment overrides, or the
GitHub installation. To revoke access, suspend/uninstall the installation; do not rely on logout
or file deletion alone.

## Troubleshooting

| Symptom | Next action |
| --- | --- |
| Validation fails | Check App versus installation ID, installed account, key revocation, and system `openssl` |
| Repository absent | Check selected-repository installation access and Contents: read |
| PR/issue writes denied | Add only the required write permission; approve updated installation permissions |
| App warning but operation succeeds | Check fallback environment/CLI credentials and their permissions |
| Sources rejects custom host | Sources supports GitHub cloud, not GitHub Enterprise Server |

Validation coverage lives in mocked [CLI](../tests/test_github_app.py) and
[Workbench](../web/tests/github-app.test.cjs) tests; this guide does not certify a live installation.
