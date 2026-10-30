# GitHub App authentication

Threatlint can use a **GitHub App** for all of its GitHub access: Sources → GitHub in the Workbench, cloning
GitHub repositories for AVIT, DefectDojo, SonarQube and DAST checkouts, PR comments, issues, and the PR chat
helper. An App gets a short-lived installation token (one hour) for each use. You don't need a personal access
token, and access ends when you uninstall the App.

Threatlint reads the App settings only from local configuration. Nothing about the App is built into the source,
and the configuration file is never committed.

## Credential order

Clones and checkouts (`threatlint avit checkout`, `threatlint dojo|sonar checkout`, DAST `--repo`) and the
Workbench try these sources in order:

1. **GitHub App**, when one is configured.
2. `GH_TOKEN`, then `GITHUB_TOKEN`.
3. `gh auth token` (the GitHub CLI sign-in).

If the App is configured but can't mint a token (a revoked key or an uninstalled App), Threatlint prints a
warning without any values and moves on to the next source. With no App configured, nothing changes from
before.

The CI helper scripts (`.github/scripts/post_pr_comment.py`, `create_issues.py`, `threatlint_chat.py`) take the
`GH_TOKEN` / `GITHUB_TOKEN` that the workflow gives them. They use the App only when neither variable is set
and `threatlint` is installed, and then fall back to `gh auth token`.

## 1. Create the App

In GitHub, go to **Settings → Developer settings → GitHub Apps → New GitHub App**. Use your organization's
settings for an organization-owned App.

- **Name / homepage:** any.
- **Webhook:** turn off **Active** (Threatlint doesn't receive webhooks).
- **Repository permissions** (least privilege):

  | Permission | Access | Needed for |
  | --- | --- | --- |
  | Metadata | Read-only | always (GitHub requires it) |
  | Contents | Read-only | listing repositories and branches, cloning |
  | Pull requests | Read & write | *only* if Threatlint should post PR comments or answer `/threatlint` |
  | Issues | Read & write | *only* if Threatlint should open issues (`create_issues.py`) |

  Leave every other permission at **No access**.
- **Where can this App be installed:** *Only on this account*.

## 2. Generate a private key

On the App's page, go to **Private keys → Generate a private key**. GitHub downloads a `.pem` file. Keep it
outside any repository, readable only by you:

```bash
mkdir -p ~/.threatlint/keys && mv ~/Downloads/<app-name>.*.private-key.pem ~/.threatlint/keys/
chmod 600 ~/.threatlint/keys/*.pem
```

## 3. Install the App and find the IDs

- **Install App** → choose the organization → *All repositories* or the repositories you review.
- **App ID**: shown at the top of the App's *General* page. The App's *Client ID* also works.
- **Installation ID**: the number at the end of the installation's settings URL
  (`https://github.com/organizations/<org>/settings/installations/<installation-id>`).

## 4. Configure Threatlint

**CLI**

```bash
threatlint github login --app-id <app-id> --installation-id <installation-id> \
  --private-key-file ~/.threatlint/keys/<app>.pem          # --api-url for GitHub Enterprise Cloud with data residency
threatlint github status    # "GitHub App (App ID set, installation ID set, private key file set ...)"
threatlint github logout    # removes the saved settings; the .pem stays where it is
```

`login` checks the settings before it saves them. It mints an installation token, calls
`GET /installation/repositories?per_page=1`, and prints only the repository count and owner. Run it without
flags to be prompted. `threatlint setup` offers the same step as an optional part of the wizard.

**Workbench**

Go to **Settings → GitHub**, check **Use GitHub App**, and enter the App ID, installation ID, and the absolute
path to the `.pem`. **Save GitHub App** validates the same way and writes the same file. After that,
**Sources → GitHub** connects on its own as *GitHub App · \<owner\>* and lists the installation's repositories.
The Workbench server signs the JWT and holds the token. The browser only ever learns which values are set.

## Where the configuration lives

`~/.threatlint/github-app.json` (`THREATLINT_HOME` relocates it), mode `0600`:

```json
{"appId": "<app-id>", "installationId": "<installation-id>", "privateKeyFile": "/absolute/path/to/app.pem", "apiUrl": "https://api.github.com"}
```

Only the key's **path** is stored, and the key is read from that file each time a token is minted. Environment
variables override the file field by field: `THREATLINT_GITHUB_APP_ID`, `THREATLINT_GITHUB_APP_INSTALLATION_ID`,
`THREATLINT_GITHUB_APP_PRIVATE_KEY_FILE`, `THREATLINT_GITHUB_API_URL`. To keep the PEM in AWS Parameter Store
instead of on disk, set `THREATLINT_GITHUB_APP_PRIVATE_KEY_PARAMETER` or `"githubAppPrivateKeyParameter"` in
`~/.threatlint/org.json`. The CLI reads the key with your AWS session and passes it to `openssl` over a pipe.

## How tokens are handled

- The App JWT is RS256 with `iat` set 60 seconds in the past, `exp` 9 minutes ahead, and `iss` set to the App ID.
  The CLI signs it with the system `openssl` (`openssl dgst -sha256 -sign <key file>`), so no Python crypto
  package is needed. The Workbench signs it with Node's `crypto`.
- The token exchange (`POST /app/installations/{id}/access_tokens`) requires HTTPS, refuses redirects, and
  uses the OS trust store.
- Installation tokens stay in memory only and are minted again five minutes before they expire. They're never
  written to disk, logs, `.git/config`, or command lines. Clones receive them as a `GIT_CONFIG_*` extra header.
- Error and status messages never include the App ID, installation ID, key path, key, JWT, or token.

## Rotation

1. On the App's page, **generate a new private key** and save it with `chmod 600`.
2. Run `threatlint github login --private-key-file <new.pem> ...`, or update the path in *Settings → GitHub*.
3. Delete the old key on GitHub, then delete the old `.pem` file.

To revoke all access right away, uninstall the App or suspend the installation. Installation tokens expire
within an hour in any case.
