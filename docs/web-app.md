# Threatlint web app

The web app adds Auth0 sign-in to the same Workbench used by the desktop app. Users sign in with Google, Apple, GitHub or an approved enterprise SSO connection. Threatlint does not provide a local username/password login or password registration. Each verified identity has its own settings, repository sessions, reports, conversations, dashboards and running jobs. Visitors cannot select another identity's workspace by supplying a profile ID.

The default deployment runs each user's Workbench in a separate Docker container with a separate named home volume. The gateway authenticates HTTP and WebSocket requests before forwarding them to that user's container. Desktop startup remains available through `npm run desktop` and the original local Workbench through `npm start`. Those local entry points keep the operating-system user's existing storage and credentials; they require neither Auth0 nor a company registry.

For the Spaceship VPS deployment, service files and HTTPS configuration, see [deploy the web app on a VPS](web-vps-deployment.md). The existing Spaceship shared hosting serves the marketing site separately.

## Configure Auth0

The application uses these values:

| Setting | Value |
| --- | --- |
| Auth0 domain | `threatlint.us.auth0.com` |
| SPA client ID | `eysUAb8yPNapU4TXqRHpIfhSX4xC4Qqy` |
| Application origin | `https://app.threatlint.dev` |
| Allowed Callback URLs | `https://app.threatlint.dev/` |
| Allowed Logout URLs | `https://app.threatlint.dev/` |
| Allowed Web Origins | `https://app.threatlint.dev` |
| API identifier / token audience | `https://threatlint.dev/api` |

These are application configuration values, including a public SPA client ID. This flow does not use an Auth0 client secret.

Complete the following in the Auth0 Dashboard before a production sign-in:

1. Open the existing application with the client ID above and confirm its type is **Single Page Application**, token endpoint authentication method is **None**, and its callback, logout and web-origin allowlists match the table. Use Authorization Code with PKCE through the browser SDK. Set the JWT signature algorithm to **RS256** and enable OIDC Conformant. See the [official SPA configuration guide](https://auth0.github.io/auth0-spa-js/index.html#configure-auth0).
2. Create or confirm the custom API with identifier **`https://threatlint.dev/api`** and **RS256** signing. Authorize this SPA to request access to that API under the tenant's application-access policy. The audience must identify this custom API, rather than the Auth0 Management API. The browser requests the `openid profile email` scopes for identity information. An access token may contain both this API and the tenant's `/userinfo` URL in its audience array; no custom claims or Auth0 Action are required. See [Auth0's audience documentation](https://auth0.com/docs/secure/tokens/access-tokens/get-access-tokens#multiple-audiences).
3. Under **Authentication > Social**, configure Google, Apple and GitHub using your own production identity-provider credentials, then enable those connections for this SPA. The expected connection names are `google-oauth2`, `apple` and `github`; environment overrides are available when the tenant uses other names. Follow each provider's Auth0 setup guide for its provider-side callback and credential requirements. See [Auth0 social identity providers](https://auth0.com/docs/authenticate/identity-providers/social-identity-providers).
4. Configure approved enterprise identity providers under **Authentication > Enterprise** and enable them for this SPA. The SSO action uses Auth0 Universal Login, where the tenant's connection discovery and enterprise policy select the provider.
5. Disable **all Database connections** for this SPA, including `Username-Password-Authentication`, and disable database sign-up. Enable only the three social connections and approved enterprise connections. The backend also rejects Auth0 database identities whose subject starts with `auth0|`.

Auth0 Dashboard changes require tenant administration. This repository does not include an Auth0 Management connection or credentials and does not automatically create APIs, enable connections or configure provider secrets. The supplied domain and client ID alone do not establish that those tenant settings are complete.

## Authentication and profile identity

The browser uses the official `@auth0/auth0-spa-js` SDK for Authorization Code with PKCE. The gateway uses the official `@auth0/auth0-express-api` SDK to validate the API access token's signature, issuer, audience and authorized SPA client. It then obtains identity information through the official `@auth0/auth0-auth-js` SDK's UserInfo operation and binds the resulting server session to that identity. Session cookies are HttpOnly and bounded by the validated access token's expiry.

Personal profiles use the verified issuer and subject (`iss` + `sub`), which map to a stable internal profile ID. Company profiles additionally include the verified Auth0 organization ID. Email addresses are display information and never merge profiles. Signing into the same identity and organization on another browser restores that profile's saved settings. Different identity-provider accounts remain separate unless Auth0 has already linked them under the same verified subject.

## Company sign-in

Company entry points use `https://app.threatlint.dev/c/<slug>/login`. An administrator maps each slug to an Auth0 Organization in a service-owned JSON registry, then sets `THREATLINT_COMPANIES_FILE` to its absolute path. Start with `web/companies.example.json` and replace the example organization IDs with real IDs from the configured tenant:

```json
[
  { "slug": "acme", "name": "Acme", "auth0OrganizationId": "org_0000000000000001" }
]
```

The zeros above are an example ID, not an existing organization. Slugs and organization IDs must each be unique. Keep this file outside the website's document root, readable by the service and writable only by administrators. Restart the gateway after registry changes. Leave the variable unset for personal sign-in without company entry points.

In Auth0, enable Organizations for this SPA and select **Both** personal and business users (`organization_usage=allow`) to retain personal sign-in. Create each organization, enable its approved connections and add its members. Organizations availability depends on the tenant's Auth0 plan. Do not assume email-domain matching grants membership; with a Both application, provision membership explicitly through the Dashboard or an authorized management workflow. See [organization behavior](https://auth0.com/docs/manage-users/organizations/configure-organizations/define-organization-behavior) and [auto-membership requirements](https://support.auth0.com/center/s/article/organization-auto-membership-feature-requirements).

The browser SDK passes the registry's immutable Organization ID through its `organization` parameter. All companies use the same root callback `https://app.threatlint.dev/`; no per-company Auth0 callback is needed. The gateway accepts company membership only from the validated token's `org_id` matching the selected registry organization. A URL slug or email domain cannot grant company access. Company A, company B and personal profiles remain separate for the same person. See [Auth0 organization tokens](https://auth0.com/docs/manage-users/organizations/using-tokens).

There are no password-creation commands, local password endpoints or development authentication bypasses. Old `accounts.json` files from the earlier local-account implementation are ignored. Their profile files are retained, but federated sign-in creates its own profile; legacy data is not automatically associated by matching email. Any future migration must explicitly prove the destination identity and preserve the source data.

## Requirements

- Node.js 22.12.0 or later and npm on the gateway host.
- Docker Engine, with the Docker CLI available to the gateway service account.
- A persistent, access-restricted directory for profile identity and session data.
- An HTTPS reverse proxy for a public deployment.
- Network access to the configured Auth0 domain and from profile containers to the model providers, source hosts, trackers and applications users choose to assess.

The gateway needs permission to create containers and named volumes. Run it as a dedicated service account on a dedicated host. Profile containers do not receive the Docker socket, gateway credentials, gateway state directory or another profile's volume.

## Build and start

Run these commands from the repository root:

```sh
docker build -f Dockerfile.web -t threatlint-profile:local .
cd web
npm ci --omit=dev --ignore-scripts
```

Copy `.env.example` to `.env`, adjust the state directory for your host, and start with Node's environment-file support:

```sh
node --env-file=.env web-server.cjs
```

Alternatively, configure environment variables in your service manager or shell and run `npm run start:web`. The default origin is `https://app.threatlint.dev`. For example, in a POSIX shell:

```sh
export AUTH0_DOMAIN=threatlint.us.auth0.com
export AUTH0_CLIENT_ID=eysUAb8yPNapU4TXqRHpIfhSX4xC4Qqy
export AUTH0_AUDIENCE=https://threatlint.dev/api
export THREATLINT_WEB_ORIGIN=https://app.threatlint.dev
export THREATLINT_WEB_STATE_DIR=/var/lib/threatlint-web
export THREATLINT_PROFILE_IMAGE=threatlint-profile:local
export THREATLINT_PROFILE_NAMESPACE=threatlint-production
```

Or in PowerShell:

```powershell
$env:AUTH0_DOMAIN = 'threatlint.us.auth0.com'
$env:AUTH0_CLIENT_ID = 'eysUAb8yPNapU4TXqRHpIfhSX4xC4Qqy'
$env:AUTH0_AUDIENCE = 'https://threatlint.dev/api'
$env:THREATLINT_WEB_ORIGIN = 'https://app.threatlint.dev'
$env:THREATLINT_WEB_STATE_DIR = 'C:\ProgramData\ThreatlintWeb'
$env:THREATLINT_PROFILE_IMAGE = 'threatlint-profile:local'
$env:THREATLINT_PROFILE_NAMESPACE = 'threatlint-production'
```

Start the gateway in the configured environment:

```sh
npm run start:web
```

Auth0 controls which identities may sign in. Threatlint creates the durable profile on the first accepted federated sign-in. Do not add a client secret to the SPA environment.

The gateway binds to `127.0.0.1:3000` by default. Point the reverse proxy at that address and preserve the incoming Host header. The externally visible origin must match `THREATLINT_WEB_ORIGIN`, including the port when nonstandard. Forward WebSocket upgrades as well as HTTP requests. Terminate TLS at the proxy and keep the backend listener off the public network.

`THREATLINT_MAX_PROFILES` limits active profile workers and defaults to `8`. Workers stay active until the gateway stops; signing out does not evict a worker or cancel its background jobs. Size this limit and host resources for your expected users. A request from a new account receives an unavailable response when the limit is reached.

An nginx location, inside the HTTPS server block for `app.threatlint.dev`:

```nginx
location / {
    proxy_pass http://127.0.0.1:3000;
    proxy_http_version 1.1;
    proxy_set_header Host $http_host;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_read_timeout 3600s;
}
```

## What is saved to a profile

Model selections and other non-secret preferences are saved on the server, so signing into the same account restores them on another browser. ServiceNow, Semgrep, Azure DevOps and GitHub settings use the account's own Threatlint configuration directory. Reports, repository history, conversations and dashboards use the account's Workbench directory. The application does not import the gateway host's desktop credentials or an earlier visitor's browser preferences.

Provider API keys entered for a review retain the existing Workbench behavior: they stay in memory for the browser session. They are not saved as ordinary model preferences. Integration credentials explicitly saved by their settings forms remain in the profile's private volume and are not returned by settings reads. Protect gateway state and profile-volume backups as sensitive data.

The same views remain available for reviewing code, running security agents, finding triage, importing scanner results, scanning an application, exporting reports, asking questions, working with dashboards and using Sidekick. Actions execute on the server in the account's container. Repository folders, local model URLs and application URLs refer to that container's environment. A remote web app cannot directly browse a visitor's laptop or reuse its CLI sign-ins.

The base image supplies Node.js, Python, Git, the Threatlint CLI and Word export support. Build a derived profile image for optional tools required by your workflow, such as Semgrep, AWS CLI, GitHub CLI, Codex, Claude Code or a browser for browser-dependent runtime assessment. Configure each account's tool credentials inside its own profile. Do not bake personal tokens into the image or pass host cloud credentials to all users. A missing optional tool is reported by the existing Workbench capability checks.

## Isolation and persistence

Profile workers run as uid 1000, without added Linux capabilities or elevated privileges, with a read-only application filesystem. Their home volume and temporary filesystem are writable. Each worker has its own network bridge, process environment, CLI configuration, in-memory caches, sockets and running jobs. The gateway's per-launch worker secret is delivered over stdin. Browser state is namespaced by account. Web profiles save integration credentials to their own volume and bypass the shared OS keyring.

Container isolation is required for a shared deployment. The Workbench intentionally handles source repositories, external tools and application targets; a process with a different `HOME` directory does not provide a filesystem security boundary. Restrict profile-container network egress according to the networks and destinations your deployment is allowed to assess.

Keep the gateway state directory and every named profile volume across restarts and upgrades. Do not prune these volumes as disposable containers. Repository checkouts use `/home/threatlint/tmp` in the persistent home volume, so saved sessions can reopen their repositories after a restart; `/tmp` remains disposable.

Back up the profile identity/session directory and profile volumes together, stop the gateway before restoration or migration, and recreate workers from the matching image. An exclusive state lock prevents two gateways from writing the same state directory. Preserve `THREATLINT_PROFILE_NAMESPACE` when moving hosts or changing the absolute state-directory path: the namespace determines named profile-volume identities. If this setting is omitted, its default is the first 12 hexadecimal characters of SHA-256 of the resolved absolute state-directory path. Record that default before a move and explicitly configure the same value on the destination; changing it selects different, initially empty profile volumes. The example above sets a stable explicit namespace to simplify migration. Namespace values use lowercase letters, digits and hyphens, start with a letter or digit, and contain at most 40 characters.

## Local development and verification

Local development still requires a real Auth0 sign-in. Add the exact local root callback, root logout URL and origin to the SPA's Auth0 allowlists before changing `THREATLINT_WEB_ORIGIN`. For example, use callback/logout `http://127.0.0.1:3000/` and web origin `http://127.0.0.1:3000`. Keep the same API audience unless you have configured a separate development API.

For local development without Docker, explicitly select process mode and a loopback origin:

```sh
export THREATLINT_PROFILE_MODE=process
export THREATLINT_WEB_ORIGIN=http://127.0.0.1:3000
export THREATLINT_WEB_STATE_DIR=./.web-state
npm run start:web
```

Use the PowerShell `$env:NAME = 'value'` syntax on Windows. Process mode accepts only loopback origins and is for development with trusted accounts. It creates separate profile directories and processes, but does not sandbox operating-system file access. Use the default container mode for shared or public hosting.

Authentication tests use a mocked issuer and tokens to verify the integration. They do not prove the production tenant's API, social connections, SSO configuration or a live end-to-end sign-in. No production authentication bypass is provided for those tests. Docker image execution also requires a running Docker Engine.
