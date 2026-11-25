---
title: Self-host the web app
description: Configure Auth0, organization access, isolated workers, and persistent profiles for your own deployment.
---

# Self-host the web app

The web app adds Auth0 sign-in to the same Workbench used by the desktop app. Users sign in through the configured Google, Apple, GitHub or approved enterprise SSO connections. The login page advertises only providers explicitly enabled in the deployment configuration. Threatlint does not provide a local username/password login or password registration. Each verified identity has its own settings, repository sessions, reports, conversations, dashboards and running jobs. Visitors cannot select another identity's workspace by supplying a profile ID.

The default deployment runs each user's Workbench in a separate Docker container with a separate named home volume. The gateway authenticates HTTP and WebSocket requests before forwarding them to that user's container. Desktop startup remains available through `npm run desktop` and the original local Workbench through `npm start`. Those local entry points keep the operating-system user's existing storage and credentials; they require neither Auth0 nor a company registry.

This reference is for administrators running their own deployment. To use the hosted service, see [Profiles and saved settings](profiles.md). The production-specific [VPS operations runbook](https://github.com/h0p3sf4ll/threatlint/blob/main/docs/web-vps-deployment.md) is maintained in the repository.

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

These are application configuration values, including a public SPA client ID. The browser sign-in flow does not use an Auth0 client secret.

Complete the following in the Auth0 Dashboard before a production sign-in:

1. Open the existing application with the client ID above and confirm its type is **Single Page Application**, token endpoint authentication method is **None**, and its callback, logout and web-origin allowlists match the table. Use Authorization Code with PKCE through the browser SDK. Set the JWT signature algorithm to **RS256** and enable OIDC Conformant. See the [official SPA configuration guide](https://auth0.github.io/auth0-spa-js/index.html#configure-auth0).
2. Create or confirm the custom API with identifier **`https://threatlint.dev/api`** and **RS256** signing. Authorize this SPA to request access to that API under the tenant's application-access policy. The audience must identify this custom API, rather than the Auth0 Management API. The browser requests the `openid profile email` scopes for identity information. An access token may contain both this API and the tenant's `/userinfo` URL in its audience array; no custom claims or Auth0 Action are required. See [Auth0's audience documentation](https://auth0.com/docs/secure/tokens/access-tokens/get-access-tokens#multiple-audiences).
3. Under **Authentication > Social**, configure the desired social providers using your own production identity-provider credentials, then enable those connections for this SPA. The expected connection names are `google-oauth2`, `apple` and `github`; environment overrides are available when the tenant uses other names. Set `AUTH0_ENABLED_PROVIDERS` to the comma-separated providers that are actually ready: the default is `google`; use `google,apple,github,sso` only after all social and enterprise connections are configured. Unknown, empty or duplicate provider values fail startup. This public availability list needs no Auth0 Management API credential and does not create tenant connections or grant organization membership. Auth0 development keys are not a substitute for production provider credentials. Follow each provider's Auth0 setup guide for its provider-side callback and credential requirements. See [Auth0 social identity providers](https://auth0.com/docs/authenticate/identity-providers/social-identity-providers).
4. Configure approved enterprise identity providers under **Authentication > Enterprise** and enable them for this SPA. The SSO action uses Auth0 Universal Login, where the tenant's connection discovery and enterprise policy select the provider.
5. Disable **all Database connections** for this SPA, including `Username-Password-Authentication`, and disable database sign-up. Enable only the configured social connections and approved enterprise connections. The backend also rejects Auth0 database identities whose subject starts with `auth0|`.

Auth0 Dashboard changes require tenant administration. The repository includes no tenant credentials and does not automatically configure APIs or provider secrets. Organization self-service uses the separate, optional server-side Management API configuration below. The supplied domain and client ID alone do not establish that tenant settings are complete.

## Authentication and profile identity

The browser uses the official `@auth0/auth0-spa-js` SDK for Authorization Code with PKCE. The gateway uses the official `@auth0/auth0-express-api` SDK to validate the API access token's signature, issuer, audience and authorized SPA client. It then obtains identity information through the official `@auth0/auth0-auth-js` SDK's UserInfo operation and binds the resulting server session to that identity. Session cookies are HttpOnly and bounded by the validated access token's expiry.

Personal profiles use the verified issuer and subject (`iss` + `sub`), which map to a stable internal profile ID. Company profiles additionally include the verified Auth0 organization ID. Email addresses are display information and never merge profiles. Signing into the same identity and organization on another browser restores that profile's saved settings. Different identity-provider accounts remain separate unless Auth0 has already linked them under the same verified subject.

## Company sign-in

Users first sign in with a configured provider. With organization management enabled, Threatlint looks up the verified identity's Auth0 memberships, including memberships added before the person's first Threatlint visit. It opens a single organization automatically, offers a choice when there are several, and offers organization creation when there are none. A personal profile remains available. Choosing an organization starts a second organization-scoped Auth0 authorization; the initial personal cookie alone cannot enter it.

Existing company entry points remain available at `https://app.threatlint.dev/c/<slug>/login`. Administrators may seed their names through a service-owned JSON registry and set `THREATLINT_COMPANIES_FILE` to its absolute path. Start with `web/companies.example.json` and replace the example organization IDs with real IDs from the configured tenant:

```json
[
  { "slug": "acme", "name": "Acme", "auth0OrganizationId": "org_0000000000000001" }
]
```

The zeros above are an example ID, not an existing organization. Slugs and organization IDs must each be unique. Keep this file outside the website's document root, readable by the service and writable only by administrators. Restart the gateway after seed-registry changes. Discovered and self-created organizations are saved separately in the persistent gateway state; this seed file need not be rewritten. When both sources describe the same organization ID, the seed file controls its name and slug.

In Auth0, enable Organizations for this SPA and select **Both** personal and business users (`organization_usage=allow`) to retain personal sign-in. Create each organization, enable its approved connections and add its members. Organizations availability depends on the tenant's Auth0 plan. Do not assume email-domain matching grants membership; with a Both application, provision membership explicitly through the Dashboard or an authorized management workflow. See [organization behavior](https://auth0.com/docs/manage-users/organizations/configure-organizations/define-organization-behavior) and [auto-membership requirements](https://support.auth0.com/center/s/article/organization-auto-membership-feature-requirements).

The browser SDK passes the server-provided immutable Organization ID through its `organization` parameter. All companies use the same root callback `https://app.threatlint.dev/`; no per-company Auth0 callback is needed. The gateway requires the validated token's `org_id` to match the chosen organization and, when Management is configured, checks current Auth0 membership. A URL slug, email match or email domain cannot grant company access. Company A, company B and personal profiles remain separate for the same person. See [Auth0 organization tokens](https://auth0.com/docs/manage-users/organizations/using-tokens).

### Enable organization discovery and administration

This requires an Auth0 tenant plan with Organizations and a separate **Machine to Machine** application. Its secret belongs only in the gateway's restricted service configuration, never in the SPA, browser, worker environment, repository or image.

1. Authorize that M2M application for the same tenant's **Auth0 Management API**. Grant only `read:organizations`, `create:organizations`, `read:organization_members`, `create:organization_members`, `delete:organization_members`, `read:organization_connections`, `create:organization_connections`, and `read:users`. Threatlint requests these scopes with a server-side client-credentials exchange; the browser still requests the Threatlint custom API audience.
2. Set `AUTH0_MANAGEMENT_CLIENT_ID` and `AUTH0_MANAGEMENT_CLIENT_SECRET` on the gateway. Both are required together. These credentials must belong to the tenant configured by `AUTH0_DOMAIN`.
3. Set `AUTH0_ORGANIZATION_CONNECTION_IDS` to the comma-separated Auth0 connection IDs approved for newly created organizations, such as `con_...`. Use connection IDs rather than social connection names. These connections must already be configured for the SPA. Without this list, existing membership discovery and administration work, but organization creation is disabled.
4. For existing organizations, disable **Membership on Authentication** and organization sign-up on their connections. New organizations are created with both options disabled and with the explicit creator membership only. A shared connection or matching email domain must never automatically enroll someone.
5. Restart the gateway, sign in, and verify organization discovery, creator administration, a pre-added member's first sign-in, and last-administrator protection. Verify that signing out and choosing the personal profile restores its separate settings.

The app generates each new organization's name/slug and records its creation request before calling Auth0. Retrying that request resumes it after a network failure or gateway restart. A completed retry never re-adds a removed creator or reverses a later role change. Preserve `organizations.json`, `organization-operations.json`, `identities.json` and the `management` directory with the rest of gateway state.

Without Management credentials, existing seeded organization sign-in continues to work. Discovery, creation, complete administrator member lists, email lookup, and membership add/remove show an unavailable error; they do not pretend an empty list means the identity has no memberships. Existing profile-ID role assignments remain available for compatibility. With Management enabled, successful membership checks are cached for at most five seconds; a failed refresh denies access rather than using an expired result. Auth0's membership indexes are eventually consistent, so external changes can take longer to appear. Removals through Threatlint revoke that company identity's cookies and sockets immediately, while retaining its saved profile data.

See Auth0's [user organization lookup](https://auth0.com/docs/api/management/v2/users/get-user-organizations), [organization creation](https://auth0.com/docs/api/management/v2/organizations/post-organizations), and [organization member listing](https://auth0.com/docs/api/management/v2/organizations/get-organization-members) API references.

There are no password-creation commands, local password endpoints or development authentication bypasses. Old `accounts.json` files from the earlier local-account implementation are ignored. Their profile files are retained, but federated sign-in creates its own profile; legacy data is not automatically associated by matching email. Any future migration must explicitly prove the destination identity and preserve the source data.

## Organization access controls

Company members have one of three roles. The gateway enforces roles on every API request before forwarding it to a profile or the shared integration service; browser controls are only a convenience.

| Role | Access |
| --- | --- |
| Administrator | Read data, run reviews, manage findings, configure connections and settings, and assign company roles. |
| Analyst | Read data, select personal models and session credentials, connect personal source sessions, run reviews, import or create tracker findings, sync tickets, and close proven false positives. Persisted integration credentials and organization connections are read-only. |
| Viewer | Read data and reports. Cannot run reviews, open review WebSockets, change settings or update trackers. |

Personal web profiles and the local desktop are owned by their individual user and have administrator permissions. New company members default to **analyst** unless an administrator assigns another role. Self-service creation explicitly assigns its creator as administrator; joining an existing organization never promotes its first visitor. To bootstrap an existing company's administrator, set `THREATLINT_ADMIN_SUBJECTS` on the gateway to a comma-separated list of exact, verified Auth0 subjects (for example, `github|123456`). This service-owned setting applies only after that subject signs into an organization of which it is a verified member. Restart the gateway after changing it and sign in again. Never use email addresses or unverified request headers as administrator selectors.

Analysts can save their own model preferences (`/api/model-preferences`), use session model credentials, and connect or disconnect in-memory source sessions (`/api/scm/connections`) inside their isolated profile. Those choices cannot change another member's runtime or the shared organization connections. Administrator permission remains required for the persisted connections in **Settings > Integrations** and for legacy saved ServiceNow, Semgrep, GitHub App, Azure DevOps and scanner credentials. Analysts can activate an administrator-configured source connection in their own runtime without seeing its token.

Alternatively, a trusted Auth0 Action may put `['administrator']`, `['analyst']`, or `['viewer']` in the access token's `https://threatlint.dev/roles` custom claim. The gateway reads this claim only after the existing official SDK verifies the token and the organization membership. A plain `role` claim, request body, UserInfo field or `X-Threatlint-Role` header cannot assign a role. When multiple recognized roles are supplied, administrator takes precedence, followed by analyst and viewer. Claim-based changes take effect at the next login. Existing sessions created before roles were introduced default to analyst until the user signs in again.

Use **Settings > Access control** to list actual Auth0 members, including people who have never opened Threatlint, and assign their roles. To add someone, search their exact sign-in email and choose the intended provider identity from the results; the person must already have an account in the tenant. Matching email addresses never link identities or enroll other accounts. An administrator assignment persists across later logins, including subsequent identity-provider role claims. Membership and roles are always bound to this organization and the exact verified issuer/subject. The API prevents demoting or removing the last current administrator. Role changes affect the next API request immediately; a demotion to viewer also closes an existing review socket. Removal preserves profile files and revokes the removed identity's company sessions. If a removal's Auth0 call fails, local access stays blocked until an administrator explicitly re-adds the member.

The gateway stores roles and central connection/finding records under `management/organizations/<sha256 of verified organization ID>/` inside `THREATLINT_WEB_STATE_DIR`. Personal central records use `management/personal/<profile UUID>/`. Company rename/slug changes retain this shared scope. These directories are private gateway state and are never mounted in a profile worker. Keep the gateway state volume persistent and access-restricted alongside `identities.json`. Existing individual repository sessions, reports and legacy integration credentials remain isolated in each profile; only connections and findings configured through the organization management interface are shared.

`GET /api/access` exposes the current `role`, boolean `permissions`, supported `roles`, and (for company administrators with Management configured) all current `members`. `POST /api/access/members` accepts `{ "subject": "github|123456", "role": "viewer" }`; the earlier profile-UUID form is retained. `DELETE /api/access/members/<encoded-subject>` removes an existing member. The administrator-only exact-email candidate lookup returns only identity labels needed for selection. Normal session, same-origin and active-profile checks apply; none of these requests accepts a client-selected organization scope.

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

`THREATLINT_MAX_PROFILES` limits active profile workers and defaults to `8`. Workers without connected clients or background jobs are reclaimed after 15 minutes; when capacity is needed, the oldest safe idle worker can be reclaimed sooner. Named volumes and saved settings remain intact. Signing out closes that session's connections while detached jobs continue. If every slot is starting, connected, busy or cannot be checked safely, a new profile receives HTTP 503 with a 30-second retry hint. Size the limit for host resources; personal and company profiles each use their own worker.

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

Guided or Advanced Experience is saved separately in each profile's `ui-preferences.json`. Every role can change this personal display preference without changing company settings. Desktop keeps the same preference in its local user store across restarts and does not require sign-in.

Provider API keys entered for a review retain the existing Workbench behavior: they stay in memory for the browser session. They are not saved as ordinary model preferences. Integration credentials explicitly saved by their settings forms remain in the profile's private volume and are not returned by settings reads. Protect gateway state and profile-volume backups as sensitive data.

The same views remain available for reviewing code, running security agents, finding triage, importing scanner results, scanning an application, exporting reports, asking questions, working with dashboards and using Sidekick. Actions execute on the server in the account's container. Repository folders, local model URLs and application URLs refer to that container's environment. A remote web app cannot directly browse a visitor's laptop or reuse its CLI sign-ins.

The base image supplies Node.js, Python, Git, ripgrep, file inspection, the Threatlint CLI, Word export support and Semgrep **1.186.0**. Semgrep runs in its own Python environment so scanner dependencies do not change Threatlint's runtime. Its [published release metadata](https://pypi.org/project/semgrep/1.186.0/) supports Python 3.10 or later and provides Linux wheels for Python 3.11 on amd64 and arm64; Debian Bookworm meets the wheel's glibc requirement. The image build checks `semgrep --version` and `threatlint --help` as its unprivileged runtime user without signing in or scanning remote code.

The image also includes pinned [Codex CLI 0.171.0](https://github.com/openai/codex), [Claude Code 2.1.330](https://code.claude.com/docs/en/setup#install-with-npm), [AWS CLI 2.42.1](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) and [GitHub CLI 2.105.0](https://github.com/cli/cli/releases/tag/v2.105.0). A separate build stage verifies the npm package archives against their upstream SHA-512 integrity, verifies the GitHub binary against the release's SHA-256 checksum, and runs a checksum-pinned official AWS installer with package-signature verification enabled. The final image checks each CLI's version as the runtime user. Download/install helpers remain in the build stage. CLI binaries are root-owned on the read-only application filesystem; Claude's update paths and GitHub update notifications are disabled, and tool changes are delivered by rebuilding the image.

AWS Parameter Store setup and CLI-backed model providers still require credentials provisioned separately inside each profile. The visitor's laptop sign-ins are not available to the server. Do not bake personal tokens into the image or pass host cloud credentials to all users. Semgrep platform access and licensed engines likewise require the account's own configured token and entitlement; including the Community Edition CLI does not grant them. An image build or version check does not verify a particular account's login, service permissions or model entitlement.

Most runtime authentication modes use ordinary HTTP requests and remain available, including tokens, Basic auth, OAuth, cookies and imported browser-state cookies. **Manual browser sign-in for SSO/MFA is not available in this server image**: the desktop implementation opens a headed Playwright browser, while the production install omits Playwright and provides no remote display to the visitor. Installing Chromium alone does not supply that interaction. CLI DAST workflows that start target containers require a separate isolated execution service; profile workers deliberately have no Docker socket access. These workflows are not available with the same capabilities as the desktop in the current deployment.

## Isolation and persistence

Profile workers run as uid 1000, without added Linux capabilities or elevated privileges, with a read-only application filesystem. Their home volume and temporary filesystem are writable. Each worker has its own network bridge, process environment, CLI configuration, in-memory caches, sockets and running jobs. The gateway's per-launch worker secret is delivered over stdin. Browser state is namespaced by account. Web profiles save integration credentials to their own volume and bypass the shared OS keyring.

Container isolation is required for a shared deployment. The Workbench intentionally handles source repositories, external tools and application targets; a process with a different `HOME` directory does not provide a filesystem security boundary. Restrict profile-container network egress according to the networks and destinations your deployment is allowed to assess.

Keep the gateway state directory and every named profile volume across restarts and upgrades. Do not prune these volumes as disposable containers. Repository checkouts use `/home/threatlint/tmp` in the persistent home volume, so saved sessions can reopen their repositories after a restart; `/tmp` remains disposable.

Back up the profile identity/session directory and profile volumes together, stop the gateway before restoration or migration, and recreate workers from the matching image. An exclusive state lock prevents two gateways from writing the same state directory. Preserve `THREATLINT_PROFILE_NAMESPACE` when moving hosts or changing the absolute state-directory path: the namespace determines named profile-volume identities. If this setting is omitted, its default is the first 12 hexadecimal characters of SHA-256 of the resolved absolute state-directory path. Record that default before a move and explicitly configure the same value on the destination; changing it selects different, initially empty profile volumes. The example above sets a stable explicit namespace to simplify migration. Namespace values use lowercase letters, digits and hyphens, start with a letter or digit, and contain at most 40 characters.

Each namespace must belong exclusively to one gateway on a Docker host, including when gateways use different state directories. Before admitting its first profile, a gateway removes orphaned containers and networks with its exact namespace and profile-ID naming pattern; volumes and unrelated resources remain intact. Failed inventory or uncertain cleanup blocks new admission until recovery can be confirmed.
