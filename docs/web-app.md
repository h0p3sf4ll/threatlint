# Threatlint web app

The web app adds account sign-in to the same Workbench used by the desktop app. Each account has its own Workbench, settings, repository sessions, reports, conversations, dashboards and running jobs. Account identity comes from the server session; visitors cannot select another account's workspace by supplying a profile ID.

The default deployment runs each user's Workbench in a separate Docker container with a separate named home volume. The gateway authenticates HTTP and WebSocket requests before forwarding them to that user's container. Desktop startup remains available through `npm run desktop` and the original local Workbench through `npm start`.

## Requirements

- Node.js 22 or later and npm on the gateway host.
- Docker Engine, with the Docker CLI available to the gateway service account.
- A persistent, access-restricted directory for the gateway's account and session data.
- An HTTPS reverse proxy for a public deployment.
- Network access from profile containers to the model providers, source hosts, trackers and applications users choose to assess.

The gateway needs permission to create containers and named volumes. Run it as a dedicated service account on a dedicated host. Profile containers do not receive the Docker socket, gateway credentials, gateway state directory or another profile's volume.

## Build and start

Run these commands from the repository root:

```sh
docker build -f Dockerfile.web -t threatlint-profile:local .
cd web
npm ci --omit=dev --ignore-scripts
```

Configure the gateway environment. For example, in a POSIX shell:

```sh
export THREATLINT_WEB_ORIGIN=https://threatlint.example.com
export THREATLINT_WEB_STATE_DIR=/var/lib/threatlint-web
export THREATLINT_PROFILE_IMAGE=threatlint-profile:local
export THREATLINT_PROFILE_NAMESPACE=threatlint-production
```

Or in PowerShell:

```powershell
$env:THREATLINT_WEB_ORIGIN = 'https://threatlint.example.com'
$env:THREATLINT_WEB_STATE_DIR = 'C:\ProgramData\ThreatlintWeb'
$env:THREATLINT_PROFILE_IMAGE = 'threatlint-profile:local'
$env:THREATLINT_PROFILE_NAMESPACE = 'threatlint-production'
```

Create the first account in the same environment, then start the gateway:

```sh
npm run web:create-user -- --email analyst@example.com --name "Security Analyst"
npm run start:web
```

The account command prompts for the password without putting it in command-line arguments. Stop the gateway before running the account command again; an exclusive state lock prevents simultaneous account-store writers. Restart the gateway after provisioning additional users. Public self-registration is disabled by default. Set `THREATLINT_WEB_REGISTRATION=1` only when visitors should be able to create their own accounts; remove it and restart the gateway to close registration.

The gateway binds to `127.0.0.1:3000` by default. Point the reverse proxy at that address and preserve the incoming Host header. The externally visible origin must match `THREATLINT_WEB_ORIGIN`, including the port when nonstandard. Forward WebSocket upgrades as well as HTTP requests. Terminate TLS at the proxy and keep the backend listener off the public network.

`THREATLINT_MAX_PROFILES` limits active profile workers and defaults to `8`. Workers stay active until the gateway stops; signing out does not evict a worker or cancel its background jobs. Size this limit and host resources for your expected users. A request from a new account receives an unavailable response when the limit is reached.

An nginx location, inside the HTTPS server block for the configured hostname:

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

Back up the account directory and profile volumes together, stop the gateway before restoration, and recreate workers from the matching image. Preserve `THREATLINT_PROFILE_NAMESPACE` when moving hosts or changing the absolute state-directory path: the namespace determines named profile-volume identities. If this setting is omitted, its default is the first 12 hexadecimal characters of SHA-256 of the resolved absolute state-directory path. Record that default before a move and explicitly configure the same value on the destination; changing it selects different, initially empty profile volumes. The example above sets a stable explicit namespace to simplify migration. Namespace values use lowercase letters, digits and hyphens, start with a letter or digit, and contain at most 40 characters.

## Local development

For local development without Docker, explicitly select process mode and a loopback origin:

```sh
export THREATLINT_PROFILE_MODE=process
export THREATLINT_WEB_ORIGIN=http://127.0.0.1:3000
export THREATLINT_WEB_STATE_DIR=./.web-state
npm run web:create-user -- --email developer@example.com --name Developer
npm run start:web
```

Use the PowerShell `$env:NAME = 'value'` syntax on Windows. Process mode accepts only loopback origins and is for development with trusted accounts. It creates separate profile directories and processes, but does not sandbox operating-system file access. Use the default container mode for shared or public hosting.
