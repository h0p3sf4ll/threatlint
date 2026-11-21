# Deploy Threatlint at app.threatlint.dev

This guide deploys the `feature/web-profiles` gateway on an existing Linux VPS, with Docker profile workers, persistent storage, nginx and a Let's Encrypt certificate. It leaves the marketing website at `threatlint.dev` on its current hosting.

## Select the runtime

First inspect the Spaceship account for an existing VPS and confirm administrative access to it. These instructions do not require purchasing a new product. Spaceship VPS provides system-level access to install software and configure services. [VPS access documentation](https://www.spaceship.com/en-GB/knowledgebase/how-to-access-vps/).

The current shared-hosting plan supports managed Node applications, but its shared-account policy prohibits standalone daemons. It cannot provide the Docker Engine, bridges and per-profile volumes required by this deployment. Do not upload the application into the marketing site's FTPS document root or switch the public app to development process mode. [Node hosting guide](https://www.spaceship.com/knowledgebase/setup-nodejs-application-spaceship-hosting/), [shared-hosting policy](https://www.spaceship.com/legal/hosting-aup/).

Use an Ubuntu server with Node.js **22.12.0 or later**, npm, Docker Engine and Git. Install Node from its [official distribution](https://nodejs.org/en/download) and Docker using the [official Ubuntu instructions](https://docs.docker.com/engine/install/ubuntu/). Install the reverse proxy and certificate client:

```sh
sudo apt-get update
sudo apt-get install -y git nginx certbot ca-certificates
node --version
npm --version
sudo docker info
```

Ensure the Node executable is available in `/usr/local/bin` or `/usr/bin`, which are in the service's PATH. Allow inbound ports 80 and 443; keep port 3000 and profile-worker ports bound to loopback. Retain your administrative access path when changing firewall rules. Size the host and `THREATLINT_MAX_PROFILES` together: each worker currently has a 2 GiB memory limit, in addition to the gateway, operating system and build requirements.

## Install the release and service

Create the dedicated gateway service account and clone the requested branch:

```sh
sudo useradd --system --create-home --home-dir /var/lib/threatlint-web --shell /usr/sbin/nologin threatlint-web
sudo usermod -aG docker threatlint-web
sudo mkdir -p /opt/threatlint
sudo git clone --branch feature/web-profiles --single-branch https://github.com/h0p3sf4ll/threatlint.git /opt/threatlint/current
sudo npm --prefix /opt/threatlint/current/web ci --omit=dev --ignore-scripts
sudo docker build -f /opt/threatlint/current/Dockerfile.web -t threatlint-profile:local /opt/threatlint/current
```

If the account or checkout already exists, inspect and reuse it rather than recreating it. Docker-group membership gives the gateway administrative control over Docker on this host. Use a dedicated VPS service account; profile containers receive neither the Docker socket nor that group access.

The profile image installs its own Python virtual environment, Threatlint CLI, Word-export dependency, Git and production Node dependencies. Optional model/scanner CLIs require a derived image, as described in the [web app guide](web-app.md#what-is-saved-to-a-profile).

Install the environment file, then edit it for the server:

```sh
sudo install -d -o root -g threatlint-web -m 0750 /etc/threatlint-web
sudo install -o root -g threatlint-web -m 0640 /opt/threatlint/current/web/.env.example /etc/threatlint-web/web.env
sudoedit /etc/threatlint-web/web.env
```

Set these deployment values; keep the supplied Auth0 domain and client ID:

```dotenv
THREATLINT_WEB_ORIGIN=https://app.threatlint.dev
AUTH0_AUDIENCE=https://threatlint.dev/api
THREATLINT_WEB_STATE_DIR=/var/lib/threatlint-web
THREATLINT_PROFILE_MODE=docker
THREATLINT_PROFILE_IMAGE=threatlint-profile:local
THREATLINT_PROFILE_NAMESPACE=threatlint-production
THREATLINT_WEB_HOST=127.0.0.1
PORT=3000
```

Adjust `THREATLINT_MAX_PROFILES` to the server's capacity. Keep the namespace stable across updates and migrations. Do not put integration credentials or an Auth0 client secret in the profile image.

For company entry points, create the service-owned registry only after creating the corresponding Auth0 Organizations and adding their members:

```sh
sudo install -o root -g threatlint-web -m 0640 /opt/threatlint/current/web/companies.example.json /etc/threatlint-web/companies.json
sudoedit /etc/threatlint-web/companies.json
```

Replace every example organization ID with a real tenant Organization ID. Then set `THREATLINT_COMPANIES_FILE=/etc/threatlint-web/companies.json` in `web.env`. Leave it unset for personal-only sign-in. See [company configuration and membership](web-app.md#company-sign-in).

Install and start the service:

```sh
sudo install -o root -g root -m 0644 /opt/threatlint/current/deploy/threatlint-web.service /etc/systemd/system/threatlint-web.service
sudo systemctl daemon-reload
sudo systemctl enable --now threatlint-web
sudo systemctl status threatlint-web --no-pager
curl --fail --header 'Host: app.threatlint.dev' http://127.0.0.1:3000/healthz
```

The unit runs the gateway on the host with Docker CLI access. The application runs each user's Workbench in its own restricted container. Gateway state is stored in `/var/lib/threatlint-web`; profile data remains in named Docker volumes. Logs are available through `journalctl -u threatlint-web`.

## Configure DNS and HTTPS

In Spaceship Advanced DNS, add an **A** record with host **`app`** and the chosen VPS's public IPv4 address. Add an AAAA record only if that server's public IPv6 connectivity is configured and tested. Preserve apex, `www`, mail and other existing records. An existing conflicting `app` record must be reviewed before replacement. [Spaceship DNS record guide](https://www.spaceship.com/knowledgebase/dns-records-types/).

Install the HTTP-only ACME configuration. Back up an existing vhost for this same hostname before replacing it; do not modify unrelated website configurations.

```sh
sudo mkdir -p /var/www/letsencrypt
sudo install -o root -g root -m 0644 /opt/threatlint/current/deploy/nginx/threatlint-web.http.conf /etc/nginx/sites-available/threatlint-web
sudo ln -s /etc/nginx/sites-available/threatlint-web /etc/nginx/sites-enabled/threatlint-web
sudo nginx -t
sudo systemctl reload nginx
```

After the `app` record resolves to this VPS, obtain the certificate. Replace `YOUR_MONITORED_EMAIL` with the certificate owner's monitored email address:

```sh
sudo certbot certonly --webroot -w /var/www/letsencrypt -d app.threatlint.dev --email YOUR_MONITORED_EMAIL --agree-tos
sudo install -o root -g root -m 0644 /opt/threatlint/current/deploy/nginx/threatlint-web.conf /etc/nginx/sites-available/threatlint-web
sudo nginx -t
sudo systemctl reload nginx
sudo install -d -o root -g root -m 0755 /etc/letsencrypt/renewal-hooks/deploy
sudo install -o root -g root -m 0750 /opt/threatlint/current/deploy/renewal-reload-nginx.sh /etc/letsencrypt/renewal-hooks/deploy/threatlint-nginx
sudo systemctl enable --now certbot.timer
sudo certbot renew --dry-run
```

The final vhost forwards HTTP and WebSockets, redirects ordinary HTTP traffic to HTTPS and keeps the ACME webroot available for renewals. Its access log records paths without OAuth callback query strings. The renewal hook checks nginx configuration and reloads renewed certificates. See [nginx WebSocket proxying](https://nginx.org/en/docs/http/websocket.html) and [Certbot webroot and renewal documentation](https://eff-certbot.readthedocs.io/en/stable/using.html#webroot).

## Configure Auth0 and verify the deployed app

Set the SPA's allowed callback and logout URL to `https://app.threatlint.dev/`, and its allowed web origin to `https://app.threatlint.dev`. Keep the confirmed custom API audience `https://threatlint.dev/api`. Enable the approved Google, Apple, GitHub and enterprise connections; disable database connections. For company entry points, enable the application's personal/business **Both** behavior and configure organization connections and explicit membership. Full settings are in the [Auth0 deployment guide](web-app.md#configure-auth0).

Verify the deployed release through the public hostname:

1. Open the HTTPS app and check valid TLS, login options and branding. Confirm `/healthz` responds and `/auth/session` rejects an unauthenticated request.
2. Complete a real permitted-provider sign-in. Confirm the root callback returns to the Workbench, the authenticated session is established and a profile container starts.
3. Save a model preference. Sign out, confirm the session endpoint returns 401, then sign back in and confirm the same profile restores it. Repeat in another browser to verify server persistence.
4. For a configured company, use `/c/<slug>/login` with a real member. Confirm its profile settings are separate from personal sign-in and from another organization. Confirm a nonmember cannot enter that company profile.
5. Confirm a second user does not inherit the first user's settings, reports or running jobs, and that WebSocket activities function through HTTPS.
6. Restart the gateway and repeat the settings check to verify state and volume persistence.

Mocked-issuer tests and local process-mode tests do not establish these live results. Record any unavailable social provider, organization entitlement, real-member account or optional workflow tool as an explicit verification limit.

## Updates and recovery

Keep the application checkout, gateway state, company registry and Docker volumes distinct. To update, stop `threatlint-web`, select the reviewed release in `/opt/threatlint/current`, install production dependencies, rebuild the profile image and restart the service. Stopping the gateway closes its active workers while preserving volumes.

Back up `/var/lib/threatlint-web`, `/etc/threatlint-web` and all profile volumes together while the service is stopped. Preserve `THREATLINT_PROFILE_NAMESPACE`, identity-to-profile mappings and organization IDs when restoring. Do not prune profile volumes as deployment cleanup. Restore to the same public origin and repeat the live sign-in and persistence checks before reopening access.
