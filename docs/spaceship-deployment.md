# ThreatLint marketing deployment to Spaceship

The website is static and lives in `marketing/`. The authenticated Workbench at `app.threatlint.dev` runs on its own VPS; see [web deployment](web-vps-deployment.md).

The verified Spaceship server is `server66.shared.spaceship.host`, and the `threatlint.dev` document root is `/home/xpqbpgplls/threatlint.dev`.

## Spaceship hosting setup

1. Open [Spaceship Hosting Manager](https://www.spaceship.com/) and select **Manage** next to the active hosting plan.
2. Confirm `threatlint.dev` is connected to this hosting subscription. In **Advanced → Document root folder**, confirm the domain's exact website directory. Ensure HTTPS/SSL is active.
3. Open cPanel via **Access → Access your cPanel**; find **Files → FTP Accounts**.
4. Create a **dedicated FTP account** with a strong generated password; set its **Directory** to `/home/xpqbpgplls/threatlint.dev` (cPanel may already display the `/home/xpqbpgplls/` prefix). **Do not** set the account directory to `/` in the cPanel form: that would grant access to your entire home directory. The remote path seen *after login* by a folder-scoped FTP account is `/`.
5. Under that account, select **Configure FTP Client**. Copy the **full FTP username**. Use the verified server hostname `server66.shared.spaceship.host`. Spaceship documents explicit FTPS on port 21.

See [Spaceship's official FTP guide](https://www.spaceship.com/knowledgebase/how-to-create-and-access-ftp-accounts/).

## GitHub Actions: configure production

Open [repository environments](https://github.com/h0p3sf4ll/threatlint/settings/environments) and select `production`. Its deployment branch policy must allow only `main`. Leave required reviewers and wait timers disabled for unattended delivery.

Under the `production` environment's **Secrets**, add all three as **environment secrets**, not source files or chat messages:

| Name | Value |
| --- | --- |
| `SPACESHIP_FTP_HOST` | `server66.shared.spaceship.host` (without `ftp://` or port) |
| `SPACESHIP_FTP_USER` | Dedicated FTP account's **full** username |
| `SPACESHIP_FTP_PASSWORD` | Dedicated FTP account password |

Under the `production` environment's **Variables**, add:

| Name | Value |
| --- | --- |
| `SPACESHIP_FTP_PATH` | `/` when the FTP account is scoped to the website's document root |

Open [repository Actions variables](https://github.com/h0p3sf4ll/threatlint/settings/variables/actions) and add the following **repository variable**:

| Name | Value |
| --- | --- |
| `SPACESHIP_DEPLOY_ENABLED` | `true` only once you have verified the document root and secrets |

Keep `SPACESHIP_DEPLOY_ENABLED` at repository scope: the deployment job's `if` condition is evaluated before its environment variables become available. The FTP secrets and path remain scoped to `production`.

**Security:** Do not use the Spaceship login password or full-access cPanel tokens as deployment secrets. The workflow requires TLS and certificate verification, uses FTP passive mode and does not delete remote files. If it reports a certificate mismatch, fix the hostname or Spaceship TLS configuration; do not disable verification.

## First deploy and ongoing delivery

Open [Deploy marketing site to Spaceship — GitHub Actions](https://github.com/h0p3sf4ll/threatlint/actions/workflows/deploy-marketing-spaceship.yml), choose **Run workflow** on `main`. The validation job works before deployment is enabled; the deployment job is skipped until `SPACESHIP_DEPLOY_ENABLED=true`. Once enabled, the workflow deploys automatically when `marketing/**` or the deployment workflow changes on `main`. Manual runs deploy only from `main`; other branches can run validation but cannot deploy. Both the workflow guard and the `production` environment's branch policy restrict deployment to `main`.

The workflow stages only the marketing site, excludes the Cloudflare-only `_headers` file, and publishes using certificate-verified **explicit FTPS**. The password is passed through `LFTP_PASSWORD`, not a command-line argument. After upload, it verifies that the public HTTPS homepage, stylesheet, logo, robots.txt and sitemap.xml exactly match the deployed source. The deployment job has a ten-minute timeout. The included `marketing/.htaccess` is intended for Spaceship's LiteSpeed/Apache-compatible shared hosting.

Verify `https://threatlint.dev` loads the homepage, styles, logo and valid TLS. If a default placeholder persists, remove or rename an old `index.php` or fix the document root in cPanel. Don't delete other site files until you've confirmed their purpose. Domain DNS must point at your Spaceship hosting; use the domain's hosting connection settings in Spaceship.

Never publish `src/`, `web/`, credentials, or the repository root.

## Deployment targets

Spaceship hosts both the marketing website and the application's VPS. An old Cloudflare
Workers build connection may still publish an obsolete GitHub check; it is not a deployment
target or release requirement for this application. Do not deploy application code or profile
state to Cloudflare to satisfy that check.
