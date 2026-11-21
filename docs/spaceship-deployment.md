# ThreatLint marketing deployment to Spaceship

The website is static and lives in `marketing/`; the real Workbench in `web/` is **not** publicly deployed.

The verified Spaceship server is `server66.shared.spaceship.host`, and the `threatlint.dev` document root is `/home/xpqbpgplls/threatlint.dev`.

## Spaceship hosting setup

1. Open [Spaceship Hosting Manager](https://www.spaceship.com/) and select **Manage** next to the active hosting plan.
2. Confirm `threatlint.dev` is connected to this hosting subscription. In **Advanced → Document root folder**, confirm the domain's exact website directory. Ensure HTTPS/SSL is active.
3. Open cPanel via **Access → Access your cPanel**; find **Files → FTP Accounts**.
4. Create a **dedicated FTP account** with a strong generated password; set its **Directory** to `/home/xpqbpgplls/threatlint.dev` (cPanel may already display the `/home/xpqbpgplls/` prefix). **Do not** set the account directory to `/` in the cPanel form: that would grant access to your entire home directory. The remote path seen *after login* by a folder-scoped FTP account is `/`.
5. Under that account, select **Configure FTP Client**. Copy the **full FTP username**. Use the verified server hostname `server66.shared.spaceship.host`. Spaceship documents explicit FTPS on port 21.

See [Spaceship's official FTP guide](https://www.spaceship.com/knowledgebase/how-to-create-and-access-ftp-accounts/).

## GitHub Actions: add secrets

Open [repository Actions secrets and variables](https://github.com/h0p3sf4ll/threatlint/settings/secrets/actions). Under **Secrets**, add all three as **repository secrets**, not source files or chat messages:

| Name | Value |
| --- | --- |
| `SPACESHIP_FTP_HOST` | `server66.shared.spaceship.host` (without `ftp://` or port) |
| `SPACESHIP_FTP_USER` | Dedicated FTP account's **full** username |
| `SPACESHIP_FTP_PASSWORD` | Dedicated FTP account password |

Under **Variables**, add:

| Name | Value |
| --- | --- |
| `SPACESHIP_FTP_PATH` | `/` when the FTP account is scoped to the website's document root |
| `SPACESHIP_DEPLOY_ENABLED` | `true` only once you have verified the document root and secrets |

**Security:** Do not use the Spaceship login password or full-access cPanel tokens as deployment secrets. The workflow requires TLS and certificate verification, uses FTP passive mode and does not delete remote files. If it reports a certificate mismatch, fix the hostname or Spaceship TLS configuration; do not disable verification.

## First deploy and ongoing delivery

Open [Deploy marketing site to Spaceship — GitHub Actions](https://github.com/h0p3sf4ll/threatlint/actions/workflows/deploy-marketing-spaceship.yml), choose **Run workflow** on `main`. The validation job works before deployment is enabled; the deployment job is skipped until `SPACESHIP_DEPLOY_ENABLED=true`. Once enabled, the workflow deploys automatically when `marketing/**` or the deployment workflow changes on `main`. Manual runs deploy only from `main`; other branches can run validation but cannot deploy. For unattended delivery, the `production` environment must allow these deployments without a required reviewer or wait timer.

The workflow stages only the marketing site, excludes the Cloudflare-only `_headers` file, and publishes using certificate-verified **explicit FTPS**. The password is passed through `LFTP_PASSWORD`, not a command-line argument. After upload, it verifies that the public HTTPS homepage, stylesheet, logo, robots.txt and sitemap.xml exactly match the deployed source. The deployment job has a ten-minute timeout. The included `marketing/.htaccess` is intended for Spaceship's LiteSpeed/Apache-compatible shared hosting.

Verify `https://threatlint.dev` loads the homepage, styles, logo and valid TLS. If a default placeholder persists, remove or rename an old `index.php` or fix the document root in cPanel. Don't delete other site files until you've confirmed their purpose. Domain DNS must point at your Spaceship hosting; use the domain's hosting connection settings in Spaceship.

Never publish `src/`, `web/`, credentials, or the repository root.
