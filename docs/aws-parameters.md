---
title: Load values from AWS Parameter Store
description: Use an authorized AWS session to load named integration credentials without copying them into forms.
---

Threatlint Desktop can load the Parameter Store values you name into its current app session. It saves references rather than decrypted secrets. Teams can also use the CLI setup wizard to import shared configuration.

## Before you start

You need:

- [AWS CLI v2](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html), verified with `aws --version` in a new terminal.
- An AWS IAM Identity Center sign-in or another authorized AWS CLI session.
- The profile, parameter region, and exact parameter names or SSM ARNs supplied by your administrator.
- `ssm:GetParameters` and the relevant `kms:Decrypt` permission for encrypted values.

Threatlint reads named parameters with decryption. It does not enumerate or guess secrets across an AWS account. Store credential values as `SecureString` where appropriate.

The desktop private-browser flow is unavailable in hosted web profiles. See [Profiles](profiles.md) for the difference between local and hosted configuration.

## Load values in Desktop

1. Open **Settings → AWS Parameter Store**.
2. Select an existing AWS profile and the region containing your parameters. If needed, expand **Set up a new SSO profile** and enter your access portal URL, Identity Center region, account ID, and permission set. An omitted Identity Center region is detected from the portal.
3. Enter parameter names or SSM ARNs under **Parameter references**. Organization-configured references are filled in automatically.
4. Choose **Save references**.
5. Choose **Sign in privately & load**, select an installed browser, and complete SSO and MFA yourself.
6. Wait for confirmation that the configured values loaded, then open the relevant integration or model settings.

Supported references include ServiceNow connection details, Semgrep token/deployment, an Azure DevOps PAT, GitHub App IDs/PEM key, model API keys, and DefectDojo/SonarQube tokens.

The flow uses AWS CLI [device-code authorization](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sso.html). Chrome uses Incognito and Edge uses InPrivate. Safari uses **New Private Window** and may need macOS Automation and Accessibility permission. If that fails, choose Chrome/Edge or copy the offered link into a [Safari Private Window](https://support.apple.com/guide/mac-help/browse-the-web-mchlgtd_web01/mac). Threatlint does not fall back to a normal browser window.

## Reuse an AWS session

**Load with current AWS session** reuses an existing sign-in. **Reload configured values when the app starts** is optional and requires an unexpired session; leave it off unless you want that behavior. AWS CLI manages its SSO cache.

Threatlint stores references, profile, region, and this optional startup setting in `~/.threatlint/aws-parameters.json`. Decrypted values stay in the runner's environment until it exits. They are not returned to the UI, saved to browser storage, or included in reports. Loading model keys does not authorize model requests or change the model-sharing checkbox.

If a configured parameter is missing or inaccessible, no new values are applied. Check the profile, region, parameter name, and SSM/KMS permissions, then retry. A failed refresh retains the previously loaded session values.

## Import shared settings with the CLI

An administrator can publish one JSON parameter containing connection settings and references to other parameters. Replace these examples with your team's values; keep secrets out of this JSON:

```json
{
  "snowInstance": "https://your-instance.service-now.com",
  "snowClientIdParameter": "/your-team/servicenow/client-id",
  "snowClientSecretParameter": "/your-team/servicenow/client-secret",
  "semgrepTokenParameter": "/your-team/semgrep/token",
  "semgrepDeployment": "your-deployment",
  "awsProfile": "appsec",
  "adoOrganizations": ["your-organization"],
  "adoPatParameter": "/your-team/ado/pat"
}
```

1. Open an interactive terminal in the Python environment where Threatlint is installed.
2. Run setup with the shared parameter, profile, and region:

   ```bash
   threatlint setup --org-parameter /your-team/threatlint/setup --aws-profile appsec --aws-region us-west-2
   ```

3. Complete AWS sign-in and the integration checks.
4. Check the resulting configuration without further prompts:

   ```bash
   threatlint setup --check
   ```

Setup imports shared metadata, then retrieves and validates the configured ServiceNow, Azure DevOps, and Semgrep credentials. ServiceNow and Semgrep settings are saved for the CLI and Workbench. Azure DevOps keeps the parameter reference and validates the PAT for each selected organization without saving a local PAT copy.

`THREATLINT_ORG_PARAMETER` can supply the shared parameter name. Setup remembers the name and region in `~/.threatlint/org.json`; the setup region defaults to `us-west-2`. Environment settings take precedence over local settings, and imported metadata fills missing local fields. Remove a local override to accept that field from shared settings on the next setup.

AWS sign-in or shared-settings failures stop setup before integration prompts. A configured lookup failure does not fall back to asking you to copy secrets. Manual setup remains available when no references are configured. `threatlint setup --check` does not import settings or save credentials.

## Configure the Azure DevOps service account

Use **Settings → Azure DevOps**, or run:

```bash
threatlint ado service-account --parameter /your-team/ado/pat --organization your-organization --aws-profile appsec --region us-west-2
threatlint ado status
```

Repeat `--organization` for additional organizations. Access is validated before reference metadata is saved. While `adoPatParameter` is configured, runtime operations read its current value and do not fall back to personal environment or saved PATs. Lookup failures stop the operation. Allowed organizations come from `adoOrganizations`.

The AWS profile is selected by explicit `--aws-profile`, then `awsProfile` / `THREATLINT_AWS_PROFILE`, then the AWS default credential chain. Proposed-fix branches and pull requests require the service account's **Code: Read & write** scope and repository permissions. Existing personal PATs remain stored but are not used while this shared reference is configured.

## Check the result

Desktop reports how many configured values loaded without displaying them. CLI setup reports each integration's status. These checks establish credential access, not permission to send source to a model or to modify a tracker.

**Next:** configure [Model providers](model-providers.md), [ServiceNow AVIT reviews](avit-integration.md), or your [GitHub App](github-app.md).
