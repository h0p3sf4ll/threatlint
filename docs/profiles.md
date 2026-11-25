---
title: Profiles and saved settings
description: Sign in to a personal or company workspace and understand where Threatlint saves your settings.
---

# Profiles and saved settings

The web app saves your work to a signed-in profile. The desktop app uses your local operating-system user profile and works without a Threatlint login.

## Sign in to the web app

1. Open [app.threatlint.dev](https://app.threatlint.dev).
2. Choose an available sign-in provider, or use your organization's SSO connection.
3. Complete sign-in with that provider and return to Threatlint.
4. Check the signed-in profile in the top bar before opening a repository or changing settings.

Threatlint does not offer local username-and-password accounts. Your identity provider manages your password and any verification steps. Only configured providers appear on the sign-in screen.

To end your Threatlint session, choose **Sign out** in the top bar. Logging out does not delete saved settings or reports. Your identity provider may keep its own session, so signing in again can reuse that provider account.

## Choose an organization

Sign in with your provider first. Threatlint checks the organizations your exact sign-in identity belongs to:

- One organization opens automatically.
- Several organizations appear in a workspace chooser.
- With no organization membership, you can create an organization or continue with your personal workspace.

You do not need to enter an organization slug. An existing company entry link still opens that organization's sign-in flow. Use **Workspaces** in the top bar to switch between your organization and personal profiles.

An administrator must add the identity you use. An email address at the company domain does not enroll you automatically, and accounts from different providers are not linked by email. If you were added through GitHub, use that GitHub identity to sign in.

If membership discovery is unavailable, retry or continue personally. An unavailable directory is not treated as an empty membership list.

## Create an organization

If you do not belong to an organization, enter its display name and choose **Create organization** after sign-in. Threatlint creates the workspace, makes you its first administrator, and takes you through organization sign-in. The workspace address is generated for you.

Organization creation does not enable automatic membership. Add each teammate deliberately.

## Manage members and access

Organization administrators can open **Settings → Roles & access** to see every member, including people who have not opened the Workbench yet.

1. To add a teammate, enter the email they use for Threatlint and choose **Find account**. They must sign in to Threatlint once before you can add them.
2. Choose the correct provider account if more than one identity matches. Select a role, then choose **Add member**.
3. To change an existing member's role, choose the role on their row and select **Save role**.
4. To revoke membership, select **Remove access** and confirm.

| Role | Access |
| --- | --- |
| Administrator | Manage members, shared integrations and settings; run reviews and manage findings |
| Analyst | Run reviews, choose personal models, and manage findings and tickets |
| Viewer | Read findings and reports |

Role changes apply to subsequent requests. Removal ends organization sessions without deleting the person's personal profile. At least one administrator must remain. A failed identity-provider removal can leave the member listed with access blocked; **Restore access** is a separate, deliberate action.

## Understand what is separate

| Scope | What to expect |
| --- | --- |
| Personal web profile | Your saved preferences, model settings, checkouts, and reports |
| Company web profile | Your own preferences, model settings, checkouts, and reports within that company |
| Company integrations | Connections and tracked ticket records can be shared within the company, subject to your role |
| Desktop | Settings and reports in the current operating-system user's local profile |

Personal and company profiles remain separate even when you use the same sign-in identity. Different provider identities can also be separate accounts. Settings do not automatically copy between profiles, providers, or the desktop app.

## Save and check your settings

1. Confirm the intended personal or company profile in the top bar.
2. Open **Settings**, make the change, and save it using that section's controls.
3. Reopen the section to check the saved value. The **Guided** or **Advanced** experience choice also persists for that profile.

If a preference appears to be missing, check the profile before changing it again. For model credentials and provider-specific behavior, see [Model providers](model-providers.md).

Nonsecret model preferences persist. Model API keys entered for a review stay in browser-session memory; they are not saved as ordinary preferences. Integration credentials persist only when explicitly saved through their settings forms.

## Work on the desktop without login

Open the installed desktop app and select a local repository. You can run local source scans without a Threatlint account or model provider. Connecting a private repository, using a model service, or updating a remote tracker may require credentials for that service.

See [Install Threatlint](setup.md) and [Scan source code](security-scanner.md) for desktop setup.
