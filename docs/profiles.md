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

## Use a company workspace

Use your company's entry link, or enter its company slug on the sign-in screen. The slug selects the company workspace; it does not grant access. An administrator must add your identity as a member and enable the appropriate connection.

If company sign-in fails, confirm the slug and provider with your administrator. An email address at the company domain alone does not make you a member.

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
