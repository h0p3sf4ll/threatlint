# Bring the security conversation to Teams

Use Teams when the team already has a finding and needs to discuss its evidence
or next action. Use the Workbench or CLI when the reviewer needs to inspect a repository.

**The distinction matters:** the bot reviews supplied evidence. It has no repository
inspection, browser, runtime-capture, login, or test-execution tools.

## Before you deploy

- Node.js 18+ for the bot package.
- An Azure Bot registration and an HTTPS endpoint reachable by Teams.
- An Anthropic API key, Azure Bot App ID, and App Password in your deployment's
  secret store.
- Permission from your Teams administrator to upload/install the app.

Deploy with the repository layout intact: the bot loads agent definitions from
`src/threatlint/data/` and the model policy from `web/lib/`. Copying only
`teams-app/` is not a complete deployment.

## Set up the bot

1. Create an Azure Bot registration. Set the messaging endpoint to
   `https://YOUR_HOST/api/messages`.
2. Configure `ANTHROPIC_API_KEY`, `BOT_APP_ID`, and `BOT_APP_PASSWORD` securely in
   the host environment. Do not put their values in the manifest or repository.
3. From the checkout:

   ```bash
   npm --prefix teams-app install
   npm --prefix teams-app start
   ```

   The service defaults to port `3978`; set `PORT` when needed. Your hosting setup
   must expose the HTTPS messaging endpoint.

4. In [manifest.json](../teams-app/manifest.json), replace `{{BOT_APP_ID}}`.
   Supply the referenced 192x192 color and 32x32 outline icons.
5. Zip the manifest and the two icons, then upload through Teams' app-management
   flow permitted by your administrator.
6. Send `@threatlint /help`. A command list is the first success check; it does not
   prove that a model request or repository review has run.

## Ask a question the bot can answer

Supply a small, redacted evidence set and the relevant question:

```text
@threatlint /fp-review
Review this supplied finding and code excerpt. Identify missing context,
give a disposition only where supported, and propose the next verification step.
```

The bot routes the 22 specialist commands and returns the report in the
conversation, splitting long responses in order. It does not create a Word file.
Missing source is a limitation, not permission to invent a code path.

`CLAUDE_MODEL` overrides the bot model. Otherwise it follows the
[scanning-model policy](setup.md#models).

## If it does not respond

| Check | What to verify |
| --- | --- |
| Routing | Azure Bot messaging endpoint matches `/api/messages` on the deployed host |
| Credentials | App ID/password and Anthropic key are configured in the host, not just locally |
| App package | Manifest App ID matches the Bot registration; icons exist in the uploaded ZIP |
| Data files | Agent definitions and model-policy module are deployed with the bot |
| Diagnostics | Inspect host logs without copying secrets into chat or tickets |

**Next:** move a source-dependent question into the [Workbench](workbench.md)
or [CLI](setup.md) and attach the resulting redacted evidence to the conversation.
