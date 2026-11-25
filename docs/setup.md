---
title: Install Threatlint
description: Choose the web app, desktop Workbench, or CLI and prepare your first review.
---

Use the interface that fits your work. You can inspect a sample report or run the built-in security scanner before configuring a model provider.

## Before you start

| Interface | What you need |
| --- | --- |
| Hosted web app | A permitted sign-in account; your company link for a company profile |
| Installed desktop app | The app and access to the repository you want to inspect |
| CLI from source | Git and Python 3.9 or later |
| Workbench from source | Node.js 22.12 or later and npm; Python for CLI workflows and Word export |

Desktop and the local Workbench do not require a Threatlint sign-in. Model-provider and integration credentials are needed only for the services you choose.

## Open the web app

1. Open [app.threatlint.dev](https://app.threatlint.dev), or the company link supplied by your administrator.
2. Sign in with an available provider.
3. Open a repository accessible to your web profile, or choose **See a sample findings report**.

Your web profile saves its own settings and history. It cannot browse your laptop's folders or reuse your desktop CLI logins. See [Profiles](profiles.md).

## Install from this checkout

```bash
git clone https://github.com/h0p3sf4ll/threatlint.git
cd threatlint
```

Install in a virtual environment so you do not need to modify a managed system Python. On macOS or Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
threatlint --help
```

On Windows PowerShell:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe -m threatlint --help
$env:THREATLINT_PYTHON = (Resolve-Path '.venv\Scripts\python.exe').Path
```

Use the same environment for later commands. If it is not activated, replace `threatlint` with the environment's Python followed by `-m threatlint`. The Windows setting above also selects that interpreter for local Workbench CLI workflows and Word conversion.

For the local browser Workbench:

```bash
npm --prefix web ci
npm --prefix web start
```

Open <http://127.0.0.1:3000>. To launch the desktop interface from the same checkout instead:

```bash
npm --prefix web run desktop
```

Desktop chooses an available local port and starts its backend. An installed desktop app can be opened through its usual shortcut.

## Choose your workspace

Run client installers from the repository you want to review:

| Client | Command and first action |
| --- | --- |
| Claude Code | `threatlint install --local -y`; restart the client, then try `/security-review` or `/threat-model src/auth` |
| GitHub Copilot | `threatlint install --copilot --local -y`; reload a trusted VS Code workspace and choose an AppSec agent |
| Codex | `threatlint install --codex --local -y`; start a new chat and request `$appsec-threat-modeler` |

Omit `--local` for a user-level install. Copilot's user-level discovery depends on the client. Its installer copies agents and skills, not the checkout's optional prompt files. Re-run the installer rather than copying individual helper scripts. Remove a Codex installation with `threatlint uninstall --codex --local -y` from the same repository.

For a terminal review with a running local model:

```bash
threatlint run threat-model --provider lmstudio
threatlint run security-review --base HEAD~1 --head HEAD
threatlint run fp-review --findings ./results.sarif
```

Use `--model MODEL_ID`, `--base-url URL`, or `--output-dir ./reports` when needed. See [Model providers](model-providers.md) for local and cloud setup.

## Cloud providers

Configure **Settings → Model provider** before starting a model review. Choose a provider approved for the source and evidence you will send. Native Claude Code, Codex, and Copilot CLI workflows use their own sign-ins; API providers use their configured keys. Follow [Model providers](model-providers.md).

## Models

Choose an available model in Settings or pass `--model`. The [model guide](model-providers.md#model-defaults) explains defaults and the `THREATLINT_SCAN_MODEL` / `THREATLINT_GENERAL_MODEL` overrides. Installing Threatlint does not grant model access.

### Where scanned repositories are cloned

DAST, runtime red-team, and AVIT workflows use temporary checkouts. Set `THREATLINT_REPO_STORE`, or the `repoStore` key in your local `~/.threatlint/org.json`, to use another disk:

```json
{"repoStore": "/Volumes/Repo Store/threatlint"}
```

Each run gets a separate subdirectory, normally removed afterward. `--keep-checkout` retains a runtime red-team checkout. Keep this machine-specific setting outside the repository.

## Check the result

You should be able to open the Workbench or run `threatlint --help`. A sample report is labelled synthetic; it is not a scan of your code. A real review should name inspected evidence and distinguish completed checks from proposed tests.

For a missing command, use the installation interpreter. For missing native commands, restart the client after installation. For missing credentials, run `threatlint setup --check` and follow [AWS Parameter Store](aws-parameters.md) or the relevant integration guide. For missing exports, see [No Word file](reports.md#no-word-file).

## Next steps

- Follow the [Quickstart](learning.md) for a small first review.
- Use the [Workbench](workbench.md) or run a [security scan](security-scanner.md).
- Read and share your [Reports](reports.md).
