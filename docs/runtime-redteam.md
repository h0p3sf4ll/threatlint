# Runtime red team

Build an application from its own repository in an isolated, throwaway environment, attack the *running* app with
Threatlint's runtime ruleset, and let each assessment teach the ruleset to test the next one better. It complements
the static agents: they read the code; this runs it and observes how it actually behaves.

```bash
threatlint redteam run --repo https://github.com/acme/web.git --branch main
```

Output lands in a run directory: `redteam-report.md`, `avits.json` (AVIT drafts), and `redteam-state.json`.
The repository is cloned into the configurable repo store, and the checkout is deleted after the run unless you
pass `--keep-checkout` (see [Where scanned repositories are cloned](setup.md#where-scanned-repositories-are-cloned)).

## What it does

1. **Clone** the repository and branch.
2. **Understand the stack** and what it takes to build and run it (Node, Python, Java, Go; Compose when present),
   reusing the same detection the DAST workflow uses.
3. **Build and deploy** into an ephemeral, isolated environment: an internal Docker network **with no route out**,
   resource limits, no host mounts, capabilities dropped. Backing services (Postgres, Redis, …) come up with
   **synthetic credentials** by default.
4. **Run the repository's own tests** against the deployment, as a smoke signal.
5. **Discover endpoints** from the source (framework routes) plus any you supply with `--routes`, and the health path.
6. **Assess** each endpoint with the applicable rules. Requests are **bounded and sent only to the sandbox app**;
   the probes are the vetted DAST checks (reflected XSS, SQL injection, path traversal, open redirect, directory
   listing, CORS reflection, cookie flags, missing security headers, version disclosure, debug leakage).
7. **Draft AVITs** for the confirmed findings. **Posting to ServiceNow is stubbed** — drafts are written to the report
   and `avits.json`. A real integration registers one hook (`redteam.servicenow_stub.set_avit_publisher`).
8. **Tear down** everything the run created, always, including on failure.

Every observation is a **candidate finding for confirmation, not a proven exploit**. Nothing is exfiltrated, no
persistence is attempted, and the report states the isolation it ran under.

## Threatlint is the ruleset

A **rule** is a bounded, declarative runtime test pattern: an id, an OWASP category, a CWE, the vulnerability class
it probes, and where it applies. The built-in seed ships with Threatlint; rules never carry free-form payloads — each
maps to a request/assessment behaviour already vetted in the DAST subsystem.

```bash
threatlint redteam rules list        # built-in + learned rules, with each rule's cumulative yield
```

### Learning

Each assessment records, per rule, how often it was tried and confirmed and on which **endpoint shapes** (e.g. paths
under `/api/pay/…`). That learned store (at `~/.threatlint/redteam/ruleset.json`, written only for the current user)
orders higher-yield rules and endpoint shapes first on the next run, so coverage improves with each test. Learning
only ever adjusts ordering, confidence, and evidence — it never invents new attack payloads.

## Credentials

By default the app runs on synthetic credentials, which is safe and needs nothing. To run it with real credentials
resolved from the credential store your codebase already references, opt in:

```bash
threatlint redteam run --repo … --branch … --credentials creds.json
```

```json
{ "store": "aws-parameter-store", "secrets": { "DB_PASSWORD": "/app/db", "STRIPE_KEY": "/app/stripe" } }
```

Only **store references** are allowed; literal secrets in the config are rejected. Resolved values are injected into
the app environment for the run only, redacted from the report and `avits.json`, and — like everything else — cannot
leave the no-egress sandbox.

## Scope and authorization

Run this only against applications you are authorized to test. It builds and executes the target application; use it
on your own repositories and in an environment you control. Docker is required for the default provider.
