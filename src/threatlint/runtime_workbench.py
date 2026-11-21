"""Stdin-only Workbench bridge to the existing isolated Docker runtime provider."""
from __future__ import annotations

import base64
import json
import os
import shutil
import signal
import sys
import tempfile

from threatlint.runtime_env import DockerProvider, Limits, detect


def auth_headers(auth: dict) -> dict:
    kind = auth.get("type", "none")
    if kind == "none":
        return {}
    if kind == "bearer":
        return {"Authorization": f"Bearer {auth['token']}"}
    if kind == "basic":
        token = base64.b64encode(f"{auth['username']}:{auth['password']}".encode()).decode()
        return {"Authorization": f"Basic {token}"}
    if kind == "cookie":
        return {"Cookie": auth["cookie"]}
    if kind == "api-key":
        return {auth["name"]: auth["value"]}
    if kind == "headers":
        return auth["headers"]
    raise ValueError("Use bearer, basic, cookie, API key, or headers for isolated runtime authentication")


def run(config: dict, *, provider=None, progress=lambda stage: None) -> dict:
    limits = Limits(max_requests=config["limits"]["maxRequests"], request_timeout=max(1, config["limits"]["timeoutMs"] // 1000))
    env = provider or DockerProvider(limits)
    work = tempfile.mkdtemp(prefix="threatlint-workbench-runtime-")
    state = {"run_id": DockerProvider.new_run_id(), "work": work}
    result = {}
    try:
        progress("Preparing isolated source checkout")
        checkout = os.path.join(work, "repo")
        shutil.copytree(config["repoPath"], checkout, symlinks=True,
                        ignore=shutil.ignore_patterns(".git", "node_modules", ".venv", "__pycache__", ".env", ".env.local", ".env.production"))
        plan = detect(checkout, work)
        progress("Building application and backing services")
        env.provision(state, plan)
        progress("Starting isolated application")
        env.deploy(state)
        progress("Running repository tests")
        tests = env.run_tests(state)
        primary = config.get("auth", {"type": "none"})
        profiles = [{"label": "anonymous" if primary.get("type") == "none" else "primary", "auth": primary}, *config.get("roles", [])]
        if config.get("checks", {}).get("compareAnonymous") and config.get("auth", {}).get("type") != "none":
            profiles.append({"label": "anonymous", "auth": {"type": "none"}})
        requests = []
        identities = {}
        for profile in profiles:
            for path in config["paths"]:
                key = str(len(requests))
                requests.append({"id": key, "path": path, "method": "GET", "headers": auth_headers(profile["auth"])})
                identities[key] = {"path": path, "identity": profile["label"]}
        if len(requests) > limits.max_requests:
            raise ValueError("Paths and roles exceed the shared sandbox request budget")
        progress("Scanning isolated application")
        responses = env.probe(state, requests)
        # Remove actual credential values even if the application echoes them.
        secrets = [value for request in requests for value in request["headers"].values() if value]
        secrets += [str(value) for profile in profiles for key, value in profile["auth"].items()
                    if key in ("token", "password", "value", "cookie") and value]
        encoded = json.dumps(responses)
        for secret in sorted(set(secrets), key=len, reverse=True):
            encoded = encoded.replace(json.dumps(secret)[1:-1], "<redacted credential>")
        result = {"responses": json.loads(encoded), "identities": identities, "tests": {"status": (tests or {}).get("tests", {}).get("status", "not recorded")},
                  "isolation": "Docker internal network; bounded resources; no host mounts"}
    finally:
        progress("Removing ephemeral environment")
        try:
            env.teardown(state)
            if state.get("teardown", {}).get("remaining"):
                raise RuntimeError("Sandbox cleanup left labelled resources; inspect Docker before retrying")
            result["cleanup"] = "complete"
        finally:
            shutil.rmtree(work, ignore_errors=True)
    return result


def main() -> None:
    def interrupted(_signum, _frame):
        raise RuntimeError("Runtime scan cancelled")
    signal.signal(signal.SIGTERM, interrupted)
    config = json.load(sys.stdin)
    try:
        result = run(config, progress=lambda stage: print(json.dumps({"stage": stage}), flush=True))
        print(json.dumps({"result": result}), flush=True)
    except Exception:
        # Provider exceptions may contain build output or secret configuration.
        print(json.dumps({"error": "Isolated runtime scan could not complete. Verify Docker, application build/start configuration, test credentials, and cleanup of containers labelled threatlint.dast.run."}), flush=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
