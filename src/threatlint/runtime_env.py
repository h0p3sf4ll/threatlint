"""Ephemeral, isolated application environments for runtime (DAST) validation.

A provider builds a repository checkout into containers, deploys it with any backing services on a network
with no route out, waits for health, runs the repository's own tests, sends a bounded list of requests to the
application from inside that network, and removes everything it created. Only Docker is implemented;
`EnvironmentProvider` is the interface another provider (e.g. AWS) implements.

Isolation (Docker): an `--internal` network (no default route, so no egress) once the images are built; egress is
used only by `docker build` / `docker pull`. Containers run with CPU, memory, PID and time limits, no host mounts
(the checkout is the build context, never mounted), `no-new-privileges`, all capabilities dropped for the app,
test and probe containers, and the labels `threatlint.dast.run=<run id>`, so teardown removes exactly this run.
Requests go only to the sandbox application by service name; the probe refuses any other host.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import subprocess
import tempfile
from typing import Protocol

from threatlint.avit_resolve import ResolveError
from threatlint.runtime_config import _SENSITIVE, _read, example_env, scrub_env, synthetic
from threatlint.runtime_compose import _inside, parse_services
from threatlint.runtime_models import EnvError, Limits, Plan, Service, plan_dict, plan_from
from threatlint.runtime_discovery import (
    IMAGES, _DEFAULT_PORTS, _compose_file, _dependency_text, _python_start, _stack,
    backing_services, compose_services, default_test_command, detect, generated_dockerfile,
)

LABEL = "threatlint.dast.run"
_RUN_ID = re.compile(r"tl-dast-[0-9a-f]{10}")
PROBE_IMAGE = os.environ.get("THREATLINT_DAST_PROBE_IMAGE", "python:3.12-slim")


# ── Provider interface ──────────────────────────────────────────────────────

class EnvironmentProvider(Protocol):
    """Lifecycle of one isolated environment. `state` is a JSON-serialisable dict persisted between steps."""
    name: str

    def provision(self, state: dict, plan: Plan) -> dict: ...  # images, network, volumes
    def deploy(self, state: dict) -> dict: ...  # start services, wait for the app to be healthy
    def run_tests(self, state: dict) -> dict: ...
    def probe(self, state: dict, requests: list[dict]) -> list[dict]: ...  # only to the sandbox application
    def teardown(self, state: dict) -> dict: ...


# Runs inside the probe container on the internal network. It connects only to the sandbox application host
# named in the plan, never follows redirects, and returns raw responses for redaction on the host.
_PROBE_SCRIPT = r'''
import http.client, json, sys, time
plan = json.loads(sys.stdin.read())
host, port, timeout = plan["host"], int(plan["port"]), float(plan["timeout"])
out = {"routes": [], "results": []}
try:
    out["routes"] = [line.split()[1] for line in open("/proc/net/route").read().splitlines()[1:] if line.split()]
except OSError:
    pass
def send(item):
    path = item["path"]
    if not path.startswith("/") or path.startswith("//") or "\r" in path or "\n" in path:
        return {"id": item["id"], "error": "refused: not an origin-relative path"}
    started = time.time()
    try:
        connection = http.client.HTTPConnection(host, port, timeout=timeout)
        body = item.get("body")
        connection.request(item.get("method", "GET"), path, body=body.encode() if body is not None else None, headers=item.get("headers") or {})
        response = connection.getresponse()
        data = response.read(262144)
        connection.close()
        return {"id": item["id"], "status": response.status, "reason": response.reason, "headers": [[k, v] for k, v in response.getheaders()],
                "body": data.decode("utf-8", "replace"), "elapsed_ms": int((time.time() - started) * 1000)}
    except Exception as exc:
        return {"id": item["id"], "error": type(exc).__name__ + ": " + str(exc)[:200], "elapsed_ms": int((time.time() - started) * 1000)}
if plan.get("mode") == "health":
    deadline = time.time() + float(plan["deadline"])
    while time.time() < deadline:
        results = [send({"id": path, "path": path}) for path in plan["paths"]]
        ready = [r for r in results if r.get("status") and r["status"] < 400] or [r for r in results if r.get("status") and r["status"] < 500 and r["id"] == "/"]
        if ready:
            out["results"] = results
            out["healthy"] = ready[0]["id"]
            break
        out["results"] = results
        time.sleep(2)
else:
    for item in plan["requests"][: int(plan["max"])]:
        out["results"].append(send(item))
print(json.dumps(out))
'''


class DockerProvider:
    """Local Docker: images built per run, an internal network, labelled containers, exact teardown."""
    name = "docker"

    def __init__(self, limits: Limits | None = None, runner=subprocess.run):
        self.limits = limits or Limits()
        self._run = runner
        self.docker = shutil.which("docker") or "docker"

    # Every docker command goes through here; argv only, never a shell.
    def _docker(self, args: list[str], *, timeout: int = 120, input_text: str | None = None, check: bool = True) -> subprocess.CompletedProcess:
        env = {key: os.environ[key] for key in ("PATH", "HOME", "DOCKER_HOST", "DOCKER_CONFIG", "DOCKER_CONTEXT", "TMPDIR") if key in os.environ}
        try:
            result = self._run([self.docker, *args], capture_output=True, text=True, timeout=timeout, check=False, input=input_text, env={**env, "DOCKER_BUILDKIT": "1"})
        except subprocess.TimeoutExpired as exc:
            raise EnvError(f"docker {args[0]} exceeded {timeout} s") from exc
        except FileNotFoundError as exc:
            raise EnvError("Docker is not installed or not on PATH") from exc
        if check and result.returncode != 0:
            raise EnvError(f"docker {' '.join(args[:2])} failed: {(result.stderr.strip().splitlines() or ['no output'])[-1][:300]}")
        return result

    def available(self) -> str:
        result = self._docker(["info", "--format", "{{.ServerVersion}}"], timeout=30, check=False)
        if result.returncode != 0:
            raise EnvError("Docker is not running; start Docker Desktop and retry (`docker info`)")
        return result.stdout.strip()

    @staticmethod
    def new_run_id() -> str:
        return f"tl-dast-{secrets.token_hex(5)}"

    def _labels(self, state: dict) -> list[str]:
        if not _RUN_ID.fullmatch(state.get("run_id", "")):
            raise EnvError("Invalid run id in the environment state")
        return ["--label", f"{LABEL}={state['run_id']}"]

    def _limits(self) -> list[str]:
        return ["--cpus", self.limits.cpus, "--memory", self.limits.memory, "--memory-swap", self.limits.memory, "--pids-limit", str(self.limits.pids),
                "--security-opt", "no-new-privileges"]

    def provision(self, state: dict, plan: Plan) -> dict:
        self.available()
        run_id = state["run_id"]
        images, log = {}, []
        for service in plan.services:
            if service.build:
                tag = f"{run_id}-{service.name.lower()}:latest"
                args = ["build", *self._labels(state), "-t", tag, "-f", service.build["dockerfile"], "--pull=false"]
                for key, value in service.build.get("args", {}).items():
                    args += ["--build-arg", f"{key}={value}"]
                if service.build.get("target"):
                    args += ["--target", service.build["target"]]
                result = self._docker([*args, service.build["context"]], timeout=self.limits.build_timeout, check=False)
                log.append({"service": service.name, "step": "build", "exit": result.returncode, "tail": (result.stderr or result.stdout)[-3000:]})
                if result.returncode != 0:
                    state.update(images=images, build=log)
                    raise EnvError(f"Building {service.name} failed (exit {result.returncode}); see build log in the evidence")
                images[service.name] = tag
            else:
                if not service.image:
                    raise EnvError(f"Service {service.name} has neither an image nor a build")
                if self._docker(["image", "inspect", service.image], check=False).returncode != 0:
                    result = self._docker(["pull", service.image], timeout=self.limits.build_timeout, check=False)
                    log.append({"service": service.name, "step": "pull", "exit": result.returncode, "tail": result.stderr[-500:]})
                    if result.returncode != 0:
                        raise EnvError(f"Pulling {service.image} failed")
                images[service.name] = service.image
        if self._docker(["image", "inspect", PROBE_IMAGE], check=False).returncode != 0:
            self._docker(["pull", PROBE_IMAGE], timeout=self.limits.build_timeout)
        network = f"{run_id}-net"
        self._docker(["network", "create", "--internal", *self._labels(state), network])
        user = self._docker(["image", "inspect", "--format", "{{.Config.User}}", images[plan.app]], check=False).stdout.strip()
        state.update(images=images, built=[tag for name, tag in images.items() if tag.startswith(run_id)], network=network, build=log,
                     app_user=user or "root", plan=plan_dict(plan))
        return state

    def deploy(self, state: dict) -> dict:
        plan = plan_from(state["plan"])
        containers = []
        env_dir = state["work"]
        for service in [s for s in plan.services if s.role != "app"] + [plan.app_service()]:
            name = f"{state['run_id']}-{service.name.lower()}"
            env_file = os.path.join(env_dir, f".env.{service.name}")
            with open(env_file, "w", encoding="utf-8") as handle:
                handle.write("".join(f"{key}={str(value).replace(chr(10), ' ')}\n" for key, value in service.env.items()))
            args = ["run", "-d", "--name", name, "--hostname", service.name, *self._labels(state), "--network", state["network"],
                    "--network-alias", service.name, *self._limits(), "--env-file", env_file, "--tmpfs", "/tmp:rw,size=256m"]
            if service.role == "app":
                args += ["--cap-drop", "ALL", "--restart", "on-failure:5"]
            if service.entrypoint:
                args += ["--entrypoint", service.entrypoint[0]]
            args += [state["images"][service.name], *service.entrypoint[1:], *service.command]
            self._docker(args, timeout=120)
            containers.append(name)
        state["containers"] = containers
        health = self._probe_run(state, {"mode": "health", "paths": plan.health_paths, "deadline": self.limits.start_timeout})
        state["health"] = {"healthy": bool(health.get("healthy")), "path": health.get("healthy", ""), "egress_routes": health.get("routes", []),
                           "default_route": "00000000" in health.get("routes", []),
                           "responses": [{k: r.get(k) for k in ("id", "status", "error")} for r in health.get("results", [])]}
        if not state["health"]["healthy"]:
            state["health"]["app_log"] = self._docker(["logs", "--tail", "60", f"{state['run_id']}-{plan.app.lower()}"], check=False).stderr[-3000:]
        return state

    def _probe_run(self, state: dict, plan: dict) -> dict:
        app = plan_from(state["plan"])
        payload = {"host": app.app, "port": app.port, "timeout": self.limits.request_timeout, "max": self.limits.max_requests, **plan}
        timeout = int(plan.get("deadline", 0)) + 60 if plan.get("mode") == "health" else self.limits.request_timeout * self.limits.max_requests + 60
        result = self._docker(["run", "--rm", "-i", "--name", f"{state['run_id']}-probe-{secrets.token_hex(3)}", *self._labels(state), "--network", state["network"],
                               *self._limits(), "--cap-drop", "ALL", "--user", "65534:65534", "--read-only", PROBE_IMAGE, "python", "-I", "-c", _PROBE_SCRIPT],
                              timeout=timeout, input_text=json.dumps(payload), check=False)
        try:
            return json.loads(result.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError) as exc:
            raise EnvError(f"The probe container failed: {(result.stderr.strip().splitlines() or ['no output'])[-1][:200]}") from exc

    def run_tests(self, state: dict) -> dict:
        plan = plan_from(state["plan"])
        if not plan.test_command:
            state["tests"] = {"status": "NOT FOUND", "command": "", "exit": None, "tail": "No test suite detected; pass --test-command"}
            return state
        app = plan.app_service()
        env_file = os.path.join(state["work"], f".env.{app.name}")
        args = ["run", "--rm", "--name", f"{state['run_id']}-tests", *self._labels(state), "--network", state["network"], *self._limits(), "--cap-drop", "ALL",
                "--env-file", env_file, "-e", f"APP_URL=http://{plan.app}:{plan.port}", "-e", "CI=true", "--tmpfs", "/tmp:rw,size=256m",
                "--entrypoint", "sh", state["images"][plan.app], "-c", plan.test_command]
        try:
            result = self._docker(args, timeout=self.limits.test_timeout, check=False)
            status, code, tail = ("PASSED" if result.returncode == 0 else "FAILED"), result.returncode, (result.stdout + result.stderr)[-4000:]
        except EnvError as exc:
            status, code, tail = "TIMED OUT", None, str(exc)
            self._docker(["rm", "-f", f"{state['run_id']}-tests"], check=False)
        state["tests"] = {"status": status, "command": plan.test_command, "exit": code, "tail": tail, "network": "internal (no egress)"}
        return state

    def probe(self, state: dict, requests: list[dict]) -> list[dict]:
        if not state.get("health", {}).get("healthy"):
            raise EnvError("The sandbox application is not healthy; nothing was probed")
        if len(requests) > self.limits.max_requests:
            raise EnvError(f"At most {self.limits.max_requests} requests per probe")
        output = self._probe_run(state, {"mode": "requests", "requests": requests})
        if "00000000" in output.get("routes", []):
            raise EnvError("The probe network has a default route; refusing to treat the environment as isolated")
        return output.get("results", [])

    def teardown(self, state: dict) -> dict:
        """Remove every container, network, volume and built image labelled with this run id."""
        label = f"label={LABEL}={state['run_id']}"
        self._labels(state)
        removed: dict[str, list[str]] = {}
        containers = self._docker(["ps", "-aq", "--filter", label], check=False).stdout.split()
        if containers:
            self._docker(["rm", "-f", "-v", *containers], check=False, timeout=180)
        removed["containers"] = containers
        networks = self._docker(["network", "ls", "-q", "--filter", label], check=False).stdout.split()
        if networks:
            self._docker(["network", "rm", *networks], check=False)
        removed["networks"] = networks
        volumes = self._docker(["volume", "ls", "-q", "--filter", label], check=False).stdout.split()
        if volumes:
            self._docker(["volume", "rm", "-f", *volumes], check=False)
        removed["volumes"] = volumes
        images = self._docker(["images", "-q", "--filter", label], check=False).stdout.split()
        if images:
            self._docker(["rmi", "-f", *dict.fromkeys(images)], check=False, timeout=180)
        removed["images"] = list(dict.fromkeys(images))
        for name in os.listdir(state.get("work", "")) if os.path.isdir(state.get("work", "")) else []:
            if name.startswith(".env."):
                os.remove(os.path.join(state["work"], name))
        left = [kind for kind, command in (("containers", ["ps", "-aq", "--filter", label]), ("networks", ["network", "ls", "-q", "--filter", label]),
                                           ("images", ["images", "-q", "--filter", label])) if self._docker(command, check=False).stdout.strip()]
        state["teardown"] = {**{key: len(value) for key, value in removed.items()}, "remaining": left}
        return state


PROVIDERS = {"docker": DockerProvider}


def provider(name: str = "docker", **kwargs) -> EnvironmentProvider:
    if name not in PROVIDERS:
        raise EnvError(f"Unknown environment provider {name}; available: {', '.join(PROVIDERS)}")
    return PROVIDERS[name](**kwargs)


def scratch_dir(prefix: str = "threatlint-dast-") -> str:
    return tempfile.mkdtemp(prefix=prefix)
