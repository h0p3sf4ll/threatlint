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
from dataclasses import asdict, dataclass, field
from typing import Protocol

from threatlint.avit_resolve import ResolveError

LABEL = "threatlint.dast.run"
_RUN_ID = re.compile(r"tl-dast-[0-9a-f]{10}")
_SENSITIVE = re.compile(r"pass(word|wd)?|secret|token|api[_-]?key|private|credential|auth|salt|signing|access[_-]?key|dsn|_key$", re.I)
_DEFAULT_PORTS = {"node": 3000, "python": 8000, "java": 8080, "go": 8080}
PROBE_IMAGE = os.environ.get("THREATLINT_DAST_PROBE_IMAGE", "python:3.12-slim")
IMAGES = {"node": os.environ.get("THREATLINT_DAST_NODE_IMAGE", "node:20-slim"),
          "python": os.environ.get("THREATLINT_DAST_PYTHON_IMAGE", "python:3.12-slim"),
          "java": os.environ.get("THREATLINT_DAST_MAVEN_IMAGE", "maven:3.9-eclipse-temurin-21"),
          "go": os.environ.get("THREATLINT_DAST_GO_IMAGE", "golang:1.22"),
          "postgres": os.environ.get("THREATLINT_DAST_POSTGRES_IMAGE", "postgres:17"),
          "mysql": os.environ.get("THREATLINT_DAST_MYSQL_IMAGE", "mysql:8.4"),
          "redis": os.environ.get("THREATLINT_DAST_REDIS_IMAGE", "redis:7-alpine"),
          "mongo": os.environ.get("THREATLINT_DAST_MONGO_IMAGE", "mongo:7")}


class EnvError(ResolveError):
    """An environment could not be provisioned, deployed, tested, probed, or removed."""


@dataclass
class Limits:
    cpus: str = os.environ.get("THREATLINT_DAST_CPUS", "1.0")
    memory: str = os.environ.get("THREATLINT_DAST_MEMORY", "1g")
    pids: int = 512
    build_timeout: int = int(os.environ.get("THREATLINT_DAST_BUILD_TIMEOUT", "1200"))
    start_timeout: int = int(os.environ.get("THREATLINT_DAST_START_TIMEOUT", "180"))
    test_timeout: int = int(os.environ.get("THREATLINT_DAST_TEST_TIMEOUT", "600"))
    request_timeout: int = 10
    max_requests: int = 40


@dataclass
class Service:
    name: str
    image: str = ""
    build: dict = field(default_factory=dict)  # context (absolute), dockerfile (absolute), args, target
    env: dict = field(default_factory=dict)
    command: list = field(default_factory=list)
    entrypoint: list = field(default_factory=list)
    port: int = 0
    role: str = "backing"
    dropped: list = field(default_factory=list)  # compose settings not applied (bind mounts, ports, privileges)


@dataclass
class Plan:
    stack: str
    services: list
    app: str
    port: int
    health_paths: list
    test_command: str
    notes: list = field(default_factory=list)

    def app_service(self) -> Service:
        return next(service for service in self.services if service.name == self.app)


# ── Stack detection ─────────────────────────────────────────────────────────

def synthetic(name: str, cache: dict) -> str:
    """A random, clearly synthetic value; the same name maps to the same value within a run."""
    return cache.setdefault(name, f"tl-synthetic-{secrets.token_hex(8)}")


def _read(path: str, limit: int = 512 * 1024) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            return handle.read(limit)
    except OSError:
        return ""


def example_env(checkout: str, cache: dict) -> dict[str, str]:
    """Values from .env.example / .env.sample / .env.template, with every sensitive-looking value synthetic."""
    values: dict[str, str] = {}
    for name in (".env.example", ".env.sample", ".env.template", ".env.dist", "example.env"):
        for line in _read(os.path.join(checkout, name)).splitlines():
            match = re.match(r"\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$", line)
            if match and match.group(1) not in values:
                value = match.group(2).strip().strip("\"'")
                values[match.group(1)] = synthetic(match.group(1), cache) if _SENSITIVE.search(match.group(1)) or not value else value
    return values


def scrub_env(env: dict, cache: dict) -> dict[str, str]:
    """Compose / repository environment with interpolations resolved to defaults and sensitive values replaced."""
    result = {}
    for key, value in (env or {}).items():
        value = "" if value is None else str(value)
        value = re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::?-([^}]*))?\}", lambda m: m.group(2) if m.group(2) is not None else synthetic(m.group(1), cache), value)
        if _SENSITIVE.search(key) and not re.search(r"(?i)file$|path$|url$|host$|port$|user(name)?$|enabled$", key):
            # The same original value maps to the same synthetic one, so services that share a password still agree.
            value = synthetic("value:" + value, cache)
        result[str(key)] = value
    return result


def _dependency_text(checkout: str) -> str:
    return "\n".join(_read(os.path.join(checkout, name)).lower() for name in
                     ("package.json", "requirements.txt", "requirements-dev.txt", "pyproject.toml", "Pipfile", "pom.xml", "build.gradle", "go.mod"))


def backing_services(checkout: str, cache: dict) -> tuple[list[Service], dict[str, str]]:
    """Databases and caches the dependencies name, with synthetic credentials, and the app variables that reach them."""
    text = _dependency_text(checkout)
    services, env = [], {}
    def uses(*names: str) -> bool:
        return any(re.search(rf"(?<![\w-]){re.escape(name)}(?![\w-])", text) for name in names)
    if uses("pg", "psycopg", "psycopg2", "psycopg2-binary", "psycopg[binary]", "asyncpg", "postgresql", "org.postgresql", "github.com/lib/pq", "pgx"):
        password = synthetic("postgres-password", cache)
        services.append(Service("postgres", IMAGES["postgres"], env={"POSTGRES_USER": "app", "POSTGRES_PASSWORD": password, "POSTGRES_DB": "app"}, port=5432))
        env.update({"DATABASE_URL": f"postgresql://app:{password}@postgres:5432/app", "PGHOST": "postgres", "PGUSER": "app", "PGPASSWORD": password, "PGDATABASE": "app"})
    if uses("mysql", "mysql2", "pymysql", "mysqlclient", "mysql-connector-python", "com.mysql"):
        password = synthetic("mysql-password", cache)
        services.append(Service("mysql", IMAGES["mysql"], env={"MYSQL_USER": "app", "MYSQL_PASSWORD": password, "MYSQL_DATABASE": "app", "MYSQL_RANDOM_ROOT_PASSWORD": "yes"}, port=3306))
        env.setdefault("DATABASE_URL", f"mysql://app:{password}@mysql:3306/app")
    if uses("redis", "ioredis", "redis-py", "jedis", "lettuce-core"):
        services.append(Service("redis", IMAGES["redis"], port=6379))
        env.update({"REDIS_URL": "redis://redis:6379/0", "REDIS_HOST": "redis"})
    if uses("mongodb", "mongoose", "pymongo", "motor"):
        services.append(Service("mongo", IMAGES["mongo"], port=27017))
        env.update({"MONGODB_URI": "mongodb://mongo:27017/app", "MONGO_URL": "mongodb://mongo:27017/app"})
    return services, env


def _python_start(checkout: str, port: int) -> str:
    for name, command in (("manage.py", f"python manage.py runserver 0.0.0.0:{port}"), ("app.py", "python app.py"), ("main.py", "python main.py"),
                          ("server.py", "python server.py"), ("wsgi.py", f"gunicorn -b 0.0.0.0:{port} wsgi:app")):
        if os.path.isfile(os.path.join(checkout, name)):
            return command
    raise EnvError("No Python entry point found (manage.py, app.py, main.py, server.py, wsgi.py); pass --start-command")


def generated_dockerfile(stack: str, checkout: str, port: int, start: str = "") -> str:
    """A non-root Dockerfile for a repository without one."""
    if stack == "node":
        command = json.dumps(start.split()) if start else '["npm", "start"]'
        return (f"FROM {IMAGES['node']}\nWORKDIR /app\nCOPY --chown=node:node . .\nUSER node\n"
                "RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi\n"
                f"ENV PORT={port} HOST=0.0.0.0\nEXPOSE {port}\nCMD {command}\n")
    if stack == "python":
        requirements = [name for name in ("requirements.txt", "requirements-dev.txt", "requirements-test.txt", "test-requirements.txt") if os.path.isfile(os.path.join(checkout, name))]
        install = " && ".join(f"pip install --no-cache-dir -r {name}" for name in requirements) or "pip install --no-cache-dir ."
        command = start or _python_start(checkout, port)
        return (f"FROM {IMAGES['python']}\nRUN useradd --uid 10001 --create-home app\nWORKDIR /app\nCOPY --chown=10001:10001 . .\n"
                f"RUN {install}\nUSER 10001\nENV PORT={port} HOST=0.0.0.0 PYTHONUNBUFFERED=1\nEXPOSE {port}\nCMD {json.dumps(['sh', '-c', command])}\n")
    if stack == "java":
        command = start or "java -jar $(ls target/*.jar | grep -v original | head -1)"
        return (f"FROM {IMAGES['java']}\nRUN useradd --uid 10001 --create-home app\nWORKDIR /app\nCOPY --chown=10001:10001 . .\nUSER 10001\n"
                f"RUN mvn -q -B -DskipTests package dependency:go-offline\nENV SERVER_PORT={port}\nEXPOSE {port}\nCMD {json.dumps(['sh', '-c', command])}\n")
    if stack == "go":
        command = start or "/app/server"
        return (f"FROM {IMAGES['go']}\nRUN useradd --uid 10001 --create-home app\nWORKDIR /src\nCOPY --chown=10001:10001 . .\nUSER 10001\n"
                f"ENV GOCACHE=/tmp/gocache GOPATH=/home/app/go\nRUN go mod download && go build -o /tmp/server . \nUSER root\nRUN install -m 0755 /tmp/server /app/server\nUSER 10001\n"
                f"ENV PORT={port}\nEXPOSE {port}\nCMD {json.dumps(['sh', '-c', command])}\n")
    raise EnvError(f"No Dockerfile template for {stack}")


def _stack(checkout: str) -> str:
    for name, stack in (("package.json", "node"), ("requirements.txt", "python"), ("pyproject.toml", "python"), ("Pipfile", "python"),
                        ("pom.xml", "java"), ("go.mod", "go")):
        if os.path.isfile(os.path.join(checkout, name)):
            return stack
    return ""


def default_test_command(checkout: str, stack: str) -> str:
    if stack == "node":
        scripts = {}
        try:
            scripts = json.loads(_read(os.path.join(checkout, "package.json"))).get("scripts", {}) or {}
        except ValueError:
            pass
        test = str(scripts.get("test", ""))
        return "npm test" if test and "no test specified" not in test else ""
    if stack == "python":
        if "pytest" in _dependency_text(checkout):
            return "python -m pytest -q"
        return "python -m unittest discover -s tests -v" if os.path.isdir(os.path.join(checkout, "tests")) else ""
    if stack == "java":
        return "mvn -q -B -o test"
    if stack == "go":
        return "cd /src && go test ./..."
    return ""


def _compose_file(checkout: str) -> str:
    for name in ("compose.yaml", "compose.yml", "docker-compose.yml", "docker-compose.yaml"):
        if os.path.isfile(os.path.join(checkout, name)):
            return os.path.join(checkout, name)
    return ""


def _inside(path: str, root: str) -> bool:
    path, root = os.path.realpath(path), os.path.realpath(root)
    return path == root or path.startswith(root + os.sep)


def compose_services(checkout: str, compose: str, cache: dict) -> list[Service]:
    """Services from `docker compose config` (no interpolation of the host environment), without host-level settings."""
    docker = shutil.which("docker")
    if not docker:
        raise EnvError("Docker is required")
    env = {key: os.environ[key] for key in ("PATH", "HOME", "DOCKER_HOST", "DOCKER_CONFIG", "DOCKER_CONTEXT") if key in os.environ}
    result = subprocess.run([docker, "compose", "-f", compose, "--project-directory", checkout, "config", "--format", "json", "--no-interpolate"],
                            capture_output=True, text=True, timeout=60, check=False, env=env)
    if result.returncode != 0:
        raise EnvError(f"docker compose could not read {os.path.basename(compose)}: {(result.stderr.strip().splitlines() or ['invalid file'])[-1][:200]}")
    config = json.loads(result.stdout)
    services = []
    for name, spec in (config.get("services") or {}).items():
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}", name):
            raise EnvError(f"Unsupported compose service name: {name[:40]}")
        build = spec.get("build") or {}
        if isinstance(build, str):
            build = {"context": build}
        if build:
            context = os.path.realpath(os.path.join(checkout, build.get("context", ".")))
            dockerfile = os.path.realpath(os.path.join(context, build.get("dockerfile", "Dockerfile")))
            if not (_inside(context, checkout) and _inside(dockerfile, checkout)):
                raise EnvError(f"Compose service {name} builds from outside the repository")
            build = {"context": context, "dockerfile": dockerfile, "args": {k: str(v) for k, v in (build.get("args") or {}).items()}, "target": build.get("target", "")}
        environment = spec.get("environment") or {}
        if isinstance(environment, list):
            environment = dict(item.split("=", 1) if "=" in item else (item, "") for item in environment)
        ports = [int(str(p.get("target") if isinstance(p, dict) else p).split("/")[0].split(":")[-1]) for p in spec.get("ports") or []]
        ports += [int(str(p).split("/")[0]) for p in spec.get("expose") or []]
        listify = lambda value: value if isinstance(value, list) else (value.split() if isinstance(value, str) else [])
        dropped = [key for key in ("ports", "volumes", "privileged", "cap_add", "network_mode", "pid", "ipc", "devices", "extra_hosts", "secrets", "configs", "env_file") if spec.get(key)]
        services.append(Service(name, "" if build else str(spec.get("image", "")), build, scrub_env(environment, cache), listify(spec.get("command")),
                                listify(spec.get("entrypoint")), ports[0] if ports else 0, dropped=dropped))
    if not services:
        raise EnvError(f"{os.path.basename(compose)} defines no services")
    return services


def detect(checkout: str, work: str, *, service: str = "", port: int = 0, health_path: str = "", test_command: str | None = None,
           start_command: str = "", cache: dict | None = None) -> Plan:
    """What to build and run for this checkout: compose, Dockerfile, or a generated Dockerfile for a known stack."""
    cache = {} if cache is None else cache
    checkout = os.path.realpath(checkout)
    stack, notes = _stack(checkout), []
    seeded = example_env(checkout, cache)
    if seeded:
        notes.append(f"Seeded {len(seeded)} variable(s) from the repository's example env file; sensitive values are synthetic")
    compose = _compose_file(checkout)
    if compose:
        services = compose_services(checkout, compose, cache)
        built = [item for item in services if item.build]
        app = (next((item for item in services if item.name == service), None) if service else
               next((item for item in built if item.build["context"] == checkout), None) or (built[0] if built else None) or next((item for item in services if item.port), None))
        if app is None:
            raise EnvError(f"No application service found in {os.path.basename(compose)}; pass --service")
        notes.append(f"Compose file {os.path.basename(compose)}: services {', '.join(item.name for item in services)}; application {app.name}")
        for item in services:
            if item.dropped:
                notes.append(f"Not applied for {item.name} (sandbox isolation): {', '.join(item.dropped)}")
        kind = "compose"
    else:
        dockerfile = os.path.join(checkout, "Dockerfile")
        resolved_port = port or _DEFAULT_PORTS.get(stack, 8080)
        if os.path.isfile(dockerfile):
            exposed = re.search(r"(?im)^\s*EXPOSE\s+(\d+)", _read(dockerfile))
            resolved_port = port or (int(exposed.group(1)) if exposed else resolved_port)
            build = {"context": checkout, "dockerfile": dockerfile, "args": {}, "target": ""}
            kind = f"dockerfile ({stack or 'unknown stack'})"
        elif stack:
            generated = os.path.join(work, "Dockerfile.generated")
            with open(generated, "w", encoding="utf-8") as handle:
                handle.write(generated_dockerfile(stack, checkout, resolved_port, start_command))
            build = {"context": checkout, "dockerfile": generated, "args": {}, "target": ""}
            kind = f"{stack} (generated Dockerfile)"
            notes.append(f"No Dockerfile; generated a non-root {stack} Dockerfile ({generated})")
        else:
            raise EnvError("Unsupported stack: no compose file, Dockerfile, package.json, requirements.txt/pyproject.toml, pom.xml, or go.mod")
        backing, backing_env = backing_services(checkout, cache)
        if backing:
            notes.append(f"Backing services from dependencies: {', '.join(item.name for item in backing)} (synthetic credentials)")
        app = Service("app", build=build, env={**seeded, **backing_env, "PORT": str(resolved_port)}, port=resolved_port,
                      command=["sh", "-c", start_command] if start_command and os.path.isfile(dockerfile) else [])
        services = [*backing, app]
    app.role = "app"
    if compose:
        app.env = {**seeded, **app.env}
    app.port = port or app.port or _DEFAULT_PORTS.get(stack, 8080)
    if test_command is None:
        test_command = default_test_command(checkout, stack)
    paths = [health_path] if health_path else ["/health", "/healthz", "/"]
    return Plan(kind, services, app.name, app.port, paths, test_command or "", notes)


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


def plan_dict(plan: Plan) -> dict:
    return asdict(plan)


def plan_from(data: dict) -> Plan:
    return Plan(**{**data, "services": [Service(**item) for item in data["services"]]})


def scratch_dir(prefix: str = "threatlint-dast-") -> str:
    return tempfile.mkdtemp(prefix=prefix)
