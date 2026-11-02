"""Discover checkout stacks and produce sandbox build/deployment plans.

This module inspects repository files and Compose configuration; it never
builds images or starts containers. Docker execution belongs to runtime_env.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess

from threatlint.runtime_config import _read, example_env, synthetic
from threatlint.runtime_compose import parse_services
from threatlint.runtime_models import EnvError, Plan, Service

_DEFAULT_PORTS = {"node": 3000, "python": 8000, "java": 8080, "go": 8080}
IMAGES = {"node": os.environ.get("THREATLINT_DAST_NODE_IMAGE", "node:20-slim"),
          "python": os.environ.get("THREATLINT_DAST_PYTHON_IMAGE", "python:3.12-slim"),
          "java": os.environ.get("THREATLINT_DAST_MAVEN_IMAGE", "maven:3.9-eclipse-temurin-21"),
          "go": os.environ.get("THREATLINT_DAST_GO_IMAGE", "golang:1.22"),
          "postgres": os.environ.get("THREATLINT_DAST_POSTGRES_IMAGE", "postgres:17"),
          "mysql": os.environ.get("THREATLINT_DAST_MYSQL_IMAGE", "mysql:8.4"),
          "redis": os.environ.get("THREATLINT_DAST_REDIS_IMAGE", "redis:7-alpine"),
          "mongo": os.environ.get("THREATLINT_DAST_MONGO_IMAGE", "mongo:7")}


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


def compose_services(checkout: str, compose: str, cache: dict) -> list[Service]:
    """Services from `docker compose config` (no interpolation of the host environment), without host-level settings."""
    docker = shutil.which("docker")
    if not docker:
        raise EnvError("Docker is required")
    env = {key: os.environ[key] for key in ("PATH", "HOME", "DOCKER_HOST", "DOCKER_CONFIG", "DOCKER_CONTEXT") if key in os.environ}
    # Repository paths are separate arguments, never interpreted by a shell.
    result = subprocess.run([docker, "compose", "-f", compose, "--project-directory", checkout, "config", "--format", "json", "--no-interpolate"],  # nosec B603
                            capture_output=True, text=True, timeout=60, check=False, env=env, shell=False)
    if result.returncode != 0:
        raise EnvError(f"docker compose could not read {os.path.basename(compose)}: {(result.stderr.strip().splitlines() or ['invalid file'])[-1][:200]}")
    return parse_services(json.loads(result.stdout), checkout, compose, cache)


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
