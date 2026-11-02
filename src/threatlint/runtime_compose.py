"""Translate decoded Compose services into host-isolated sandbox plans."""

from __future__ import annotations

import os
import re

from threatlint.runtime_config import scrub_env
from threatlint.runtime_models import EnvError, Service


def _inside(path: str, root: str) -> bool:
    path, root = os.path.realpath(path), os.path.realpath(root)
    return path == root or path.startswith(root + os.sep)


def parse_services(config: dict, checkout: str, compose: str, cache: dict) -> list[Service]:
    """Keep only supported settings and reject build paths outside the checkout."""
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
