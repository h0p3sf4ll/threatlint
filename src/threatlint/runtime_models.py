"""Provider-independent runtime sandbox plans, limits and serialization."""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass, field

from threatlint.avit_resolve import ResolveError


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
    """Sandbox service with optional absolute build paths and omitted host settings in ``dropped``."""

    name: str
    image: str = ""
    build: dict = field(default_factory=dict)
    env: dict = field(default_factory=dict)
    command: list = field(default_factory=list)
    entrypoint: list = field(default_factory=list)
    port: int = 0
    role: str = "backing"
    dropped: list = field(default_factory=list)


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


def plan_dict(plan: Plan) -> dict:
    return asdict(plan)


def plan_from(data: dict) -> Plan:
    return Plan(**{**data, "services": [Service(**item) for item in data["services"]]})
