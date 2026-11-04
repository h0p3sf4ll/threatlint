"""Discover candidate HTTP endpoints to assess, from the repository checkout.

This reads source only; it never calls the application. Endpoints come from framework route declarations (Express,
Flask/FastAPI, Django, Spring, Go net/http), an optional user-supplied routes file, and always the health path and
root. The list is bounded (`MAX_ENDPOINTS`) and each endpoint is reduced to what the bounded probes need:
method, a sandbox-relative path with concrete values for path variables, and the parameter names a probe may target.
"""

from __future__ import annotations

import json
import os
import re

MAX_ENDPOINTS = 40
MAX_FILES = 4000
_SOURCE_SUFFIX = (".js", ".ts", ".mjs", ".cjs", ".py", ".java", ".kt", ".go", ".rb")
_SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", "target", "vendor", "test", "tests", "spec", "__tests__"}
_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")

# One concrete, clearly-synthetic value for a path variable, so a route template becomes a requestable path.
_VAR_VALUE = "1"
_PATH_VAR = re.compile(r"[:{<][^/>}]+[>}]?")

_PATTERNS = (
    # Express / Koa / Fastify / NestJS:  app.get('/path', ...)
    re.compile(r"""(?:app|router|server|fastify|route)\.(get|post|put|patch|delete)\s*\(\s*['"`]([^'"`]+)['"`]""", re.I),
    # Flask / FastAPI:  @app.route('/path', methods=[...])  |  @app.get('/path')
    re.compile(r"""@\w+\.(get|post|put|patch|delete|route)\s*\(\s*['"]([^'"]+)['"]""", re.I),
    # Django urls:  path('route/', ...) | re_path(r'^route/$', ...)
    re.compile(r"""\b(?:re_)?path\s*\(\s*(?:r?['"])\^?([^'"$]+)['"]""", re.I),
    # Spring:  @GetMapping("/path") | @RequestMapping("/path")
    re.compile(r"""@(Get|Post|Put|Patch|Delete|Request)Mapping\s*\(\s*(?:value\s*=\s*)?['"]([^'"]+)['"]""", re.I),
    # Go:  mux.HandleFunc("/path", ...) | r.Get("/path", ...)
    re.compile(r"""\.(?:HandleFunc|Handle|Get|Post|Put|Patch|Delete)\s*\(\s*['"]([^'"]+)['"]""", re.I),
)
_QUERY_PARAM = re.compile(r"""(?:request\.args\.get|req\.query|query_params\.get|getParameter|\.query\[|\bc\.Query)\s*[\(\[]?\s*['"]([A-Za-z_][\w-]{0,40})['"]""")


def _concrete(path: str) -> str:
    """A route template reduced to a requestable, sandbox-relative path (path variables filled with a synthetic value)."""
    path = path.split("?")[0].strip()
    if not path.startswith("/"):
        path = "/" + path
    path = _PATH_VAR.sub(_VAR_VALUE, path)
    path = re.sub(r"\(\?P?<[^>]+>[^)]*\)", _VAR_VALUE, path)   # Django named groups
    path = re.sub(r"[.^$*+?()\[\]\\]", "", path).replace("//", "/")
    return path.rstrip("/") or "/"


def _iter_source(checkout: str):
    seen = 0
    for root, dirs, files in os.walk(checkout):
        dirs[:] = [name for name in dirs if name not in _SKIP_DIRS and not name.startswith(".")]
        for name in files:
            if name.endswith(_SOURCE_SUFFIX):
                seen += 1
                if seen > MAX_FILES:
                    return
                yield os.path.join(root, name)


def _read(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            return handle.read(512 * 1024)
    except OSError:
        return ""


def from_source(checkout: str) -> list[dict]:
    """Candidate endpoints declared in the checkout's route definitions, de-duplicated by (method, path)."""
    found: dict[tuple[str, str], dict] = {}
    for file in _iter_source(checkout):
        text = _read(file)
        if not text:
            continue
        params = sorted(set(_QUERY_PARAM.findall(text)))[:8]
        for pattern in _PATTERNS:
            for match in pattern.finditer(text):
                groups = match.groups()
                verb, raw = (groups[0], groups[1]) if len(groups) == 2 else ("GET", groups[0])
                method = verb.upper() if verb.upper() in _METHODS else "GET"
                path = _concrete(raw)
                if not path or len(path) > 200 or re.search(r"[^\x20-\x7e]", path):
                    continue
                key = (method, path)
                if key not in found:
                    found[key] = {"method": method, "path": path, "params": params if method in ("GET", "POST") else [],
                                  "source": os.path.relpath(file, checkout)}
    return list(found.values())


def from_routes_file(path: str) -> list[dict]:
    """A user-supplied routes file: JSON list of {method, path, params} or a text file of `METHOD /path` lines."""
    raw = _read(path)
    if not raw.strip():
        return []
    endpoints = []
    try:
        data = json.loads(raw)
        for item in data if isinstance(data, list) else []:
            if isinstance(item, dict) and item.get("path"):
                endpoints.append({"method": str(item.get("method", "GET")).upper(), "path": _concrete(str(item["path"])),
                                  "params": [str(name) for name in (item.get("params") or [])][:8], "source": "routes file"})
        return endpoints
    except ValueError:
        pass
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0].upper() in _METHODS:
            endpoints.append({"method": parts[0].upper(), "path": _concrete(parts[1]), "params": [], "source": "routes file"})
        elif len(parts) == 1 and parts[0].startswith("/"):
            endpoints.append({"method": "GET", "path": _concrete(parts[0]), "params": [], "source": "routes file"})
    return endpoints


def discover(checkout: str, plan, routes_file: str = "") -> list[dict]:
    """The bounded endpoint set to assess: health paths and root, plus routes from source and any routes file."""
    endpoints: dict[tuple[str, str], dict] = {}
    for path in [*(plan.health_paths or []), "/"]:
        endpoints.setdefault(("GET", path), {"method": "GET", "path": path, "params": [], "source": "health/root"})
    for endpoint in (from_routes_file(routes_file) if routes_file else []) + from_source(checkout):
        endpoints.setdefault((endpoint["method"], endpoint["path"]), endpoint)
    return list(endpoints.values())[:MAX_ENDPOINTS]
