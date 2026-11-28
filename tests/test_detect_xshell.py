import importlib.util
import io
import json
import sys
import urllib.error
from email.message import Message
from pathlib import Path

import pytest

from threatlint.detect_xshell import advisories, fleet, lockfiles, scanner
from threatlint.detect_xshell.cli import cmd_detect_xshell
from threatlint.detect_xshell.report import document, markdown, target_result
from threatlint.detect_xshell.semver import parse, range_floor

ROOT = Path(__file__).resolve().parents[1]
W = advisories.WATCHED_PACKAGES


def adv(key):
    return next(a for a in advisories.ADVISORIES if a.key == key)


# ─── versions ────────────────────────────────────────────────────────────────

def test_semver_orders_prereleases_before_releases():
    assert parse("15.6.0-canary.57") < parse("15.6.0-canary.58") < parse("15.6.0")
    assert parse("15.0.0-0") < parse("15.0.0-canary.1") < parse("15.0.0-rc.1") < parse("15.0.0")
    assert parse("^19.0.0") is None and parse("latest") is None


def test_range_floor_handles_common_npm_specs():
    assert str(range_floor("^19.1.0")) == "19.1.0"
    assert str(range_floor(">=15.0.0 <16")) == "15.0.0"
    assert str(range_floor("npm:next@15.1.0")) == "15.1.0"
    assert range_floor("workspace:*") is None and range_floor("latest") is None


@pytest.mark.parametrize("version,affected", [
    ("19.0.0", True), ("19.0.1", False), ("19.1.1", True), ("19.1.2", False), ("19.2.0", True), ("19.2.1", False),
    ("18.3.1", False), ("19.0.0-rc-66855b96-20241106", False),
])
def test_react2shell_versions(version, affected):
    assert bool(scanner.matching_line(adv("react2shell-rce"), parse(version))) is affected


@pytest.mark.parametrize("version,affected", [
    ("14.2.20", False), ("14.3.0-canary.76", False), ("14.3.0-canary.77", True), ("15.0.4", True), ("15.0.5", False),
    ("15.1.8", True), ("15.1.9", False), ("15.5.6", True), ("15.5.7", False), ("15.6.0-canary.57", True),
    ("15.6.0-canary.58", False), ("16.0.6", True), ("16.0.7", False), ("16.1.0-canary.11", True),
    ("16.1.0-canary.12", False), ("16.1.0", False), ("13.5.6", False),
])
def test_next_rce_versions(version, affected):
    assert bool(scanner.matching_line(adv("next-react2shell"), parse(version))) is affected


@pytest.mark.parametrize("version,affected", [
    ("14.2.34", True), ("14.2.35", False), ("15.4.10", True), ("15.4.11", False), ("16.1.0-canary.18", True),
    ("16.1.0-canary.19", False), ("16.1.4", True), ("16.1.5", False), ("13.2.0", False),
])
def test_next_followup_versions(version, affected):
    assert bool(scanner.matching_line(adv("next-rsc-followups"), parse(version))) is affected


def test_every_advisory_cites_a_vendor_source_and_parses():
    for item in advisories.ADVISORIES:
        assert item.sources and all(s.startswith("https://") for s in item.sources)
        assert item.severity in scanner.SEVERITY_RANK
        for line in item.lines:
            assert parse(line.introduced) and (line.fixed is None or parse(line.fixed))


# ─── lockfiles ───────────────────────────────────────────────────────────────

NPM_V3 = json.dumps({"lockfileVersion": 3, "packages": {
    "": {"dependencies": {"next": "15.1.0"}},
    "node_modules/next": {"version": "15.1.0"},
    "node_modules/react": {"version": "19.0.0"},
    "node_modules/foo/node_modules/react-server-dom-webpack": {"version": "19.1.0"},
    "node_modules/my-next": {"name": "next", "version": "15.1.0"},
}}, indent=2)


def test_npm_lock_v3_reads_nested_and_aliased_packages():
    found = lockfiles.parse_npm_lock(NPM_V3, "package-lock.json", W)
    pairs = {(r.package, r.version) for r in found}
    assert ("next", "15.1.0") in pairs and ("react-server-dom-webpack", "19.1.0") in pairs
    assert all(r.line > 1 for r in found)


def test_npm_lock_v1():
    text = json.dumps({"lockfileVersion": 1, "dependencies": {"next": {"version": "15.0.3", "dependencies": {
        "react-server-dom-webpack": {"version": "19.0.0"}}}}}, indent=2)
    pairs = {(r.package, r.version) for r in lockfiles.parse_npm_lock(text, "package-lock.json", W)}
    assert pairs == {("next", "15.0.3"), ("react-server-dom-webpack", "19.0.0")}


def test_yarn_classic_and_berry():
    classic = 'next@^15.0.0, next@15.1.0:\n  version "15.1.0"\n  resolved "x"\n\n"@vitejs/plugin-rsc@^0.4.0":\n  version "0.4.1"\n'
    berry = '"next@npm:16.0.3":\n  version: 16.0.3\n  resolution: "next@npm:16.0.3"\n'
    assert {(r.package, r.version, r.line) for r in lockfiles.parse_yarn_lock(classic, "yarn.lock", W)} == {
        ("next", "15.1.0", 1), ("@vitejs/plugin-rsc", "0.4.1", 5)}
    assert [(r.package, r.version) for r in lockfiles.parse_yarn_lock(berry, "yarn.lock", W)] == [("next", "16.0.3")]


def test_pnpm_v6_v9_and_v5_keys():
    text = ("lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      next:\n        version: 15.2.0\n"
            "packages:\n  next@15.2.0:\n    resolution: {}\n  '@parcel/rsc@2.0.0':\n    resolution: {}\n"
            "  /react-server-dom-webpack@19.2.0(react@19.2.0):\n    resolution: {}\n  /next/14.2.3:\n    x: 1\n"
            "snapshots:\n  next@15.2.0(react@19.0.0):\n    dependencies: {}\n")
    pairs = {(r.package, r.version) for r in lockfiles.parse_pnpm_lock(text, "pnpm-lock.yaml", W)}
    assert pairs == {("next", "15.2.0"), ("@parcel/rsc", "2.0.0"), ("react-server-dom-webpack", "19.2.0"), ("next", "14.2.3")}


def test_bun_lock():
    text = '{\n  "packages": {\n    "next": ["next@16.0.1", "", {}],\n    "waku": ["waku@0.21.0", "", {}],\n  }\n}\n'
    assert {(r.package, r.version) for r in lockfiles.parse_bun_lock(text, "bun.lock", W)} == {("next", "16.0.1"), ("waku", "0.21.0")}


# ─── single repository scans ─────────────────────────────────────────────────

def write(root: Path, files: dict):
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content if isinstance(content, str) else json.dumps(content, indent=2), encoding="utf-8")


def test_app_router_next_is_confirmed_critical(tmp_path):
    write(tmp_path, {"package.json": {"dependencies": {"next": "15.1.0"}}, "package-lock.json": NPM_V3,
                     "src/app/page.tsx": "export default function P(){}",
                     "node_modules/next/package.json": {"name": "next", "version": "15.1.0"}})
    result = scanner.scan_path(str(tmp_path))
    nxt = next(f for f in result.findings if f["package"] == "next")
    assert (nxt["severity"], nxt["confidence"]) == ("CRITICAL", "CONFIRMED")
    assert "CVE-2025-66478" in nxt["cves"] and "CVE-2025-55184" in nxt["cves"]
    assert nxt["fixedIn"] == "15.1.12"  # the follow-up fix supersedes the RCE fix on the same line
    assert "src/app/page.tsx" in nxt["exposure"]
    assert result.status == "vulnerable"
    assert result.findings[0]["id"] == "TS-001"
    assert not any("node_modules" in f["file"] for f in result.findings)


def test_pages_router_next_is_theoretical(tmp_path):
    write(tmp_path, {"package.json": {"dependencies": {"next": "15.1.0"}},
                     "yarn.lock": 'next@15.1.0:\n  version "15.1.0"\n', "pages/index.js": ""})
    finding = scanner.scan_path(str(tmp_path)).findings[0]
    assert finding["confidence"] == "THEORETICAL" and "Pages Router" in finding["exposure"]


def test_manifest_without_lockfile_is_plausible(tmp_path):
    write(tmp_path, {"apps/web/package.json": {"dependencies": {"react-server-dom-webpack": "^19.0.0", "waku": "0.21.0"}}})
    result = scanner.scan_path(str(tmp_path))
    assert [(f["package"], f["confidence"]) for f in result.findings] == [("react-server-dom-webpack", "PLAUSIBLE")]
    assert "waku" in result.findings[0]["exposure"]


def test_patched_versions_are_clean_and_no_stack_is_not_applicable(tmp_path):
    write(tmp_path / "a", {"package.json": {"dependencies": {"next": "16.4.1"}},
                           "pnpm-lock.yaml": "packages:\n  next@16.4.1:\n    x: 1\n", "app/layout.tsx": ""})
    write(tmp_path / "b", {"package.json": {"dependencies": {"express": "4.0.0"}}})
    assert scanner.scan_path(str(tmp_path / "a")).status == "clean"
    assert scanner.scan_path(str(tmp_path / "b")).status == "not-applicable"


def test_malformed_lockfile_is_reported_not_fatal(tmp_path):
    write(tmp_path, {"package-lock.json": "{not json", "package.json": {"dependencies": {"next": "15.0.0"}}})
    result = scanner.scan_path(str(tmp_path))
    assert any("Could not parse package-lock.json" in note for note in result.coverage)


# ─── report contract with the CI gate and SARIF converter ────────────────────

def load_script(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / ".github" / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_markdown_report_is_gateable(tmp_path):
    write(tmp_path, {"package.json": {"dependencies": {"next": "15.1.0"}}, "package-lock.json": NPM_V3, "app/page.js": ""})
    doc = document([target_result(scanner.scan_path(str(tmp_path)), repository="web")], scope="web")
    text = markdown(doc)
    assert "## TIER 1 — EXECUTIVE SUMMARY" in text and "**CRITICAL**" in text
    parsed = load_script("gate_report").parse_findings(text)
    assert parsed and parsed[0].id == "TS-001" and parsed[0].severity == "CRITICAL" and parsed[0].confidence == "CONFIRMED"


def test_cli_scan_json_and_fail_on(tmp_path, capsys):
    write(tmp_path, {"package.json": {"dependencies": {"next": "15.1.0"}}, "package-lock.json": NPM_V3, "app/page.js": ""})

    class Args:
        action, path, format, output, fail_on = "scan", str(tmp_path), "json", None, "CRITICAL"
    assert cmd_detect_xshell(Args()) == 3
    doc = json.loads(capsys.readouterr().out)
    assert doc["schema"] == "threatlint.detect-xshell/v1" and doc["summary"]["critical"] >= 1


def test_cli_is_registered():
    from threatlint.cli import build_parser
    args = build_parser().parse_args(["detect-2shell", "fleet", "--all", "--branches", "main,release/*"])
    assert args.action == "fleet" and args.all and args.integration_handler is cmd_detect_xshell


# ─── fleet ───────────────────────────────────────────────────────────────────

class FakeResponse(io.BytesIO):
    def __init__(self, body, headers=None, status=200):
        super().__init__(body if isinstance(body, bytes) else json.dumps(body).encode())
        self.headers, self.status = Message(), status
        for key, value in (headers or {}).items():
            self.headers[key] = value

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeOpener:
    def __init__(self, routes):
        self.routes, self.requests = routes, []

    def open(self, request, timeout=None):
        self.requests.append(request)
        url = request.full_url
        # Longest prefix wins, so a page-2 URL never falls back to the page-1 route.
        for prefix, response in sorted(self.routes.items(), key=lambda item: -len(item[0])):
            if url.startswith(prefix):
                value = response(request) if callable(response) else response
                if isinstance(value, int):
                    raise urllib.error.HTTPError(url, value, "err", Message(), None)
                return value
        raise urllib.error.HTTPError(url, 404, "missing", Message(), None)


GH = "https://api.github.com"
LOCK = json.dumps({"lockfileVersion": 3, "packages": {"node_modules/next": {"version": "16.0.3"}}}, indent=2)


def github_routes():
    return {
        f"{GH}/installation/repositories?per_page=100": lambda r: FakeResponse(
            {"repositories": [{"full_name": "acme/web", "owner": {"login": "acme"}, "default_branch": "main"}]},
            {"Link": f'<{GH}/installation/repositories?per_page=100&page=2>; rel="next"'}),
        f"{GH}/installation/repositories?per_page=100&page=2": lambda r: FakeResponse(
            {"repositories": [{"full_name": "acme/api", "owner": {"login": "acme"}, "default_branch": "main"},
                              {"full_name": "acme/old", "owner": {"login": "acme"}, "archived": True}]}),
        f"{GH}/repos/acme/web/branches": lambda r: FakeResponse([{"name": "main", "commit": {"sha": "a" * 40}},
                                                                  {"name": "release/1", "commit": {"sha": "b" * 40}},
                                                                  {"name": "feature/x", "commit": {"sha": "c" * 40}}]),
        f"{GH}/repos/acme/web/commits/main": lambda r: FakeResponse(b"a" * 40),
        f"{GH}/repos/acme/web/git/trees/": lambda r: FakeResponse({"tree": [
            {"path": "package.json", "type": "blob", "size": 40}, {"path": "package-lock.json", "type": "blob", "size": 99},
            {"path": "app/page.tsx", "type": "blob", "size": 5}, {"path": "src/index.ts", "type": "blob", "size": 5}]}),
        f"{GH}/repos/acme/web/contents/package-lock.json": lambda r: FakeResponse(LOCK.encode()),
        f"{GH}/repos/acme/web/contents/package.json": lambda r: FakeResponse(b'{"dependencies":{"next":"16.0.3"}}'),
        f"{GH}/repos/acme/api/commits/main": lambda r: FakeResponse(b"d" * 40),
        f"{GH}/repos/acme/api/git/trees/": lambda r: FakeResponse({"tree": [{"path": "go.mod", "type": "blob", "size": 9}]}),
    }


def gh_env(token="ghs_test"):
    return {fleet.CREDENTIALS_ENV: json.dumps({"connections": [{"id": "gh1", "provider": "github", "token": token}]})}


def test_fleet_scans_all_repositories_default_branch_without_cloning():
    opener = FakeOpener(github_routes())
    connection = fleet.load_connections(gh_env())[0]
    events = []
    doc = fleet.run_fleet({"connections": [{"connection": "gh1"}]}, progress=events.append, environ=gh_env(),
                          clients={"gh1": fleet.client(connection, opener, sleep=lambda s: None)})
    by_repo = {r["repository"]: r for r in doc["results"]}
    assert set(by_repo) == {"acme/web", "acme/api"}  # archived repository skipped, pagination followed
    assert by_repo["acme/web"]["status"] == "vulnerable" and by_repo["acme/web"]["commit"] == "a" * 40
    assert by_repo["acme/api"]["status"] == "not-applicable"
    assert events[0] == {"event": "plan", "total": 2} and events[-1] == {"event": "done"}
    fetched = [r.full_url for r in opener.requests if "/contents/" in r.full_url]
    assert all(("package" in u) for u in fetched) and not any("index.ts" in u or "page.tsx" in u for u in fetched)
    assert all(r.get_header("Authorization") == "Bearer ghs_test" for r in opener.requests)
    assert "ghs_test" not in json.dumps(doc) and "ghs_test" not in json.dumps(events)


def test_fleet_subset_and_branch_patterns():
    opener = FakeOpener(github_routes())
    connection = fleet.load_connections(gh_env())[0]
    doc = fleet.run_fleet({"connections": [{"connection": "github", "repositories": ["acme/web"],
                                            "branches": ["main", "release/*"]}]}, environ=gh_env(),
                          clients={"gh1": fleet.client(connection, opener, sleep=lambda s: None)})
    assert [(r["repository"], r["branch"]) for r in doc["results"]] == [("acme/web", "main"), ("acme/web", "release/1")]


def test_fleet_falls_back_to_user_repos_for_personal_tokens():
    routes = github_routes()
    routes[f"{GH}/installation/repositories"] = 403
    routes[f"{GH}/user/repos"] = lambda r: FakeResponse([{"full_name": "me/site", "owner": {"login": "me"}, "default_branch": "main"}])
    del routes[f"{GH}/installation/repositories?per_page=100"]
    del routes[f"{GH}/installation/repositories?per_page=100&page=2"]
    api = fleet.client(fleet.load_connections(gh_env())[0], FakeOpener(routes), sleep=lambda s: None)
    assert [r.name for r in api.repositories()] == ["me/site"]


def test_fleet_errors_are_per_target():
    routes = github_routes()
    routes[f"{GH}/repos/acme/web/git/trees/"] = 404
    connection = fleet.load_connections(gh_env())[0]
    doc = fleet.run_fleet({}, environ=gh_env(),
                          clients={"gh1": fleet.client(connection, FakeOpener(routes), sleep=lambda s: None)})
    web = next(r for r in doc["results"] if r["repository"] == "acme/web")
    assert web["status"] == "error" and "404" in web["error"] and doc["summary"]["errors"] == 1


def test_http_refuses_cross_host_and_retries_rate_limits():
    calls = []

    def limited(request):
        calls.append(1)
        return 429 if len(calls) < 3 else FakeResponse({"ok": True})
    http = fleet.Http(GH, {}, FakeOpener({f"{GH}/x": limited}), sleep=lambda s: None)
    assert http.get("/x")[0] == {"ok": True} and len(calls) == 3
    with pytest.raises(fleet.FleetError, match="different host"):
        http.get("https://evil.example/x")


def test_azure_devops_listing_branches_and_content():
    base = "https://dev.azure.com/contoso"
    tree = {"value": [{"path": "/web/package.json", "gitObjectType": "blob"},
                      {"path": "/web/pnpm-lock.yaml", "gitObjectType": "blob"},
                      {"path": "/web/app/page.tsx", "gitObjectType": "blob"}]}
    routes = {
        f"{base}/_apis/git/repositories?": FakeResponse({"value": [
            {"id": "r1", "name": "storefront", "project": {"name": "Retail"}, "defaultBranch": "refs/heads/main"}]}),
        f"{base}/Retail/_apis/git/repositories/r1/refs?filter=heads/main": FakeResponse(
            {"value": [{"name": "refs/heads/main", "objectId": "e" * 40}]}),
        f"{base}/Retail/_apis/git/repositories/r1/items?recursionLevel=Full": FakeResponse(tree),
        f"{base}/Retail/_apis/git/repositories/r1/items?path=/web/pnpm-lock.yaml": FakeResponse(
            b"packages:\n  react-server-dom-webpack@19.2.0:\n    x: 1\n  next@15.5.6:\n    x: 1\n"),
        f"{base}/Retail/_apis/git/repositories/r1/items?path=/web/package.json": FakeResponse(b'{"dependencies":{}}'),
    }
    env = {fleet.CREDENTIALS_ENV: json.dumps({"connections": [
        {"id": "ado", "provider": "azure-devops", "token": "pat", "organization": "contoso"}]})}
    opener = FakeOpener(routes)
    doc = fleet.run_fleet({}, environ=env,
                          clients={"ado": fleet.client(fleet.load_connections(env)[0], opener, sleep=lambda s: None)})
    result = doc["results"][0]
    assert result["repository"] == "Retail/storefront" and result["status"] == "vulnerable"
    assert {f["package"] for f in result["findings"]} == {"react-server-dom-webpack", "next"}
    assert all(r.get_header("Authorization").startswith("Basic ") for r in opener.requests)


@pytest.mark.parametrize("data", [
    {"connections": [{"repositories": "some"}]},
    {"connections": [{"branches": ["ok", "../etc"]}]},
    {"maxRepositories": 0},
    {"connections": "all"},
])
def test_invalid_targets_rejected(data):
    with pytest.raises(fleet.FleetError):
        fleet.load_targets(data)


def test_invalid_credentials_rejected():
    with pytest.raises(fleet.FleetError):
        fleet.load_connections({fleet.CREDENTIALS_ENV: json.dumps({"connections": [{"provider": "gitlab", "token": "x"}]})})
    with pytest.raises(fleet.FleetError):
        fleet.load_connections({fleet.CREDENTIALS_ENV: json.dumps({"connections": [
            {"provider": "github", "token": "x", "apiBase": "http://insecure.example"}]})})


# ─── *-4Shell (Java) ─────────────────────────────────────────────────────────

def test_maven_style_versions_parse_and_order():
    assert parse("2.0-beta9") < parse("2.0-rc1") < parse("2.0") < parse("2.0.1")
    assert str(parse("5.2.19.RELEASE")) == "5.2.19.RELEASE" and parse("5.2.19.RELEASE") < parse("5.2.20")
    assert parse("1.9") < parse("1.10.0")
    assert parse("${log4j.version}") is None


@pytest.mark.parametrize("key,version,affected", [
    ("log4shell-rce", "2.0-beta8", False), ("log4shell-rce", "2.0-beta9", True), ("log4shell-rce", "2.3", True),
    ("log4shell-rce", "2.3.1", False), ("log4shell-rce", "2.12.1", True), ("log4shell-rce", "2.12.2", False),
    ("log4shell-rce", "2.14.1", True), ("log4shell-rce", "2.15.0", False),
    ("log4j-context-lookup-rce", "2.15.0", True), ("log4j-context-lookup-rce", "2.16.0", False),
    ("log4j-followups", "2.16.0", True), ("log4j-followups", "2.17.0", False), ("log4j-followups", "2.12.3", False),
    ("spring4shell-rce", "5.3.17", True), ("spring4shell-rce", "5.3.18", False), ("spring4shell-rce", "5.2.19.RELEASE", True),
    ("spring4shell-rce", "5.2.20.RELEASE", False), ("spring4shell-rce", "4.3.30.RELEASE", True),
    ("spring-boot-spring4shell", "2.6.5", True), ("spring-boot-spring4shell", "2.6.6", False),
    ("spring-boot-spring4shell", "2.5.11", True), ("spring-boot-spring4shell", "2.5.12", False),
    ("text4shell-rce", "1.4", False), ("text4shell-rce", "1.5", True), ("text4shell-rce", "1.9", True),
    ("text4shell-rce", "1.10.0", False),
])
def test_4shell_versions(key, version, affected):
    assert bool(scanner.matching_line(adv(key), parse(version))) is affected


def test_every_advisory_has_a_family():
    assert {a.family for a in advisories.ADVISORIES} == {"2Shell", "4Shell"}


POM = """<project>
  <!-- <dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>2.0</version></dependency> -->
  <parent><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-parent</artifactId><version>2.6.3</version></parent>
  <packaging>war</packaging>
  <properties><log4j2.version>2.14.1</log4j2.version><text.version>[1.8,2.0)</text.version></properties>
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>${log4j2.version}</version>
    </dependency>
    <dependency><groupId>org.springframework</groupId><artifactId>spring-webmvc</artifactId><version>5.3.15</version></dependency>
    <dependency><groupId>org.apache.commons</groupId><artifactId>commons-text</artifactId><version>${text.version}</version></dependency>
    <dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-api</artifactId><version>2.14.1</version></dependency>
  </dependencies>
</project>
"""


def test_maven_pom_findings_and_exposure(tmp_path):
    write(tmp_path, {"pom.xml": POM})
    result = scanner.scan_path(str(tmp_path))
    by_pkg = {f["package"]: f for f in result.findings}
    log4j = by_pkg[advisories.LOG4J_CORE]
    assert (log4j["severity"], log4j["confidence"], log4j["family"]) == ("CRITICAL", "CONFIRMED", "4Shell")
    assert log4j["version"] == "2.14.1" and log4j["fixedIn"] == "2.17.0" and log4j["line"] == 7
    assert {"CVE-2021-44228", "CVE-2021-45046", "CVE-2021-45105"} <= set(log4j["cves"])
    spring = by_pkg["org.springframework:spring-webmvc"]
    assert spring["confidence"] == "CONFIRMED" and "WAR packaging found" in spring["exposure"]
    assert by_pkg[advisories.SPRING_BOOT]["confidence"] == "PLAUSIBLE"
    text = by_pkg[advisories.COMMONS_TEXT]
    assert text["confidence"] == "PLAUSIBLE" and "StringSubstitutor" in text["exposure"]
    assert "org.apache.logging.log4j:log4j-api" not in by_pkg  # log4j-api alone is not affected
    assert all(f["version"] != "2.0" for f in result.findings)  # commented-out dependency ignored


def test_spring_without_war_is_softened(tmp_path):
    write(tmp_path, {"pom.xml": "<project><dependencies><dependency><groupId>org.springframework</groupId>"
                                "<artifactId>spring-beans</artifactId><version>5.3.10</version></dependency>"
                                "</dependencies></project>"})
    finding = scanner.scan_path(str(tmp_path)).findings[0]
    assert finding["confidence"] == "PLAUSIBLE" and "executable jars are not vulnerable" in finding["exposure"]


def test_gradle_build_catalog_lockfile_and_jars(tmp_path):
    write(tmp_path, {
        "app/build.gradle": "plugins {\n  id 'war'\n  id 'org.springframework.boot' version '2.5.10'\n}\n"
                            "ext.log4jVersion = '2.13.3'\ndependencies {\n"
                            "  implementation \"org.apache.logging.log4j:log4j-core:$log4jVersion\"\n"
                            "  implementation group: 'org.apache.commons', name: 'commons-text', version: '1.9'\n}\n",
        "svc/build.gradle.kts": "dependencies { implementation(\"org.apache.logging.log4j:log4j-core:2.11.0\") }\n",
        "svc/gradle.lockfile": "org.apache.logging.log4j:log4j-core:2.17.1=compileClasspath,runtimeClasspath\nempty=\n",
        "gradle/libs.versions.toml": "[versions]\nlog4j = \"2.14.0\"\n[libraries]\n"
                                     "log4j-core = { module = \"org.apache.logging.log4j:log4j-core\", version.ref = \"log4j\" }\n",
        "legacy/lib/log4j-core-2.8.2.jar": "binary",
        "legacy/lib/log4j-core-2.8.2-sources.jar": "binary",
        "legacy/lib/spring-beans-5.3.17.jar": "binary",
    })
    result = scanner.scan_path(str(tmp_path))
    found = {(f["file"], f["package"], f["version"], f["confidence"]) for f in result.findings}
    assert ("app/build.gradle", advisories.LOG4J_CORE, "2.13.3", "PLAUSIBLE") in found
    assert ("app/build.gradle", advisories.COMMONS_TEXT, "1.9", "PLAUSIBLE") in found
    assert ("app/build.gradle", advisories.SPRING_BOOT, "2.5.10", "PLAUSIBLE") in found
    assert ("gradle/libs.versions.toml", advisories.LOG4J_CORE, "2.14.0", "PLAUSIBLE") in found
    assert ("legacy/lib/log4j-core-2.8.2.jar", advisories.LOG4J_CORE, "2.8.2", "CONFIRMED") in found
    assert ("legacy/lib/spring-beans-5.3.17.jar", "org.springframework:spring-beans", "5.3.17", "PLAUSIBLE") in found
    # svc/: the lockfile pins a patched log4j, so the older declaration in the build file is not reported.
    assert not any(f["file"].startswith("svc/") for f in result.findings)
    assert not any("sources" in f["file"] for f in result.findings)


def test_report_names_both_families(tmp_path):
    write(tmp_path, {"pom.xml": POM, "package.json": {"dependencies": {"next": "15.1.0"}},
                     "package-lock.json": NPM_V3, "app/page.js": ""})
    doc = document([target_result(scanner.scan_path(str(tmp_path)), repository="mixed")], scope="mixed")
    assert doc["summary"]["families"]["2Shell"] >= 1 and doc["summary"]["families"]["4Shell"] >= 3
    text = markdown(doc)
    assert "# *-Shell Exposure Scan (*-2Shell / *-4Shell)" in text and "| Fix available |" in text and "CVE-2021-44228" in text and "CVE-2022-22965" in text
    ids = [f.id for f in load_script("gate_report").parse_findings(text)]
    assert ids and len(ids) == len(set(ids))


def test_detect_4shell_alias_and_lowercase_fail_on():
    from threatlint.cli import build_parser
    args = build_parser().parse_args(["detect-4shell", "scan", "--path", ".", "--fail-on", "critical"])
    assert args.integration_handler is cmd_detect_xshell and args.fail_on == "CRITICAL"


def test_fleet_downloads_java_manifests_but_not_jars():
    routes = github_routes()
    routes[f"{GH}/repos/acme/web/git/trees/"] = lambda r: FakeResponse({"tree": [
        {"path": "pom.xml", "type": "blob", "size": 900}, {"path": "lib/log4j-core-2.14.1.jar", "type": "blob", "size": 9},
        {"path": "src/Main.java", "type": "blob", "size": 9}]})
    routes[f"{GH}/repos/acme/web/contents/pom.xml"] = lambda r: FakeResponse(POM.encode())
    opener = FakeOpener(routes)
    connection = fleet.load_connections(gh_env())[0]
    doc = fleet.run_fleet({"connections": [{"connection": "gh1", "repositories": ["acme/web"]}]}, environ=gh_env(),
                          clients={"gh1": fleet.client(connection, opener, sleep=lambda s: None)})
    [web] = doc["results"]
    assert web["status"] == "vulnerable" and {f["family"] for f in web["findings"]} == {"4Shell"}
    assert any(f["file"].endswith(".jar") for f in web["findings"])
    fetched = [r.full_url for r in opener.requests if "/contents/" in r.full_url]
    assert fetched == [f"{GH}/repos/acme/web/contents/pom.xml?ref={'a' * 40}"]


# ─── 2026 CVEs, runtime evidence, impacted lines with no fix ─────────────────

from threatlint.detect_xshell import runtimes  # noqa: E402


@pytest.mark.parametrize("key,version,affected", [
    ("php2shell-rce", "8.3.35", True), ("php2shell-rce", "8.3.36", False), ("php2shell-rce", "8.5.11", True),
    ("php2shell-rce", "8.5.12", False), ("php2shell-rce", "8.1.30", True), ("php2shell-rce", "7.3.33", False),
    ("wp2shell-rce", "6.9.4", True), ("wp2shell-rce", "6.9.5", False), ("wp2shell-rce", "7.0.1", True),
    ("wp2shell-rce", "7.1-beta1", True), ("wp2shell-rce", "7.1-beta2", False), ("wp2shell-rce", "6.8.5", False),
    ("wordpress-wp-query-sqli", "6.8.5", True), ("wordpress-wp-query-sqli", "6.8.6", False),
    ("node2shell-brotli", "22.23.3", True), ("node2shell-brotli", "22.23.4", False), ("node2shell-brotli", "20.18.0", True),
    ("node2shell-brotli", "25.1.0", True), ("node2shell-brotli", "26.12.1", False), ("node2shell-brotli", "10.24.1", False),
    ("node2shell-brotli-python", "1.0.9", True), ("node2shell-brotli-python", "1.0.10", False),
    ("node2shell-brotli-python", "1.1.0", True), ("node2shell-brotli-python", "1.2.1", False),
    ("node2shell-brotli-python", "1.0.2", False),
    ("react-rsc-typed-array-rce", "19.2.8", True), ("react-rsc-typed-array-rce", "19.2.9", False),
    ("react-rsc-typed-array-rce", "19.3.0", True), ("next-rsc-typed-array-rce", "16.4.0", True),
    ("next-rsc-typed-array-rce", "16.4.1", False), ("next-rsc-typed-array-rce", "15.5.9", False),
    ("java4shell-base64", "17.0.5", False), ("java4shell-base64", "17.0.21", True), ("java4shell-base64", "17.0.21.1", False),
    ("java4shell-base64", "21.0.13", True), ("java4shell-base64", "21.0.13.1", False), ("java4shell-base64", "23.0.2", True),
    ("java4shell-base64", "11.0.25", False),
])
def test_2026_versions(key, version, affected):
    assert bool(scanner.matching_line(adv(key), parse(version))) is affected


def test_four_part_versions_order():
    assert parse("17.0.21") < parse("17.0.21.1") < parse("17.0.22")
    assert parse("1.2.1.0") == parse("1.2.1")


@pytest.mark.parametrize("version,fix_available,fixed_in", [
    ("22.23.3", True, "22.23.4"),
    ("20.18.0", False, None),        # end-of-life line: impacted, no fix
])
def test_impacted_lines_without_a_fix_are_still_reported(tmp_path, version, fix_available, fixed_in):
    write(tmp_path, {"Dockerfile": f"FROM node:{version}-alpine AS build\nRUN npm ci\n"})
    [finding] = scanner.scan_path(str(tmp_path)).findings
    assert finding["package"] == advisories.NODE_RUNTIME and finding["fixAvailable"] is fix_available
    if fixed_in:
        assert finding["fixedIn"] == fixed_in
    else:
        assert "no fix" in finding["fixedIn"]
    assert finding["confidence"] == "PLAUSIBLE"  # Node2Shell needs untrusted Brotli input (softened)
    assert "soften" not in finding and "advisoryExposure" not in finding


def test_php_wordpress_and_python_runtime_evidence(tmp_path):
    write(tmp_path, {
        "docker/Dockerfile": "FROM --platform=linux/amd64 php:8.3.10-apache\nFROM node:22 AS floating\n",
        "site/wp-includes/version.php": "<?php\n$wp_version = '6.9.3';\n",
        "composer.lock": {"packages": [{"name": "roots/wordpress-no-content", "version": "7.0.1"}]},
        "composer.json": {"config": {"platform": {"php": "8.1.27"}}},
        "requirements.txt": "requests==2.32.0\nBrotli==1.1.0\n",
        "poetry.lock": "[[package]]\nname = \"brotlicffi\"\nversion = \"1.2.0.0\"\n",
        ".github/workflows/ci.yml": "jobs:\n  t:\n    steps:\n      - uses: actions/setup-node@v4\n        with:\n          node-version: [22.23.4, 24.21.0]\n",
        ".tool-versions": "java temurin-21.0.13+11\nnodejs 26.12.1\n",
    })
    result = scanner.scan_path(str(tmp_path))
    found = {(f["file"], f["package"], f["version"]): f for f in result.findings}
    php = found[("docker/Dockerfile", advisories.PHP_RUNTIME, "8.3.10")]
    assert (php["severity"], php["confidence"], php["fixAvailable"]) == ("CRITICAL", "CONFIRMED", True)
    assert php["fixedIn"] == "8.3.37" and {"CVE-2026-109618", "CVE-2026-115560"} <= set(php["cves"])
    old_php = found[("composer.json", advisories.PHP_RUNTIME, "8.1.27")]
    assert old_php["fixAvailable"] is False and old_php["confidence"] == "PLAUSIBLE"
    wp = found[("site/wp-includes/version.php", advisories.WORDPRESS_CORE, "6.9.3")]
    assert wp["confidence"] == "CONFIRMED" and wp["fixedIn"] == "6.9.5"
    assert {"CVE-2026-63030", "CVE-2026-60137"} <= set(wp["cves"])
    assert found[("composer.lock", advisories.WORDPRESS_CORE, "7.0.1")]["fixedIn"] == "7.0.2"
    assert found[("requirements.txt", advisories.PYPI_BROTLI, "1.1.0")]["confidence"] == "PLAUSIBLE"
    assert ("poetry.lock", advisories.PYPI_BROTLICFFI, "1.2.0.0") in found
    assert (".github/workflows/ci.yml", advisories.NODE_RUNTIME, "24.21.0") in found
    assert (".github/workflows/ci.yml", advisories.NODE_RUNTIME, "22.23.4") not in found  # patched
    java = found[(".tool-versions", advisories.JAVA_RUNTIME, "21.0.13")]
    assert java["family"] == "4Shell" and java["confidence"] == "PLAUSIBLE"
    assert not any(f["package"] == advisories.NODE_RUNTIME and f["file"] == "docker/Dockerfile" for f in result.findings)


def test_runtime_file_detection_and_exact_versions():
    assert runtimes.is_runtime_file("svc/Dockerfile.prod") and runtimes.is_runtime_file(".github/workflows/ci.yaml")
    assert runtimes.is_runtime_file("requirements-dev.txt") and not runtimes.is_runtime_file("src/app.py")
    assert runtimes.exact_version("22.23.3-alpine") == "22.23.3" and runtimes.exact_version("22-slim") == ""
    assert runtimes.exact_version("21.0.13_11-jdk") == "21.0.13" and runtimes.exact_version("lts/*") == ""


def test_corretto_build_number_tags_are_not_guessed(tmp_path):
    write(tmp_path, {"Dockerfile": "FROM amazoncorretto:21.0.13.11.1\n"})
    result = scanner.scan_path(str(tmp_path))
    assert not result.findings and any("Corretto" in note for note in result.coverage)


def test_rare_precondition_cves_are_plausible_and_eol_spring_has_no_fix(tmp_path):
    write(tmp_path, {"package.json": {"dependencies": {"next": "16.3.0"}},
                     "package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {
                         "node_modules/next": {"version": "16.3.0"}}}), "app/page.tsx": "",
                     "legacy/pom.xml": "<project><packaging>war</packaging><dependencies><dependency><groupId>org.springframework"
                                       "</groupId><artifactId>spring-webmvc</artifactId><version>4.3.30.RELEASE</version>"
                                       "</dependency></dependencies></project>"})
    by_pkg = {f["package"]: f for f in scanner.scan_path(str(tmp_path)).findings}
    nxt = by_pkg["next"]
    assert "CVE-2026-126187" in nxt["cves"] and nxt["confidence"] == "PLAUSIBLE" and nxt["fixedIn"] == "16.4.1"
    spring = by_pkg["org.springframework:spring-webmvc"]
    assert spring["fixAvailable"] is False and spring["confidence"] == "CONFIRMED"


def test_xshell_cli_name_and_aliases():
    from threatlint.cli import build_parser
    for name in ("detect-xshell", "detect-2shell", "detect-4shell"):
        args = build_parser().parse_args([name, "scan"])
        assert args.integration_handler is cmd_detect_xshell


def test_legacy_env_names_still_work(tmp_path):
    from threatlint.detect_xshell import metrics
    env = {fleet.LEGACY_CREDENTIALS_ENV: json.dumps({"connections": [{"id": "g", "provider": "github", "token": "t"}]})}
    assert [c.id for c in fleet.load_connections(env)] == ["g"]
    doc = document([], scope="x")
    assert metrics.record(doc, mode="scan", environ={"THREATLINT_HOME": str(tmp_path), "THREATLINT_2SHELL_METRICS": "off"}) is None
    path = metrics.record(doc, mode="scan", environ={"THREATLINT_HOME": str(tmp_path)})
    assert path and path.name == "metrics.jsonl" and path.parent.name == "detect-xshell"


@pytest.mark.parametrize("version,affected", [
    ("8.2.35", True), ("8.2.36", False), ("8.3.36", True), ("8.3.37", False), ("8.4.27", True),
    ("8.4.28", False), ("8.5.12", True), ("8.5.13", False), ("8.6.0", False), ("7.4.33", True), ("5.3.29", False),
])
def test_cve_2026_115560_versions(version, affected):
    assert bool(scanner.matching_line(adv("php-session-serializer-rce"), parse(version))) is affected


def test_cve_2026_115560_alone_is_plausible_with_default_on_note(tmp_path):
    write(tmp_path, {"Dockerfile": "FROM php:8.3.36-fpm\n"})
    [finding] = scanner.scan_path(str(tmp_path)).findings
    assert finding["cves"] == ["CVE-2026-115560"] and finding["fixedIn"] == "8.3.37"
    assert finding["confidence"] == "PLAUSIBLE" and finding["fixAvailable"] is True
    assert "default On" in finding["exposure"]


def test_cve_2026_115560_config_context(tmp_path):
    write(tmp_path, {
        "Dockerfile": "FROM php:8.4.20-apache\nRUN echo 'session.upload_progress.enabled=0' > /usr/local/etc/php/conf.d/up.ini\n",
        "docker/php-fpm.d/www.conf": "[www]\nphp_admin_value[session.serialize_handler] = php_serialize\n",
        "public/.user.ini": "session.upload_progress.enabled = Off\n",
    })
    finding = next(f for f in scanner.scan_path(str(tmp_path)).findings if "CVE-2026-115560" in f["cves"])
    assert "disabled administratively (`Dockerfile:2`)" in finding["exposure"]
    assert "php_serialize" in finding["exposure"]
    write(tmp_path / "on", {"Dockerfile": "FROM php:8.4.20-apache\n", "php.ini": "session.upload_progress.enabled = On\n",
                            "app/.user.ini": "session.upload_progress.enabled=0\n"})
    finding = next(f for f in scanner.scan_path(str(tmp_path / "on")).findings if "CVE-2026-115560" in f["cves"])
    assert "explicitly On (`php.ini:1`)" in finding["exposure"]
