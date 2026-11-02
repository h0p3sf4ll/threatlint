"""Offline runtime planning tests; no Docker, credentials, or live environment."""

import copy

import pytest

from threatlint import runtime_compose, runtime_config, runtime_discovery, runtime_env, runtime_models


def test_example_env_reads_only_examples_and_first_value_wins(tmp_path):
    (tmp_path / ".env").write_text("HOST=live.invalid\nLIVE_ONLY=do-not-read\n")
    (tmp_path / ".env.example").write_text("HOST='sandbox'\nPASSWORD=example-secret\nEMPTY=\nexport PORT=8000\n")
    (tmp_path / ".env.sample").write_text("HOST=ignored\nOTHER=sample\n")
    cache = {}
    env = runtime_config.example_env(str(tmp_path), cache)
    assert env["HOST"] == "sandbox" and env["PORT"] == "8000" and env["OTHER"] == "sample"
    assert "LIVE_ONLY" not in env
    assert env["PASSWORD"].startswith("tl-synthetic-") and env["PASSWORD"] != "example-secret"
    assert env["EMPTY"].startswith("tl-synthetic-")
    assert runtime_config.example_env(str(tmp_path), cache) == env


def test_scrub_env_shares_synthetic_values_without_host_interpolation(monkeypatch):
    monkeypatch.setenv("HOST_SECRET", "must-not-use")
    original = {
        "PASSWORD": "shared", "DB_PASSWORD": "shared", "HOST": "${HOST_SECRET}",
        "PORT": "${PORT:-8000}", "OTHER": "${OTHER-default}", "EMPTY": None,
        "TOKEN_FILE": "/synthetic/token", "AUTH_ENABLED": True,
    }
    before = copy.deepcopy(original)
    clean = runtime_config.scrub_env(original, {})
    assert clean["PASSWORD"] == clean["DB_PASSWORD"] != "shared"
    assert clean["HOST"].startswith("tl-synthetic-") and clean["HOST"] != "must-not-use"
    assert clean["PORT"] == "8000" and clean["OTHER"] == "default" and clean["EMPTY"] == ""
    assert clean["TOKEN_FILE"] == "/synthetic/token" and clean["AUTH_ENABLED"] == "True"
    assert original == before


def test_runtime_models_round_trip_preserves_types_and_independent_defaults():
    app = runtime_env.Service("app", port=8000, env={"TOKEN": "synthetic"})
    backing = runtime_env.Service("backing")
    assert runtime_env.Service is runtime_models.Service
    assert runtime_env.EnvError is runtime_models.EnvError
    assert runtime_env.Limits is runtime_models.Limits
    plan = runtime_env.Plan("synthetic", [backing, app], "app", 8000, ["/"], "")
    data = runtime_env.plan_dict(plan)
    restored = runtime_env.plan_from(data)
    assert restored == plan and restored.app_service() is restored.services[1]
    restored.app_service().env["TOKEN"] = "changed"
    assert app.env["TOKEN"] == "synthetic" and backing.env == {}
    assert data["services"][1]["env"]["TOKEN"] == "changed"
    runtime_env.Service("first").dropped.append("volumes")
    assert runtime_env.Service("second").dropped == []


def test_compose_translation_drops_host_settings_without_mutating_input(tmp_path):
    config = {"services": {"app": {
        "build": {"context": ".", "args": {"COUNT": 2}, "target": "test"},
        "image": "ignored-for-build", "environment": ["PASSWORD=sample", "EMPTY"],
        "ports": [{"target": 8123}], "command": "python app.py", "entrypoint": ["entry"],
        "volumes": ["/host:/app"], "privileged": True, "network_mode": "host",
    }}}
    before = copy.deepcopy(config)
    [service] = runtime_compose.parse_services(config, str(tmp_path), "compose.yaml", {})
    assert service.image == "" and service.build["context"] == str(tmp_path.resolve())
    assert service.build["args"] == {"COUNT": "2"} and service.build["target"] == "test"
    assert service.port == 8123 and service.command == ["python", "app.py"] and service.entrypoint == ["entry"]
    assert service.env["PASSWORD"].startswith("tl-synthetic-") and service.env["EMPTY"] == ""
    assert set(service.dropped) == {"ports", "volumes", "privileged", "network_mode"}
    assert config == before


@pytest.mark.parametrize("build", [{"context": "../outside"}, {"context": ".", "dockerfile": "../outside/Dockerfile"}])
def test_compose_build_paths_cannot_escape_checkout(tmp_path, build):
    root = tmp_path / "repo"
    root.mkdir()
    with pytest.raises(runtime_env.EnvError, match="outside the repository"):
        runtime_compose.parse_services({"services": {"app": {"build": build}}}, str(root), "compose.yml", {})


def test_compose_build_symlink_cannot_escape_checkout(tmp_path):
    root, outside = tmp_path / "repo", tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (root / "linked").symlink_to(outside, target_is_directory=True)
    with pytest.raises(runtime_env.EnvError, match="outside the repository"):
        runtime_compose.parse_services({"services": {"app": {"build": "linked"}}}, str(root), "compose.yml", {})


@pytest.mark.parametrize("config,message", [
    ({"services": {}}, "defines no services"),
    ({"services": {"-bad": {"image": "synthetic"}}}, "Unsupported compose service name"),
])
def test_compose_invalid_service_definitions_are_rejected(tmp_path, config, message):
    with pytest.raises(runtime_env.EnvError, match=message):
        runtime_compose.parse_services(config, str(tmp_path), "compose.yml", {})


@pytest.mark.parametrize("manifest,contents,stack,port,command", [
    ("package.json", '{"scripts":{"test":"synthetic-test"}}', "node", 3000, "npm test"),
    ("requirements.txt", "pytest\n", "python", 8000, "python -m pytest -q"),
    ("pom.xml", "<project/>", "java", 8080, "mvn -q -B -o test"),
    ("go.mod", "module synthetic", "go", 8080, "cd /src && go test ./..."),
])
def test_discovery_only_writes_a_build_plan_without_running_tools(tmp_path, monkeypatch, manifest, contents, stack, port, command):
    (tmp_path / manifest).write_text(contents)
    if stack == "python":
        (tmp_path / "app.py").write_text("# synthetic entry point")
    monkeypatch.setattr(runtime_discovery.subprocess, "run", lambda *args, **kwargs: pytest.fail("Discovery must not build or deploy"))
    plan = runtime_discovery.detect(str(tmp_path), str(tmp_path))
    assert plan.stack == f"{stack} (generated Dockerfile)" and plan.port == port and plan.test_command == command
    assert (tmp_path / "Dockerfile.generated").is_file()
    assert runtime_env.detect is runtime_discovery.detect
    assert runtime_env.generated_dockerfile is runtime_discovery.generated_dockerfile


def test_discovery_can_select_a_compose_service_without_default_port(tmp_path, monkeypatch):
    (tmp_path / "compose.yaml").write_text("# synthetic")
    monkeypatch.setattr(runtime_discovery, "compose_services", lambda *args: [runtime_env.Service("backing", port=5432)])
    with pytest.raises(runtime_env.EnvError, match="No application service found in compose.yaml; pass --service"):
        runtime_discovery.detect(str(tmp_path), str(tmp_path), service="missing")
