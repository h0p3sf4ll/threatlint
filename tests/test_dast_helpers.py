"""Synthetic regression coverage for bounded DAST request and evidence helpers."""

import argparse
import copy
import errno
import types
from pathlib import Path

import pytest

from threatlint import dast, dast_cli, dast_evidence, dast_passive, dast_probe, dast_records, dast_requests


def _finding(method="GET", kind="xss"):
    return {"method": method, "kind": kind, "query": "q=first&q=second&keep=&other=value",
            "parameter": "q", "path": "/search", "vulnerability": "Cross-site Scripting"}


@pytest.mark.parametrize("method", ["GET", "HEAD", "POST"])
def test_request_mutation_is_bounded_and_keeps_unrelated_query_parameters(method):
    finding = _finding(method)
    original = copy.deepcopy(finding)
    requests = dast_requests.plan_requests(finding, "synthetic")
    assert [request["id"] for request in requests] == ["baseline", "marker"]
    assert requests[0]["path"] == "/search?q=first&q=second&keep=&other=value"
    if method == "POST":
        assert requests[1]["path"] == requests[0]["path"]
        assert requests[1]["body"].startswith("q=tlsynthetic")
        assert requests[1]["headers"]["Content-Type"] == "application/x-www-form-urlencoded"
    else:
        assert requests[1]["path"].startswith("/search?keep=&other=value&q=tlsynthetic")
        assert "body" not in requests[1]
    assert requests[0]["headers"] == {"User-Agent": "threatlint-dast/1"}
    assert finding == original
    assert dast.plan_requests is dast_requests.plan_requests


def test_request_marker_default_keeps_existing_secrets_patch_seam(monkeypatch):
    monkeypatch.setattr(dast.secrets, "token_hex", lambda size: "fixed-marker")
    request = dast.plan_requests(_finding())[1]
    assert "tlfixed-marker" in request["path"]


@pytest.mark.parametrize("kind,count", [("xss", 2), ("sqli", 6), ("redirect", 3), ("traversal", 4), ("cors", 2), ("generic", 1)])
def test_request_plans_remain_finite_and_origin_relative(kind, count):
    requests = dast_requests.plan_requests(_finding(kind=kind), "synthetic")
    assert len(requests) == count
    assert all(request["path"].startswith("/") and not request["path"].startswith("//") for request in requests)
    if kind == "cors":
        assert requests[1]["headers"]["Origin"] == dast.PROBE_ORIGIN


def test_redaction_keeps_marker_context_and_redacts_secrets_in_both_excerpts():
    response = {
        "id": "marker", "status": 200, "body": "password=first-secret " + "x" * 2500 + "tlmarker token=second-secret café",
        "headers": [["Set-Cookie", "sid=secret-cookie; HttpOnly; SameSite=Lax"],
                    ["X-Session-Token", "secret-header"], ["X-Trace", "z" * 500]],
    }
    original = copy.deepcopy(response)
    redacted = dast_evidence.redact_response(response, marker="marker", limit=400)
    assert "tlmarker" in redacted["body_excerpt"] and "characters omitted" in redacted["body_excerpt"]
    for secret in ("first-secret", "second-secret", "secret-cookie", "secret-header"):
        assert secret not in str(redacted)
    assert redacted["headers"][0] == ["Set-Cookie", "sid=<redacted>; HttpOnly; SameSite=Lax"]
    assert len(redacted["headers"][2][1]) == 300
    assert redacted["body_bytes"] == len(response["body"].encode())
    assert response == original
    assert dast.redact_response is dast_evidence.redact_response


def test_passive_checks_preserve_case_insensitive_multivalue_headers_and_https_limits():
    response = {"status": 200, "body": "", "headers": [
        ["CONTENT-TYPE", "text/html"], ["Content-Security-Policy", "frame-ancestors 'none'"],
        ["Set-Cookie", "sid=synthetic; HttpOnly; SameSite=Lax"],
        ["set-cookie", "theme=synthetic; HttpOnly; Secure; SameSite=Lax"],
    ]}
    http = dast_passive.passive_checks(response, "/")
    https = dast_passive.passive_checks(response, "/", scanned_https=True)
    assert {item["rule"] for item in http} == {"RT-HDR-XCTO"}
    assert {item["rule"] for item in https} == {"RT-HDR-XCTO", "RT-HDR-HSTS", "RT-COOKIE-FLAGS"}
    assert dast_passive._headers(response)["set-cookie"] == [response["headers"][2][1], response["headers"][3][1]]
    assert dast.passive_checks is dast_passive.passive_checks
    assert dast_passive.passive_checks({"error": "synthetic"}, "/") == []


def test_dast_parser_keeps_description_and_existing_option_defaults(monkeypatch):
    monkeypatch.delenv(dast.sn.INSTANCE_ENV, raising=False)
    monkeypatch.setattr(dast.sn, "saved_config", lambda: {"instance": "https://synthetic.service-now.com"})
    parser = argparse.ArgumentParser()
    actions = parser.add_subparsers(dest="command")
    dast.add_dast_parser(actions)
    args = parser.parse_args(["dast", "AVIT0000000900001", "--step", "probe", "--work", "synthetic"])
    assert args.step == "probe" and args.work == "synthetic" and args.env_provider == "docker"
    assert args.snow_instance == "https://synthetic.service-now.com"
    assert actions.choices["dast"].description == dast.__doc__
    assert dast.STEPS is dast_cli.STEPS
    assert dast.load_avit_file is dast_records.load_avit_file
    assert dast.assess is dast_probe.assess


def test_collect_probe_keeps_raw_responses_out_of_persistable_evidence():
    finding = {**_finding(), "scanned_origin": "https://never-contacted.invalid"}
    state = {"finding": finding, "plan": {"app": "synthetic-app", "port": 8000}}
    original = copy.deepcopy(state)
    raw = [
        {"id": "baseline", "status": 200, "body": "password=synthetic-secret", "headers": [["Content-Type", "text/html"]]},
        {"id": "marker", "status": 200, "body": "<tlmarker>", "headers": [["Content-Type", "text/html"]]},
    ]
    seen = []

    def probe(received, requests):
        assert received is state
        seen.extend(requests)
        return raw

    evidence = dast_probe.collect_probe(state, types.SimpleNamespace(probe=probe), "marker")
    assert evidence["assessment"]["observed"] is True
    assert "synthetic-secret" not in str(evidence) and "password=<redacted>" in str(evidence)
    assert "synthetic-secret" in raw[0]["body"]
    assert all("never-contacted.invalid" not in str(request) for request in seen)
    assert evidence["target"].startswith("http://synthetic-app:8000 (sandbox only;")
    assert len(evidence["passive"]) == len({(item["rule"], item["observation"]) for item in evidence["passive"]})
    assert state == original


# ── Repo store base (where scanned repos are cloned) ────────────────────────────

def test_scratch_dir_uses_configured_repo_store(tmp_path, monkeypatch):
    from threatlint import runtime_env as rt
    store = tmp_path / "Repo Store"
    store.mkdir()
    monkeypatch.setenv("THREATLINT_REPO_STORE", str(store))
    base = rt.repo_store_base()
    assert base == str(store.resolve()) and store.is_dir()
    created = rt.scratch_dir()
    import os
    assert os.path.dirname(created) == str(store)  # clone workspace lands on the configured drive
    os.rmdir(created)


def test_missing_optional_store_falls_back_without_creating_mount_parents(tmp_path, monkeypatch):
    import tempfile
    from threatlint import runtime_env as rt
    primary = tmp_path / "primary"
    primary.mkdir()
    missing = tmp_path / "unmounted" / "repositories"
    monkeypatch.setenv("THREATLINT_REPO_STORE", str(missing))
    monkeypatch.setattr(tempfile, "tempdir", str(primary))
    assert rt.repo_store_base() is None
    created = rt.scratch_dir()
    assert Path(created).parent == primary
    assert not missing.parent.exists()


def test_existing_unmounted_volume_directory_falls_back_without_writing(tmp_path, monkeypatch):
    import io
    import tempfile
    from threatlint import runtime_env as rt
    external, primary = tmp_path / "external", tmp_path / "primary"
    external.mkdir()
    primary.mkdir()
    monkeypatch.setenv("THREATLINT_REPO_STORE", str(external))
    monkeypatch.setattr(tempfile, "tempdir", str(primary))
    monkeypatch.setattr(rt.os.path, "ismount", lambda _path: False)
    import builtins
    ordinary_open = builtins.open
    monkeypatch.setattr(builtins, "open", lambda filename, *args, **kwargs:
        io.StringIO("") if filename == "/proc/self/mountinfo" else ordinary_open(filename, *args, **kwargs))
    mounted = rt._mounted_store_directory
    assert mounted("/mnt/external/repos", platform="posix") is False
    monkeypatch.setattr(rt, "_mounted_store_directory", lambda _path: mounted("/mnt/external/repos", platform="posix"))
    assert Path(rt.scratch_dir()).parent == primary
    assert list(external.iterdir()) == []


def test_known_volume_roots_require_a_mount_but_custom_folders_remain_allowed(monkeypatch):
    import builtins
    import io
    from threatlint import runtime_env as rt
    monkeypatch.setattr(rt.os.path, "ismount", lambda value: value == "/Volumes/External")
    ordinary_open = builtins.open
    table = "31 20 0:1 /source /mnt/External\\040Drive rw - ext4 /dev/synthetic rw\n"
    monkeypatch.setattr(builtins, "open", lambda filename, *args, **kwargs:
        io.StringIO(table) if filename == "/proc/self/mountinfo" else ordinary_open(filename, *args, **kwargs))
    assert rt._mounted_store_directory("/Volumes/External/repos", platform="posix") is True
    assert rt._mounted_store_directory("/mnt/External Drive/repos", platform="posix") is True
    assert rt._mounted_store_directory("/run/media/user/unmounted/repos", platform="posix") is False
    assert rt._mounted_store_directory("/home/user/custom-repos", platform="posix") is True


def test_conventional_volume_parent_itself_requires_a_proven_mount(monkeypatch):
    import builtins
    import io
    from threatlint import runtime_env as rt
    ordinary_open = builtins.open
    table = ""
    monkeypatch.setattr(builtins, "open", lambda filename, *args, **kwargs:
        io.StringIO(table) if filename == "/proc/self/mountinfo" else ordinary_open(filename, *args, **kwargs))
    monkeypatch.setattr(rt.os.path, "ismount", lambda _path: False)
    assert rt._mounted_store_directory("/mnt", platform="posix") is False
    assert rt._mounted_store_directory("/media/repos", platform="posix") is False
    monkeypatch.setattr(rt.os.path, "ismount", lambda value: value == "/mnt")
    assert rt._mounted_store_directory("/mnt", platform="posix") is True
    assert rt._mounted_store_directory("/mnt/repos", platform="posix") is True
    table = "31 20 0:1 /source /media rw - ext4 /dev/synthetic rw\n"
    assert rt._mounted_store_directory("/media", platform="posix") is True
    assert rt._mounted_store_directory("/media/repos", platform="posix") is True


@pytest.mark.parametrize("code", [errno.EACCES, errno.EROFS, errno.ENODEV, errno.ENOSPC])
def test_unwritable_optional_store_uses_primary_storage(tmp_path, monkeypatch, code):
    import tempfile
    from threatlint import runtime_env as rt
    external, primary = tmp_path / "external", tmp_path / "primary"
    external.mkdir()
    primary.mkdir()
    monkeypatch.setenv("THREATLINT_REPO_STORE", str(external))
    monkeypatch.setattr(tempfile, "tempdir", str(primary))
    def unavailable(**_kwargs):
        raise OSError(code, "synthetic unavailable storage")
    monkeypatch.setattr(rt.tempfile, "mkstemp", unavailable)
    created = rt.scratch_dir()
    assert Path(created).parent == primary
    assert list(external.iterdir()) == []


def test_optional_store_disappearing_before_allocation_falls_back(tmp_path, monkeypatch):
    import tempfile
    from threatlint import runtime_env as rt
    external, primary = tmp_path / "external", tmp_path / "primary"
    external.mkdir()
    primary.mkdir()
    monkeypatch.setattr(rt, "repo_store_base", lambda: str(external))
    monkeypatch.setattr(tempfile, "tempdir", str(primary))
    allocate = tempfile.mkdtemp
    attempted = []
    def disappearing(*args, **kwargs):
        attempted.append(kwargs.get("dir"))
        if kwargs.get("dir") == str(external):
            raise FileNotFoundError("synthetic disconnected disk")
        return allocate(*args, **kwargs)
    monkeypatch.setattr(tempfile, "mkdtemp", disappearing)
    assert Path(rt.scratch_dir()).parent == primary
    assert attempted == [str(external), None]


def test_temporary_repo_keeps_selected_path_and_does_not_fail_when_it_disappears(tmp_path, monkeypatch):
    import shutil
    from threatlint import runtime_env as rt
    external, later = tmp_path / "external", tmp_path / "later"
    external.mkdir()
    later.mkdir()
    monkeypatch.setenv("THREATLINT_REPO_STORE", str(external))
    with rt.temporary_repo() as directory:
        selected = Path(directory)
        assert selected.parent == external
        monkeypatch.setenv("THREATLINT_REPO_STORE", str(later))
        (selected / "evidence").write_text("selected once", encoding="utf-8")
        assert (selected / "evidence").read_text(encoding="utf-8") == "selected once"
        shutil.rmtree(selected)
    assert list(later.iterdir()) == []


def test_optional_cleanup_failure_preserves_completed_result(tmp_path, monkeypatch, capsys):
    from threatlint import runtime_env as rt, servicenow_checkout
    monkeypatch.setenv("THREATLINT_REPO_STORE", str(tmp_path))
    def blocked(_directory):
        raise PermissionError("synthetic disconnected or locked disk")
    monkeypatch.setattr(servicenow_checkout, "remove_checkout", blocked)
    def completed_review():
        with rt.temporary_repo():
            return {"status": "complete"}
    assert completed_review() == {"status": "complete"}
    assert "cleanup could not finish" in capsys.readouterr().err


def test_scratch_dir_falls_back_to_system_temp_when_unset(monkeypatch):
    from threatlint import runtime_env as rt
    from threatlint import org_config
    monkeypatch.delenv("THREATLINT_REPO_STORE", raising=False)
    monkeypatch.setattr(org_config, "value", lambda key: "")
    assert rt.repo_store_base() is None
    created = rt.scratch_dir()
    import os, tempfile
    assert os.path.dirname(created) == os.path.realpath(tempfile.gettempdir()) or os.path.dirname(created) == tempfile.gettempdir()
    os.rmdir(created)
