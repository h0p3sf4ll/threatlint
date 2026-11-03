"""Integration types, the plugin registry, and `threatlint integrations list`. No network, no real plugins."""

import json
import types

import pytest

from threatlint import cli
from threatlint import integrations as registry
from threatlint.integrations.findings_management import FindingsManagementPlatform
from threatlint.integrations.scanning import ScanningTool


class AcmeFindings(FindingsManagementPlatform):
    name, command, label = "acme-findings", "acme", "Acme Findings"
    summary = "Example community findings platform"
    reference_example = "ACME-1"


class Entry:
    """Stands in for importlib.metadata.EntryPoint."""

    def __init__(self, name, loader, dist="threatlint-acme"):
        self.name, self._loader, self.value = name, loader, f"{dist}:{name}"
        self.dist = types.SimpleNamespace(name=dist)

    def load(self):
        return self._loader()


@pytest.fixture
def plugins(monkeypatch):
    """Install fake entry points; the registry cache is cleared before and after."""
    import importlib.metadata as metadata
    installed = []
    monkeypatch.setattr(metadata, "entry_points", lambda group: installed if group == registry.ENTRY_POINT_GROUP else [])
    monkeypatch.delenv("THREATLINT_DISABLE_PLUGINS", raising=False)
    registry.reload()
    yield installed
    registry.reload()


def test_built_ins_are_separate_types(plugins):
    kinds = {integration.name: integration.kind for integration in registry.integrations()}
    assert kinds == {"defectdojo": "findings-management", "sonarqube": "scanning"}
    dojo, sonar = registry.reviewable()["dojo"], registry.reviewable()["sonar"]
    assert isinstance(dojo, FindingsManagementPlatform) and not isinstance(dojo, ScanningTool)
    assert isinstance(sonar, ScanningTool) and not isinstance(sonar, FindingsManagementPlatform)
    assert dojo.supports_attachments and not sonar.supports_attachments


@pytest.mark.parametrize("loader", [lambda: AcmeFindings, lambda: AcmeFindings(), lambda: (lambda: AcmeFindings())],
                         ids=["class", "instance", "factory"])
def test_plugin_entry_point_forms_register_with_their_distribution(plugins, loader):
    plugins.append(Entry("acme", loader))
    acme = registry.reviewable()["acme"]
    assert acme.kind == "findings-management" and acme.source == "threatlint-acme"


def test_broken_or_conflicting_plugins_are_skipped_with_a_warning(plugins, capsys):
    class Clash(ScanningTool):
        name, command, label = "sonar-clone", "sonar", "Clash"

    class Unknown(AcmeFindings):
        kind, name, command = "ticketing", "acme-tickets", "tickets"

    def broken():
        raise ImportError("missing dependency")

    plugins += [Entry("broken", broken), Entry("clash", lambda: Clash), Entry("unknown", lambda: Unknown)]
    assert set(registry.reviewable()) == {"dojo", "sonar"}
    warnings = capsys.readouterr().err
    assert "broken" in warnings and "already registered" in warnings and "unknown integration type" in warnings


def test_plugins_can_be_disabled(plugins, monkeypatch):
    plugins.append(Entry("acme", lambda: AcmeFindings))
    monkeypatch.setenv("THREATLINT_DISABLE_PLUGINS", "1")
    registry.reload()
    assert "acme" not in registry.reviewable()


def test_plugin_gets_the_review_commands_and_is_listed(plugins, capsys, monkeypatch):
    plugins.append(Entry("acme", lambda: AcmeFindings))
    args = cli.build_parser().parse_args(["acme", "resolve", "ACME-1", "--report", "r.md", "--docx", "r.docx"])
    assert args.integration.name == "acme-findings" and args.integration_command == "resolve"
    monkeypatch.setattr("sys.argv", ["threatlint", "integrations", "list", "--json"])
    with pytest.raises(SystemExit) as exit_info:
        cli.main()
    assert exit_info.value.code == 0
    rows = json.loads(capsys.readouterr().out)
    assert {"name": "acme-findings", "kind": "findings-management", "command": "acme", "source": "threatlint-acme"}.items() \
        <= next(row for row in rows if row["name"] == "acme-findings").items()


def test_list_groups_by_type(plugins, capsys):
    args = cli.build_parser().parse_args(["integrations", "list"])
    assert args.integration_handler(args) == 0
    out = capsys.readouterr().out
    assert out.index("Findings management") < out.index("DefectDojo") < out.index("Scanning tools") < out.index("SonarQube")
    assert "Secret validation" in out and "(none installed)" in out


def test_deprecated_scanners_imports_still_resolve():
    import importlib
    import sys
    for name in [module for module in sys.modules if module == "threatlint.scanners" or module.startswith("threatlint.scanners.")]:
        del sys.modules[name]
    with pytest.warns(DeprecationWarning, match="threatlint.integrations"):
        scanners = importlib.import_module("threatlint.scanners")
    from threatlint.integrations import common
    from threatlint.integrations.findings_management import defectdojo
    from threatlint.scanners import base, defectdojo as old_dojo, sonarqube as old_sonar, verdicts
    assert scanners.ScannerError is base.ScannerError is common.IntegrationError
    assert base.request is common.request and base.validate_base_url is common.validate_base_url
    assert old_dojo.ADAPTER is defectdojo.INTEGRATION and isinstance(old_sonar.ADAPTER, scanners.Adapter)
    assert set(scanners.registry()) >= {"dojo", "sonar"} and callable(verdicts.candidates)
