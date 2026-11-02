"""Synthetic workbook-table parsing, with no credentials or remote integrations."""

import pytest

from threatlint.sidekick import report_import, reports, store
from threatlint.sidekick.clients import SidekickError


@pytest.mark.parametrize(
    ("header", "expected"),
    [(" Total Vulns ", "total_vulns"), ("--Repo Manager--", "repo_manager"), (None, "")],
)
def test_header_normalization(header, expected):
    assert report_import.normalize_header(header) == expected
    assert reports._norm(header) == expected


def test_aliases_and_metric_conversion_preserve_imported_row_shape():
    table = [
        ["Repo", "Project", "Org", "Secrets", "Total Vulns", "Total High", "Manager"],
        ["api", "P", "other", "2.9", "bad", None, "Owner"],
        ["web", "P", "", "", 3.8, "4"],
        ["", "P"],
        ["missing-project"],
        [],
    ]
    columns = report_import.import_columns(table)
    rows = report_import.import_rows(table[1:], columns, "default", store.METRICS)
    assert len(rows) == 2
    assert rows[0] == {
        "repository": "api", "project": "P", "organization": "other", "status": "complete",
        "repo_manager": "Owner", "director": "",
        **{metric: None for metric in store.METRICS},
        "open_secrets": 2,
    }
    assert rows[1]["organization"] == "default"
    assert rows[1]["total_vulns"] == 3 and rows[1]["total_high"] == 4
    assert rows[1]["repo_manager"] == "" and rows[1]["open_secrets"] is None


def test_extra_cells_and_duplicate_columns_keep_existing_last_column_wins():
    table = [["repo", "project", "total_vulns", "total-vulns"], ["r", "p", 8, 3, "ignored"]]
    columns = report_import.import_columns(table)
    rows = report_import.import_rows(table[1:], columns, "o", store.METRICS)
    assert rows[0]["total_vulns"] == 3


@pytest.mark.parametrize(
    ("table", "message"),
    [([], "header but no rows"), ([["repo", "project"]], "header but no rows"),
     ([["repo"], ["r"]], "repository and project columns")],
)
def test_bad_workbook_shape(table, message):
    with pytest.raises(SidekickError, match=message):
        report_import.import_columns(table)


def test_no_complete_repository_identity_is_rejected():
    with pytest.raises(SidekickError, match="No rows"):
        report_import.import_rows([["r"], ["", "p"]], ["repository", "project"], "o", store.METRICS)


def test_import_preserves_reader_and_normalizer_monkeypatch_seams(monkeypatch, tmp_path):
    monkeypatch.setenv("THREATLINT_HOME", str(tmp_path))
    monkeypatch.setattr(reports, "read_xlsx", lambda path: [["custom", "Project"], ["r", "p"]])
    normalize = reports._norm
    monkeypatch.setattr(reports, "_norm", lambda header: "repository" if header == "custom" else normalize(header))
    monkeypatch.setattr(store, "default_organization", lambda: "synthetic")
    source = tmp_path / "synthetic.xlsx"
    source.write_bytes(b"synthetic workbook; reader is mocked")
    result = reports.import_report(str(source), "L", "2026-10-01")
    [row] = reports.run_rows(result["runId"])
    assert row["repository"] == "r" and row["organization"] == "synthetic"
    assert row["status"] == "complete"


def test_invalid_headers_are_rejected_before_resolving_organization(monkeypatch, tmp_path):
    monkeypatch.setenv("THREATLINT_HOME", str(tmp_path))
    monkeypatch.setattr(reports, "read_xlsx", lambda path: [["wrong"], ["r"]])

    def unexpected_config_read():
        pytest.fail("invalid workbook must not resolve organization or credentials")

    monkeypatch.setattr(store, "default_organization", unexpected_config_read)
    with pytest.raises(SidekickError, match="repository and project"):
        reports.import_report("unused.xlsx", "L", "2026-10-01")
