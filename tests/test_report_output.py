"""Report output uses temporary artifacts, never a developer's real report folder."""

from pathlib import Path
from types import SimpleNamespace

from threatlint import report_output


def test_missing_converter_falls_back_to_markdown(tmp_path, monkeypatch):
    monkeypatch.setattr(report_output, "_SCRIPTS_SRC", tmp_path / "no-scripts")
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    saved = report_output._save_report("# Synthetic report", tmp_path / "reports", "example", "test")
    assert saved == tmp_path / "reports" / "example.md"
    assert saved.read_text() == "# Synthetic report"


def test_successful_converter_removes_temporary_markdown(tmp_path, monkeypatch):
    script = tmp_path / "md_to_docx.py"
    script.write_text("# synthetic converter")
    monkeypatch.setattr(report_output, "_SCRIPTS_SRC", tmp_path)
    sources = []

    def convert(command, **kwargs):
        source, target = Path(command[-2]), Path(command[-1])
        assert source.read_text() == "# Synthetic report"
        sources.append(source)
        target.write_bytes(b"synthetic docx")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(report_output.subprocess, "run", convert)
    saved = report_output._save_report("# Synthetic report", tmp_path / "reports", "example", "test")
    assert saved.suffix == ".docx" and saved.read_bytes() == b"synthetic docx"
    assert not sources[0].exists()


def test_failed_converter_falls_back_and_removes_temporary_file(tmp_path, monkeypatch):
    (tmp_path / "md_to_docx.py").write_text("# synthetic converter")
    monkeypatch.setattr(report_output, "_SCRIPTS_SRC", tmp_path)
    sources = []

    def fail(command, **kwargs):
        sources.append(Path(command[-2]))
        return SimpleNamespace(returncode=1)

    monkeypatch.setattr(report_output.subprocess, "run", fail)
    saved = report_output._save_report("# Synthetic report", tmp_path, "example", "test")
    assert saved.read_text() == "# Synthetic report"
    assert saved.suffix == ".md" and not sources[0].exists()
