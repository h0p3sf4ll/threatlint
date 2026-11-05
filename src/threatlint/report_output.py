"""Persist analysis reports and choose stable output names."""

from __future__ import annotations

import datetime
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from .installation import _SCRIPTS_SRC, _DOCX_SCRIPT, _CLAUDE_DIR
from .finding_review import normalize_report


def _git_output(*args: str) -> str:
    return subprocess.run(["git", *args], capture_output=True, text=True, check=False).stdout.strip()


def _report_basename(repo_root: str, mode: str) -> str:
    repo_name = Path(repo_root).name.lower().replace(" ", "-")
    branch = (_git_output("rev-parse", "--abbrev-ref", "HEAD") or "no-branch").lower().replace("/", "-")
    return f"{repo_name}-{branch}-{mode}-local-{datetime.date.today():%Y-%m-%d}"


def _save_report(output: str, out_dir: Path, base_name: str, mode: str) -> Path:
    """Save as Word when the converter succeeds, otherwise as Markdown."""
    if mode == "fp-review":
        output = normalize_report(output)
    out_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(suffix=".md", delete=False, prefix=f"{mode}_") as tf:
        tf.write(output.encode())
        tmp_md = Path(tf.name)
    docx_script = _SCRIPTS_SRC / _DOCX_SCRIPT
    if not docx_script.exists():
        docx_script = Path.home() / _CLAUDE_DIR / "scripts" / _DOCX_SCRIPT
    out_docx = out_dir / f"{base_name}.docx"
    if docx_script.exists() and subprocess.run([sys.executable, str(docx_script), str(tmp_md), str(out_docx)], check=False).returncode == 0:
        tmp_md.unlink(missing_ok=True)
        return out_docx
    out_md = out_dir / f"{base_name}.md"
    shutil.move(str(tmp_md), out_md)
    return out_md
