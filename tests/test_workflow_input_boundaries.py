"""Exercise the real workflow shell with hostile dispatch input as inert data."""

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

import pytest


WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"


@pytest.mark.skipif(os.name == "nt" or not shutil.which("bash"), reason="Requires a POSIX workflow shell")
@pytest.mark.parametrize("workflow", ["attack-tree", "compliance-check", "iac-review", "red-team", "threat-model"])
def test_workflow_dispatch_target_cannot_become_shell_code(tmp_path, workflow):
    text = (WORKFLOWS / f"appsec-{workflow}.yml").read_text()
    step = re.search(r"      - name: Run [^\n]+\(OpenAI / GitHub Models\)\n(.*?)(?=\n      - |\Z)", text, re.S).group(1)
    script = step.split("        run: |\n", 1)[1]
    script = "\n".join(line[10:] if line.startswith("          ") else line for line in script.splitlines())
    # Replace only the executable, preserving the exact workflow arguments and quoting.
    executable = tmp_path / "capture.py"
    executable.write_text("import json, os, sys\njson.dump(sys.argv[1:], open(os.environ['CAPTURE_FILE'], 'w'))\n")
    script = script.replace("python3 .github/scripts/appsec_api.py", '"$FIXTURE_PYTHON" "$FIXTURE_CAPTURE"')
    marker = tmp_path / "injected"
    target = f'"; printf injected > "{marker}"; # $(printf injected > "{marker}") `printf injected > "{marker}"`'
    captured = tmp_path / "arguments.json"
    result = subprocess.run(["bash", "-e", "-c", script], cwd=tmp_path, capture_output=True, text=True,
                            env={**os.environ, "REVIEW_TARGET": target, "PROVIDER": "openai", "REPORT_FILE": "fixture report.md",
                                 "CAPTURE_FILE": str(captured), "FIXTURE_PYTHON": sys.executable, "FIXTURE_CAPTURE": str(executable)}, check=False)
    assert result.returncode == 0, result.stderr
    args = json.loads(captured.read_text())
    assert args[args.index("--target") + 1] == target
    assert args[args.index("--output") + 1] == "fixture report.md"
    assert not marker.exists()
