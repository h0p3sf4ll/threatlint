"""Installation treats standalone entry points and their helpers as one bundle."""

import argparse

from threatlint import installation


def test_uninstall_removes_bundled_scripts_and_preserves_custom_content(tmp_path):
    args = argparse.Namespace(
        local=True, directory=str(tmp_path), yes=True, quiet=True,
        lmstudio=False, copilot=False,
    )
    assert installation.cmd_install(args) == 0
    scripts = tmp_path / ".claude" / "scripts"
    shipped = [path.name for path in installation._SCRIPTS_SRC.iterdir() if path.is_file()]
    assert "threatlint_chat.py" in shipped
    assert "_chat_content.py" in shipped
    assert "_appsec_prompts.py" in shipped
    assert all((scripts / name).is_file() for name in shipped)
    custom = scripts / "company-script.py"
    custom.write_text("# user-owned")
    nested = scripts / "company-tools"
    nested.mkdir()
    (nested / "notes.txt").write_text("user-owned")
    assert installation.cmd_uninstall(args) == 0
    assert not any((scripts / name).exists() for name in shipped)
    assert custom.read_text() == "# user-owned"
    assert (nested / "notes.txt").read_text() == "user-owned"
