"""CLI compatibility without touching the developer's queue."""

import argparse
import json
from pathlib import Path

from threatlint.avit_orchestrator import add_orchestrator_parser, cmd_orchestrator
from threatlint.cli import build_parser


def test_cli_queue_pause_stats_and_resume(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    parser = argparse.ArgumentParser()
    add_orchestrator_parser(parser.add_subparsers(dest="command"))

    def run(*args):
        return cmd_orchestrator(parser.parse_args(["orchestrator", *args]))

    assert run("queue", "add", "AVIT0000001") == 0
    capsys.readouterr()
    assert run("queue", "list", "--status", "pending") == 0
    assert json.loads(capsys.readouterr().out)[0]["number"] == "AVIT0000001"
    assert run("pause") == 0
    capsys.readouterr()
    assert run("stats") == 0
    assert json.loads(capsys.readouterr().out)["paused"] is True
    assert run("resume") == 0
    capsys.readouterr()
    assert run("clear") == 0
    assert capsys.readouterr().out == "Cleared 1 item(s)\n"


def test_cli_canary_without_handler_fails(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    parser = argparse.ArgumentParser()
    add_orchestrator_parser(parser.add_subparsers(dest="command"))
    assert cmd_orchestrator(parser.parse_args(["orchestrator", "canary"])) == 1
    assert "not implemented without handler" in capsys.readouterr().out


def test_main_cli_registers_package_parser():
    args = build_parser().parse_args(["orchestrator", "queue", "list", "--status", "failed"])
    assert args.command == "orchestrator"
    assert args.orch_command == "queue"
    assert args.queue_cmd == "list"
    assert args.status == "failed"
