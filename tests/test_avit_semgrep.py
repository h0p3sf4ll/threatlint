"""AVIT matching uses the original transport, parser, and path-comparison seams."""

import json
from types import SimpleNamespace

from threatlint import avit_resolve as ar
from threatlint import semgrep_platform as sp
from threatlint import servicenow as sn


def test_transport_keeps_auth_headers_and_original_opener(monkeypatch):
    seen = []

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self):
            return b'{"num_triaged": 1}'

    def open_request(request, **kwargs):
        seen.append((request, kwargs))
        return Response()

    monkeypatch.setattr(sn, "_OPENER", SimpleNamespace(open=open_request))
    assert ar._semgrep("/synthetic", "synthetic-token", body={"synthetic": True}) == {"num_triaged": 1}
    request, kwargs = seen[0]
    assert request.headers["Authorization"] == "Bearer synthetic-token"
    assert json.loads(request.data) == {"synthetic": True}
    assert kwargs == {"timeout": 120}


def test_matching_resolves_original_report_line_and_path_collaborators(monkeypatch):
    monkeypatch.setattr(sp, "deployment", lambda *args: {"slug": "synthetic", "id": 7})
    monkeypatch.setattr(ar, "_report_line", lambda *args: 42)
    monkeypatch.setattr(ar, "_same_path", lambda *args: True)
    monkeypatch.setattr(ar, "_semgrep", lambda *args: {"findings": [
        {"id": 1, "rule_name": "r", "location": {"file_path": "synthetic.py", "line": 42}},
    ]})
    _dep, matches = ar.semgrep_matches(
        "synthetic", "sast", {"organization": "synthetic", "name": "repo"},
        {"file_path": "file.py", "rule": "r"}, report_text="synthetic",
    )
    assert [match["id"] for match in matches] == [1]
