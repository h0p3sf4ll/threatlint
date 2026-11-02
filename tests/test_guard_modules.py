"""Guard responsibilities remain individually importable and composable."""

import json

from threatlint import guard
from threatlint.guard import models, output, rules, scanning


def test_public_guard_exports_are_the_extracted_implementations():
    assert guard.Rule is models.Rule
    assert guard.Finding is models.Finding
    assert guard.RULES is rules.RULES
    assert guard.scan_text is scanning.scan_text
    assert guard.to_sarif is output.to_sarif


def test_engine_output_boundary_keeps_redaction_and_locations():
    source = "api_key = " + repr("synthetic-value")
    findings = scanning.scan_text(source, path="app.py")
    assert len(findings) == 1
    assert findings[0].rule_id == "TL-SECRET-GENERIC"
    assert findings[0].snippet.endswith("[redacted]")
    payload = json.loads(output.to_json(findings))
    assert payload["findings"][0]["path"] == "app.py"
    assert payload["findings"][0]["line"] == 1
    assert "synthetic-value" not in payload["findings"][0]["snippet"]
