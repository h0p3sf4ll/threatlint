"""Runtime red-team assessment: build an application from its own repository in an isolated, no-egress ephemeral
environment and assess it with Threatlint's own runtime ruleset.

Threatlint is the ruleset provider. A `Ruleset` is a library of bounded, declarative runtime test patterns (an id,
an OWASP category, a CWE, the vulnerability class it probes, and where it applies). The built-in seed generalizes
the vetted DAST checks (`dast_probe`, `dast_passive`); a per-user learned store records which patterns actually find
issues on which kinds of endpoint, so each assessment makes the next one target better.

Every guardrail of the DAST subsystem holds here: the app runs on an `--internal` Docker network with no route out,
requests are bounded and go only to the sandbox application, credentials default to synthetic, and nothing is
exploited or exfiltrated. Confirmed findings are drafted as AVITs; posting them to ServiceNow is stubbed behind a
hook (`servicenow_stub.set_avit_publisher`) and otherwise written to the report.
"""

from __future__ import annotations

from threatlint.redteam.rules import BUILT_IN, Rule, Ruleset, load_ruleset

__all__ = ["BUILT_IN", "Rule", "Ruleset", "load_ruleset"]
