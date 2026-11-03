"""Secret-validation integrations: extension point for checking whether a detected credential is live.

Threatlint ships no built-in validators. Validators are supplied as plugins (see docs/integrations/authoring.md)
and must stay inside the safety contract in `base`: fixed provider hosts, read-only identity calls, no redirects,
and masked output. Without a validator, credential validity is reported UNVERIFIED.
"""

from threatlint.integrations.secret_validation.base import (INVALID, KIND, STATUSES, UNVERIFIED, VALID, Candidate, Result,
                                                             SecretValidator, fingerprint, mask)

__all__ = ["INVALID", "KIND", "STATUSES", "UNVERIFIED", "VALID", "Candidate", "Result", "SecretValidator", "fingerprint", "mask"]
