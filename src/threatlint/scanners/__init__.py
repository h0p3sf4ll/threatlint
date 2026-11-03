"""Deprecated alias for `threatlint.integrations`; kept so existing imports keep working.

The scanner adapters were split by integration type:

  threatlint.scanners.base        -> threatlint.integrations.common   (ScannerError -> IntegrationError,
                                                                       Adapter -> ReviewableIntegration)
  threatlint.scanners.verdicts    -> threatlint.integrations.verdicts
  threatlint.scanners.defectdojo  -> threatlint.integrations.findings_management.defectdojo
  threatlint.scanners.sonarqube   -> threatlint.integrations.scanning.sonarqube
  threatlint.scanners.registry()  -> threatlint.integrations.reviewable()

This package will be removed in a future release.
"""

import warnings

from threatlint.integrations import reviewable as registry
from threatlint.integrations.common import IntegrationError as ScannerError
from threatlint.integrations.common import ReviewableIntegration as Adapter

warnings.warn("threatlint.scanners is deprecated; import from threatlint.integrations instead",
              DeprecationWarning, stacklevel=2)

__all__ = ["Adapter", "ScannerError", "registry"]
