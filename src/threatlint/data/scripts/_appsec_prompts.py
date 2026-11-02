"""Compatibility exports for the snapshot runner's mode-family prompt catalogs.

Edit review, modeling, operations, or findings instructions in the corresponding
_appsec_prompts_<family>.py sibling. All modules remain dependency-free.
"""
from _appsec_prompts_findings import (
    COMPLIANCE_CHECK_SYSTEM, COMPLIANCE_CHECK_TEMPLATE,
    THREAT_DELTA_SYSTEM, THREAT_DELTA_TEMPLATE,
    VERIFY_FIX_SYSTEM, VERIFY_FIX_TEMPLATE,
)
from _appsec_prompts_modeling import (
    ATTACK_TREE_SYSTEM, ATTACK_TREE_TEMPLATE,
    RED_TEAM_SYSTEM, RED_TEAM_TEMPLATE,
    THREAT_MODEL_DEEP_SYSTEM, THREAT_MODEL_DEEP_TEMPLATE,
    THREAT_MODEL_SYSTEM, THREAT_MODEL_TEMPLATE,
)
from _appsec_prompts_operations import (
    CICD_AUDIT_SYSTEM, CICD_AUDIT_TEMPLATE,
    DEPENDENCY_AUDIT_SYSTEM, DEPENDENCY_AUDIT_TEMPLATE,
    IAC_REVIEW_SYSTEM, IAC_REVIEW_TEMPLATE,
    SECRETS_SCAN_SYSTEM, SECRETS_SCAN_TEMPLATE,
)
from _appsec_prompts_review import (
    API_SECURITY_SYSTEM, API_SECURITY_TEMPLATE,
    AUTH_REVIEW_SYSTEM, AUTH_REVIEW_TEMPLATE,
    PR_REVIEW_SYSTEM, PR_REVIEW_TEMPLATE,
)
