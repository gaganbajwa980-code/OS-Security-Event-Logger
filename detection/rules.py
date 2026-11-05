"""
Predefined detection rules and security definitions for Sentinel.
Maps Windows Event IDs, system indicators, and sample patterns
to formal security rules, severity levels, and MITRE ATT&CK references.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from monitor.event_models import SeverityLevel


@dataclass(frozen=True)
class DetectionRule:
    """Formal definition of a security detection rule."""
    rule_id: str
    name: str
    severity: str
    description: str
    mitre_attack_id: Optional[str] = None
    target_event_ids: tuple[int, ...] = ()


# ----------------------------------------------------------------------
# Rule Catalog
# ----------------------------------------------------------------------

RULE_BRUTE_FORCE = DetectionRule(
    rule_id="SEC-R01",
    name="Repeated Failed Logins (Brute Force)",
    severity=SeverityLevel.HIGH.value,
    description=(
        "Multiple failed authentication attempts detected for the same account "
        "and source IP within a sliding time window."
    ),
    mitre_attack_id="T1110",
    target_event_ids=(4625,),
)

RULE_AUDIT_LOG_CLEARED = DetectionRule(
    rule_id="SEC-R02",
    name="Security Audit Log Cleared",
    severity=SeverityLevel.CRITICAL.value,
    description=(
        "The Windows Security audit log was cleared (Event ID 1102 / 104). "
        "Adversaries frequently clear audit logs to remove forensic evidence."
    ),
    mitre_attack_id="T1070.001",
    target_event_ids=(1102, 104),
)

RULE_NEW_SERVICE = DetectionRule(
    rule_id="SEC-R03",
    name="New Windows Service Installed",
    severity=SeverityLevel.WARNING.value,
    description=(
        "A new service was installed in the system (Event ID 7045). "
        "Adversaries often install persistent services or backdoors."
    ),
    mitre_attack_id="T1543.003",
    target_event_ids=(7045,),
)

RULE_ACCOUNT_CREATED = DetectionRule(
    rule_id="SEC-R04",
    name="User Account Created",
    severity=SeverityLevel.WARNING.value,
    description=(
        "A new user account was created (Event ID 4720). "
        "Verify whether this administrative action was planned and authorized."
    ),
    mitre_attack_id="T1136.001",
    target_event_ids=(4720,),
)

RULE_PRIVILEGE_MODIFIED = DetectionRule(
    rule_id="SEC-R05",
    name="Account or Group Privileges Modified",
    severity=SeverityLevel.HIGH.value,
    description=(
        "A security-sensitive account modification occurred: an account was deleted, "
        "enabled, or a member was added to a privileged security group (Event IDs 4722, 4726, 4728, 4732)."
    ),
    mitre_attack_id="T1098",
    target_event_ids=(4722, 4726, 4728, 4732, 4756),
)

RULE_UNAUTHORIZED_ACCESS = DetectionRule(
    rule_id="SEC-R06",
    name="Unauthorized Access Attempt",
    severity=SeverityLevel.HIGH.value,
    description="Explicit unauthorized access attempt identified in application or system log.",
    mitre_attack_id="T1078",
)

RULE_PERMISSION_DENIED = DetectionRule(
    rule_id="SEC-R07",
    name="Permission-Denied Activity",
    severity=SeverityLevel.HIGH.value,
    description="Permission-denied or access-violation event recorded in log stream.",
    mitre_attack_id="T1069",
)

ALL_RULES = [
    RULE_BRUTE_FORCE,
    RULE_AUDIT_LOG_CLEARED,
    RULE_NEW_SERVICE,
    RULE_ACCOUNT_CREATED,
    RULE_PRIVILEGE_MODIFIED,
    RULE_UNAUTHORIZED_ACCESS,
    RULE_PERMISSION_DENIED,
]
