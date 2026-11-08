"""Patch compliance computation for OS Management Hub exports.

OS Management Hub (an out-of-the-box OCI feature) inventories managed
instances and their pending updates. This module works on a static JSON
export of that state: per instance it totals pending patches by type,
finds the oldest pending SECURITY patch, and flags instances that breach
the patch window. All analysis is offline; no OCI calls.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
PATCH_TYPES = ("SECURITY", "BUGFIX", "ENHANCEMENT")


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    instance: str
    message: str


@dataclass
class InstanceReport:
    name: str
    pending: dict = field(default_factory=lambda: {t: 0 for t in PATCH_TYPES})
    oldest_security_days: int = 0

    @property
    def total_pending(self):
        return sum(self.pending.values())


def _parse_time(value):
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def load_export(document, reference_time):
    """Parse the export and build per-instance reports."""
    if not isinstance(document, dict) or not isinstance(document.get("instances"), list):
        raise ValueError("document must contain a top-level 'instances' list")
    reports = {}
    for raw in document["instances"]:
        if not isinstance(raw, dict):
            raise ValueError("each instance entry must be an object")
        name = raw.get("name")
        if not name:
            raise ValueError("instance entry missing 'name'")
        report = reports.setdefault(str(name), InstanceReport(name=str(name)))
        patches = raw.get("pending_patches")
        if not isinstance(patches, list):
            raise ValueError(f"instance {name} missing 'pending_patches' list")
        for patch in patches:
            if not isinstance(patch, dict):
                raise ValueError(f"instance {name} has a non-object patch entry")
            ptype = str(patch.get("type", "")).upper()
            if ptype not in PATCH_TYPES:
                raise ValueError(f"instance {name} has patch with unknown type '{patch.get('type')}'")
            report.pending[ptype] += 1
            if ptype == "SECURITY":
                released = _parse_time(patch.get("released_at"))
                if released is not None:
                    age = (reference_time - released).days
                    report.oldest_security_days = max(report.oldest_security_days, age)
    return list(reports.values())


def audit_reports(reports, security_window_days):
    """Apply compliance rules to parsed reports."""
    findings = []
    for report in reports:
        if report.pending["SECURITY"] and report.oldest_security_days > security_window_days:
            findings.append(Finding(
                "PAT001", "HIGH", report.name,
                f"oldest pending SECURITY patch is {report.oldest_security_days} days old (window {security_window_days}); patch now",
            ))
        elif report.pending["SECURITY"]:
            findings.append(Finding(
                "PAT002", "MEDIUM", report.name,
                f"{report.pending['SECURITY']} SECURITY patch(es) pending within the {security_window_days}-day window",
            ))
        if report.total_pending >= 25:
            findings.append(Finding(
                "PAT003", "LOW", report.name,
                f"{report.total_pending} total patches pending; the instance is drifting from the baseline",
            ))
    return sorted(findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.rule_id, f.instance, f.message))
