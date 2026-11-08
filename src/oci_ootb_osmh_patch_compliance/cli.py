"""Command line interface for the patch compliance reporter."""

import argparse
import json
import sys

from datetime import datetime, timezone

from .compliance import PATCH_TYPES, audit_reports, load_export

EXIT_HIGH_FINDINGS = 2
EXIT_INPUT_ERROR = 1
EXIT_OK = 0


def _load(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except OSError as exc:
        raise ValueError(f"cannot read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path} is not valid JSON: {exc}") from exc


def _parse_time(value):
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _render(reports, findings, window):
    lines = []
    for report in reports:
        parts = ", ".join(f"{t.lower()} {report.pending[t]}" for t in PATCH_TYPES)
        lines.append(
            f"instance {report.name}: {report.total_pending} pending ({parts}), "
            f"oldest security patch {report.oldest_security_days} day(s)"
        )
    for finding in findings:
        lines.append(f"[{finding.severity:<6}] {finding.rule_id} {finding.instance}: {finding.message}")
    high = sum(1 for f in findings if f.severity == "HIGH")
    lines.append(
        f"summary: {len(reports)} instance(s), {len(findings)} finding(s), "
        f"{high} over the {window}-day security window"
    )
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="oci-ootb-osmh-patch-compliance",
        description="Offline patch compliance report for OS Management Hub exports.",
    )
    parser.add_argument("path", help="OSMH patch state JSON export")
    parser.add_argument("--window", type=int, default=14,
                        help="allowed age in days for the oldest pending SECURITY patch (default 14)")
    args = parser.parse_args(argv)

    try:
        document = _load(args.path)
        reference_time = _parse_time(document.get("reference_time")) or datetime.now(timezone.utc)
        reports = load_export(document, reference_time)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INPUT_ERROR

    findings = audit_reports(reports, args.window)
    print(_render(reports, findings, args.window))
    if any(f.severity == "HIGH" for f in findings):
        return EXIT_HIGH_FINDINGS
    return EXIT_OK
