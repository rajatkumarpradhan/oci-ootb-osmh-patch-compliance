import unittest
from datetime import datetime, timezone

from oci_ootb_osmh_patch_compliance.compliance import audit_reports, load_export

REF = datetime(2026, 11, 9, tzinfo=timezone.utc)


def patch(ptype, released="2026-11-08T00:00:00Z"):
    return {"type": ptype, "released_at": released}


def instance(name, patches):
    return {"name": name, "pending_patches": patches}


class TestLoadExport(unittest.TestCase):
    def test_valid_export_parses(self):
        reports = load_export({"instances": [instance("a", [patch("SECURITY")])]}, REF)
        self.assertEqual(len(reports), 1)
        self.assertEqual(reports[0].pending["SECURITY"], 1)

    def test_missing_instances_list_rejected(self):
        with self.assertRaises(ValueError):
            load_export({"items": []}, REF)

    def test_non_object_instance_rejected(self):
        with self.assertRaises(ValueError):
            load_export({"instances": ["junk"]}, REF)

    def test_missing_name_rejected(self):
        with self.assertRaises(ValueError):
            load_export({"instances": [{"pending_patches": []}]}, REF)

    def test_missing_patch_list_rejected(self):
        with self.assertRaises(ValueError):
            load_export({"instances": [{"name": "a"}]}, REF)

    def test_unknown_patch_type_rejected(self):
        with self.assertRaises(ValueError):
            load_export({"instances": [instance("a", [patch("CRITICAL")])]}, REF)

    def test_oldest_security_age_computed(self):
        patches = [patch("SECURITY", "2026-10-01T00:00:00Z"), patch("SECURITY", "2026-11-05T00:00:00Z")]
        report = load_export({"instances": [instance("a", patches)]}, REF)[0]
        self.assertEqual(report.oldest_security_days, 39)

    def test_patch_type_case_normalised(self):
        report = load_export({"instances": [instance("a", [patch("security")])]}, REF)[0]
        self.assertEqual(report.pending["SECURITY"], 1)


class TestAuditReports(unittest.TestCase):
    def test_pat001_over_window(self):
        patches = [patch("SECURITY", "2026-09-01T00:00:00Z")]
        reports = load_export({"instances": [instance("a", patches)]}, REF)
        findings = audit_reports(reports, 14)
        self.assertEqual(findings[0].rule_id, "PAT001")
        self.assertEqual(findings[0].severity, "HIGH")

    def test_pat002_within_window(self):
        patches = [patch("SECURITY", "2026-11-05T00:00:00Z")]
        reports = load_export({"instances": [instance("a", patches)]}, REF)
        findings = audit_reports(reports, 14)
        self.assertEqual(findings[0].rule_id, "PAT002")
        self.assertEqual(findings[0].severity, "MEDIUM")

    def test_no_security_patches_no_findings(self):
        reports = load_export({"instances": [instance("a", [patch("BUGFIX")])]}, REF)
        self.assertEqual(audit_reports(reports, 14), [])

    def test_pat003_drift(self):
        reports = load_export({"instances": [instance("a", [patch("BUGFIX")] * 30)]}, REF)
        findings = audit_reports(reports, 14)
        self.assertEqual(findings[0].rule_id, "PAT003")

    def test_window_is_tunable(self):
        patches = [patch("SECURITY", "2026-11-01T00:00:00Z")]  # 8 days old
        reports = load_export({"instances": [instance("a", patches)]}, REF)
        # With a 30-day window the same patch is inside the window (PAT002)...
        findings = audit_reports(reports, 30)
        self.assertEqual([f.rule_id for f in findings], ["PAT002"])
        # ...and with a 7-day window it breaches (PAT001).
        findings = audit_reports(reports, 7)
        self.assertEqual(findings[0].rule_id, "PAT001")

    def test_findings_sorted_high_first(self):
        reports = load_export({"instances": [
            instance("overdue", [patch("SECURITY", "2026-08-01T00:00:00Z")]),
            instance("recent", [patch("SECURITY", "2026-11-08T00:00:00Z")]),
        ]}, REF)
        findings = audit_reports(reports, 14)
        self.assertEqual(findings[0].severity, "HIGH")
        self.assertEqual(findings[-1].severity, "MEDIUM")


if __name__ == "__main__":
    unittest.main()
