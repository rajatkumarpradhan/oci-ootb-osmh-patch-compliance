import io
import os
import unittest
from contextlib import redirect_stderr, redirect_stdout

from oci_ootb_osmh_patch_compliance.cli import main

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestCli(unittest.TestCase):
    def test_missing_file_exits_1(self):
        with redirect_stderr(io.StringIO()):
            self.assertEqual(main(["/nonexistent/patches.json"]), 1)

    def test_invalid_json_exits_1(self):
        with redirect_stderr(io.StringIO()):
            self.assertEqual(main([os.path.join(ROOT, "pyproject.toml")]), 1)

    def test_overdue_sample_exits_2_and_flags_db1(self):
        out = io.StringIO()
        with redirect_stdout(out):
            code = main([os.path.join(ROOT, "samples", "patch-state-overdue.json")])
        self.assertEqual(code, 2)
        text = out.getvalue()
        self.assertIn("PAT001 db-1", text)
        self.assertIn("PAT002 app-2", text)
        self.assertIn("PAT003 cache-1", text)
        self.assertIn("bastion-1: 0 pending", text)
        self.assertIn("summary:", text)

    def test_healthy_sample_exits_0(self):
        out = io.StringIO()
        with redirect_stdout(out):
            code = main([os.path.join(ROOT, "samples", "patch-state-healthy.json")])
        self.assertEqual(code, 0)
        self.assertIn("0 over", out.getvalue())

    def test_wider_window_passes_overdue_sample(self):
        with redirect_stdout(io.StringIO()):
            code = main([os.path.join(ROOT, "samples", "patch-state-overdue.json"), "--window", "60"])
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
