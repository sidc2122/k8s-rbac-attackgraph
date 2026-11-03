"""Tests for the evaluation harness."""
import unittest

from rbacgraph import service
from rbacgraph.evaluate import build_report
from tests.helpers import sample


class TestEvaluationReport(unittest.TestCase):

    def setUp(self):
        self.result = service.scan_yaml([sample("vulnerable_rbac.yaml")])
        self.report = build_report(self.result, "samples/vulnerable_rbac.yaml")

    def test_report_has_all_sections(self):
        for section in ("Methodology", "capability", "KubeScape",
                        "Discussion", "References"):
            self.assertIn(section, self.report)

    def test_report_includes_our_real_result(self):
        # The two-path finding must appear in the auto-filled output.
        self.assertIn("Attack paths found: **2**", self.report)
        self.assertIn("HIGH", self.report)

    def test_capability_table_marks_chaining_as_our_advantage(self):
        self.assertIn("Chains permissions into multi-step attack paths", self.report)


if __name__ == "__main__":
    unittest.main()
