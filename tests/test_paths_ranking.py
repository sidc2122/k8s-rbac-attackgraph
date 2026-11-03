"""
Correctness of attack-path discovery and risk ranking.

These lock in the expected results for every sample file, so the answer to
"how do you know your tool is correct?" is: a repeatable test suite.
"""
import unittest

from rbacgraph import service
from tests.helpers import sample


class TestSampleResults(unittest.TestCase):

    def _paths(self, name):
        return service.scan_yaml([sample(name)])["paths"]

    def test_vulnerable_finds_two_paths(self):
        paths = self._paths("vulnerable_rbac.yaml")
        self.assertEqual(len(paths), 2)

    def test_vulnerable_severities_and_risks(self):
        paths = self._paths("vulnerable_rbac.yaml")
        # Sorted by risk descending: HIGH (33.33) then MEDIUM (20.0).
        self.assertEqual(paths[0]["severity"], "HIGH")
        self.assertAlmostEqual(paths[0]["risk"], 33.33, places=2)
        self.assertEqual(paths[1]["severity"], "MEDIUM")
        self.assertAlmostEqual(paths[1]["risk"], 20.0, places=2)

    def test_vulnerable_top_path_is_two_hops(self):
        top = self._paths("vulnerable_rbac.yaml")[0]
        self.assertEqual(top["hops"], 2)
        self.assertEqual(top["entry"], "sa:app/frontend")

    def test_benign_finds_nothing(self):
        self.assertEqual(len(self._paths("benign_rbac.yaml")), 0)

    def test_default_sa_admin_is_critical_one_step(self):
        paths = self._paths("default_sa_admin.yaml")
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0]["severity"], "CRITICAL")
        self.assertEqual(paths[0]["hops"], 1)
        self.assertAlmostEqual(paths[0]["risk"], 100.0, places=2)

    def test_partial_fix_leaves_one_path(self):
        self.assertEqual(len(self._paths("fix_partial_rbac.yaml")), 1)

    def test_full_fix_leaves_no_paths(self):
        self.assertEqual(len(self._paths("fix_full_rbac.yaml")), 0)


class TestRankingProperties(unittest.TestCase):

    def test_paths_sorted_by_risk_descending(self):
        paths = service.scan_yaml([sample("vulnerable_rbac.yaml")])["paths"]
        risks = [p["risk"] for p in paths]
        self.assertEqual(risks, sorted(risks, reverse=True))

    def test_risk_equals_impact_over_effort(self):
        for p in service.scan_yaml([sample("vulnerable_rbac.yaml")])["paths"]:
            self.assertAlmostEqual(p["risk"], round(p["impact"] / p["effort"], 2),
                                   places=2)


if __name__ == "__main__":
    unittest.main()
