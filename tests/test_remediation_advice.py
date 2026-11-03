"""
Remediation validation and fix-advice generation.
"""
import unittest

from rbacgraph import service
from tests.helpers import sample


def paths(name):
    return service.scan_yaml([sample(name)])["paths"]


class TestRemediationDiff(unittest.TestCase):

    def test_partial_fix_one_eliminated_one_remaining(self):
        d = service.compare(paths("vulnerable_rbac.yaml"),
                            paths("fix_partial_rbac.yaml"))
        self.assertEqual(d["summary"]["eliminated"], 1)
        self.assertEqual(d["summary"]["remaining"], 1)
        self.assertEqual(d["summary"]["introduced"], 0)

    def test_full_fix_all_eliminated(self):
        d = service.compare(paths("vulnerable_rbac.yaml"),
                            paths("fix_full_rbac.yaml"))
        self.assertEqual(d["summary"]["eliminated"], 2)
        self.assertEqual(d["summary"]["remaining"], 0)
        self.assertEqual(d["summary"]["introduced"], 0)

    def test_regression_is_detected_as_introduced(self):
        # Going from the fixed config back to the vulnerable one should look
        # like new paths were introduced.
        d = service.compare(paths("fix_full_rbac.yaml"),
                            paths("vulnerable_rbac.yaml"))
        self.assertEqual(d["summary"]["introduced"], 2)
        self.assertEqual(d["summary"]["eliminated"], 0)


class TestFixAdvice(unittest.TestCase):

    def test_each_path_has_fix_advice(self):
        for p in paths("vulnerable_rbac.yaml"):
            self.assertIn("fixes", p)
            self.assertTrue(p["fixes"]["steps"])

    def test_recommended_step_has_actionable_fix(self):
        p = paths("vulnerable_rbac.yaml")[0]
        step = p["fixes"]["steps"][p["fixes"]["recommended"]]
        rec = step["recommended"]
        # Recommended fix must be actionable: either a scope example or a command.
        self.assertTrue(rec.get("example") or rec.get("commands"))

    def test_scope_is_preferred_for_secret_reads(self):
        # The frontend's secret-read step should recommend scoping, not deletion,
        # so the app keeps working.
        step0 = paths("vulnerable_rbac.yaml")[0]["fixes"]["steps"][0]
        self.assertIn("Scope", step0["recommended"]["approach"])
        # Removal is still offered as an alternative, with the real command.
        self.assertIsNotNone(step0["alternative"])
        self.assertTrue(step0["alternative"]["commands"])

    def test_command_targets_the_real_binding(self):
        p = paths("vulnerable_rbac.yaml")[0]
        cmds = []
        for s in p["fixes"]["steps"]:
            for block in (s["recommended"], s["alternative"]):
                if block:
                    cmds += block.get("commands", [])
        self.assertIn("frontend-secret-reader", " ".join(cmds))


class TestEveryRuleHasProperGuidance(unittest.TestCase):

    def test_no_rule_is_delete_only(self):
        # Every escalation rule must offer a proper least-privilege fix
        # (scope down, replace, or restrict) - never only "delete".
        from rbacgraph.advice import RULE_FIX
        for rid, meta in RULE_FIX.items():
            has_proper = meta.get("scope") or meta.get("replace") or meta.get("restrict")
            self.assertTrue(has_proper, f"rule '{rid}' only offers deletion")

    def test_every_recommended_fix_has_example_or_command(self):
        # Across all sample findings, the recommended fix is always actionable.
        for name in ("vulnerable_rbac.yaml", "default_sa_admin.yaml"):
            for p in paths(name):
                for s in p["fixes"]["steps"]:
                    rec = s["recommended"]
                    self.assertTrue(rec.get("example") or rec.get("commands"),
                                    f"{name}: a recommended fix was not actionable")


if __name__ == "__main__":
    unittest.main()
