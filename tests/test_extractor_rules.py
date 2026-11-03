"""
Extractor (permission resolution) and rule engine.
"""
import unittest

from rbacgraph.extractor import build_cluster, can
from rbacgraph.models import Subject
from rbacgraph.rules import CLUSTER_ADMIN, generate_edges
from tests.helpers import sample


class TestExtractor(unittest.TestCase):

    def setUp(self):
        self.cluster = build_cluster([sample("vulnerable_rbac.yaml")])

    def test_finds_three_service_accounts(self):
        names = {s.name for s in self.cluster.subjects()
                 if s.kind == "ServiceAccount"}
        self.assertTrue({"frontend", "deployer", "binder"}.issubset(names))

    def test_frontend_can_read_secrets(self):
        frontend = Subject("ServiceAccount", "frontend", "app")
        self.assertTrue(can(self.cluster, frontend, "", "secrets", "get"))

    def test_binder_can_create_rolebindings(self):
        binder = Subject("ServiceAccount", "binder", "app")
        self.assertTrue(can(self.cluster, binder,
                            "rbac.authorization.k8s.io", "rolebindings", "create"))

    def test_pod_service_account_mapping(self):
        self.assertTrue(any(p.service_account == "frontend" for p in self.cluster.pods))


class TestBuiltinAdminInjection(unittest.TestCase):

    def test_default_sa_bound_to_cluster_admin_resolves_to_wildcard(self):
        cluster = build_cluster([sample("default_sa_admin.yaml")])
        default_sa = Subject("ServiceAccount", "default", "default")
        # Wildcard permission means it matches any verb/resource.
        self.assertTrue(can(cluster, default_sa, "anything", "anything", "anything"))


class TestRuleEngine(unittest.TestCase):

    def test_vulnerable_has_edge_to_cluster_admin(self):
        cluster = build_cluster([sample("vulnerable_rbac.yaml")])
        edges = generate_edges(cluster)
        self.assertTrue(any(e.dst == CLUSTER_ADMIN for e in edges))

    def test_benign_has_no_edge_to_cluster_admin(self):
        cluster = build_cluster([sample("benign_rbac.yaml")])
        edges = generate_edges(cluster)
        self.assertFalse(any(e.dst == CLUSTER_ADMIN for e in edges))

    def test_read_secrets_creates_token_theft_edge(self):
        cluster = build_cluster([sample("vulnerable_rbac.yaml")])
        edges = generate_edges(cluster)
        rule_ids = {e.rule_id for e in edges}
        self.assertIn("read-secrets", rule_ids)
        self.assertIn("create-binding", rule_ids)


if __name__ == "__main__":
    unittest.main()
