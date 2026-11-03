"""
Input robustness (never crash on bad input) and scalability (no hang on large
dense clusters).
"""
import os
import tempfile
import time
import unittest

from rbacgraph import service
from rbacgraph.extractor import InvalidInputError


def _scan_text(content, binary=False):
    d = tempfile.mkdtemp()
    p = os.path.join(d, "t.yaml")
    with open(p, "wb" if binary else "w") as f:
        f.write(content)
    return service.scan_yaml([p])


class TestBadInputNeverCrashes(unittest.TestCase):

    def test_empty_file(self):
        self.assertEqual(len(_scan_text("")["paths"]), 0)

    def test_non_kubernetes_yaml_gives_warning(self):
        r = _scan_text("shopping:\n  - milk\n  - eggs")
        self.assertEqual(len(r["paths"]), 0)
        self.assertIn("warning", r)

    def test_plain_text_does_not_crash(self):
        self.assertEqual(len(_scan_text("just some text")["paths"]), 0)

    def test_list_document_does_not_crash(self):
        self.assertEqual(len(_scan_text("- a\n- b\n- c")["paths"]), 0)

    def test_malformed_yaml_raises_friendly_error(self):
        with self.assertRaises(InvalidInputError):
            _scan_text("kind: Role\n  bad: [indent\nrules: :::")

    def test_binary_file_raises_friendly_error(self):
        with self.assertRaises(InvalidInputError):
            _scan_text(b"\x00\x01\x02\xff\xfe", binary=True)

    def test_malformed_objects_are_skipped(self):
        # rules not a list, roleRef a string, metadata a string - none crash.
        content = (
            "kind: Role\nmetadata: justtext\n---\n"
            "kind: RoleBinding\nmetadata:\n  name: b\n  namespace: n\n"
            "roleRef: oops\nsubjects: []\n"
        )
        self.assertEqual(len(_scan_text(content)["paths"]), 0)


class TestScalability(unittest.TestCase):

    def test_large_dense_cluster_completes_quickly(self):
        n = 200
        lines = []
        for i in range(n):
            lines.append(f"---\napiVersion: v1\nkind: ServiceAccount\n"
                         f"metadata:\n  name: sa{i}\n  namespace: big")
            lines.append(f"---\napiVersion: rbac.authorization.k8s.io/v1\n"
                         f"kind: Role\nmetadata:\n  name: r{i}\n  namespace: big\n"
                         f"rules:\n- apiGroups: [\"\"]\n  resources: [\"secrets\"]\n"
                         f"  verbs: [\"get\"]")
            lines.append(f"---\napiVersion: rbac.authorization.k8s.io/v1\n"
                         f"kind: RoleBinding\nmetadata:\n  name: rb{i}\n  namespace: big\n"
                         f"subjects:\n- kind: ServiceAccount\n  name: sa{i}\n"
                         f"  namespace: big\nroleRef:\n  kind: Role\n  name: r{i}\n"
                         f"  apiGroup: rbac.authorization.k8s.io")
            lines.append(f"---\napiVersion: v1\nkind: Pod\nmetadata:\n  name: p{i}\n"
                         f"  namespace: big\nspec:\n  serviceAccountName: sa{i}")
        # one account with a real route to admin -> the case that used to hang
        lines.append("---\napiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\n"
                     "metadata:\n  name: maker\nrules:\n- apiGroups: [\"rbac.authorization.k8s.io\"]\n"
                     "  resources: [\"clusterrolebindings\"]\n  verbs: [\"create\"]")
        lines.append("---\napiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\n"
                     "metadata:\n  name: sa0-maker\nsubjects:\n- kind: ServiceAccount\n"
                     "  name: sa0\n  namespace: big\nroleRef:\n  kind: ClusterRole\n"
                     "  name: maker\n  apiGroup: rbac.authorization.k8s.io")

        d = tempfile.mkdtemp()
        p = os.path.join(d, "big.yaml")
        with open(p, "w") as fh:
            fh.write("\n".join(lines))

        start = time.time()
        r = service.scan_yaml([p])
        elapsed = time.time() - start

        self.assertLess(elapsed, 30, "large dense cluster should not hang")
        self.assertGreater(len(r["paths"]), 0, "should still find the real route")


if __name__ == "__main__":
    unittest.main()
