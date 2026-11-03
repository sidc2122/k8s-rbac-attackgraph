"""
Web app endpoints and service-level error handling.
"""
import io
import unittest

from rbacgraph import service
from rbacgraph.web import app
from tests.helpers import sample


class TestWebEndpoints(unittest.TestCase):

    def setUp(self):
        self.c = app.test_client()

    def test_home_page_loads(self):
        r = self.c.get("/")
        self.assertEqual(r.status_code, 200)

    def test_upload_vulnerable_returns_two_paths(self):
        with open(sample("vulnerable_rbac.yaml"), "rb") as f:
            r = self.c.post("/api/scan/upload",
                            data={"files": (f, "v.yaml")},
                            content_type="multipart/form-data")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(r.get_json()["paths"]), 2)

    def test_upload_malformed_returns_friendly_error(self):
        r = self.c.post("/api/scan/upload",
                        data={"files": (io.BytesIO(b"kind: x\n bad: [\n:::"), "x.yaml")},
                        content_type="multipart/form-data")
        self.assertEqual(r.status_code, 400)
        self.assertIn("error", r.get_json())

    def test_upload_no_file_is_rejected(self):
        r = self.c.post("/api/scan/upload", data={},
                        content_type="multipart/form-data")
        self.assertEqual(r.status_code, 400)

    def test_compare_endpoint(self):
        before = service.scan_yaml([sample("vulnerable_rbac.yaml")])["paths"]
        after = service.scan_yaml([sample("fix_full_rbac.yaml")])["paths"]
        r = self.c.post("/api/compare", json={"before": before, "after": after})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["summary"]["eliminated"], 2)


class TestServiceErrorHandling(unittest.TestCase):

    def test_friendly_error_for_connection_refused(self):
        msg = service._friendly_cluster_error(
            Exception("HTTPSConnectionPool ... Max retries exceeded ... refused"))
        self.assertIn("Docker", msg)

    def test_friendly_error_for_missing_client(self):
        msg = service._friendly_cluster_error(Exception("No module named 'kubernetes'"))
        self.assertIn("pip install kubernetes", msg)

    def test_list_contexts_returns_dict(self):
        result = service.list_contexts()
        self.assertIn("contexts", result)
        self.assertIsInstance(result["contexts"], list)


if __name__ == "__main__":
    unittest.main()
