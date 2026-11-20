from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from app import db
from app.web import app


class CvePagePocTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.old_db_path = db.DB_PATH
        db.DB_PATH = f"{self.tmp.name}/test.db"
        db.init_db()
        with db.connect(write=True) as conn:
            conn.execute(
                "INSERT INTO epss(cve_id,score,percentile) VALUES(?,?,?)",
                ("CVE-2026-12345", 0.01, 0.5),
            )
        self.client = TestClient(app)

    def tearDown(self):
        self.client.close()
        db.DB_PATH = self.old_db_path
        self.tmp.cleanup()

    @patch("httpx.Client")
    def test_cve_page_does_not_call_github_during_page_render(self, fetch):
        response = self.client.get("/cve/CVE-2026-12345")
        self.assertEqual(200, response.status_code)
        fetch.assert_not_called()


if __name__ == "__main__":
    unittest.main()
