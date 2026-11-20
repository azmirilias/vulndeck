from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from app import db, web
from app.web import app


class SummaryRateLimitTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.old_db_path = db.DB_PATH
        db.DB_PATH = f"{self.tmp.name}/test.db"
        web._summary_last.clear()
        db.init_db()
        with db.connect(write=True) as conn:
            for slug in ("one", "two"):
                conn.execute(
                    "INSERT INTO article(link,source,title,summary) VALUES(?,?,?,?)",
                    (f"https://intel.example/{slug}", "Feed", f"Article {slug}", "Public excerpt"),
                )
        self.client = TestClient(app)

    def tearDown(self):
        self.client.close()
        db.DB_PATH = self.old_db_path
        self.tmp.cleanup()

    @patch("app.web._ai_summary", return_value="- Summary generated")
    def test_summary_generation_is_limited_per_client(self, generate):
        first = self.client.get("/intel/summary", params={"link": "https://intel.example/one"})
        second = self.client.get("/intel/summary", params={"link": "https://intel.example/two"})
        self.assertEqual(200, first.status_code)
        self.assertIn("Summary generated", first.text)
        self.assertEqual(429, second.status_code)
        self.assertEqual(1, generate.call_count)


if __name__ == "__main__":
    unittest.main()
