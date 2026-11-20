from tempfile import TemporaryDirectory
import unittest

from fastapi.testclient import TestClient

from app import db
from app.web import app


class IocSearchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.old_db_path = db.DB_PATH
        db.DB_PATH = f"{self.tmp.name}/test.db"
        db.init_db()
        with db.connect(write=True) as conn:
            conn.execute(
                "INSERT INTO article(link,source,title,published) VALUES(?,?,?,?)",
                ("https://intel.example/story", "Feed", "Threat report", "2026-11-21"),
            )
            conn.execute(
                "INSERT INTO article_ioc(article_link,ioc_type,ioc_value) VALUES(?,?,?)",
                ("https://intel.example/story", "domain", "bad.example.net"),
            )
        self.client = TestClient(app)

    def tearDown(self):
        self.client.close()
        db.DB_PATH = self.old_db_path
        self.tmp.cleanup()

    def test_search_finds_articles_by_extracted_indicator(self):
        response = self.client.get("/search", params={"q": "bad.example.net"})
        self.assertEqual(200, response.status_code)
        self.assertIn("Threat report", response.text)


if __name__ == "__main__":
    unittest.main()
