from tempfile import TemporaryDirectory
import unittest
from urllib.parse import quote

from fastapi.testclient import TestClient

from app import db
from app.web import app


class IntelArticlePageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.old_db_path = db.DB_PATH
        db.DB_PATH = f"{self.tmp.name}/test.db"
        db.init_db()
        self.link = "https://intel.example/research"
        with db.connect(write=True) as conn:
            conn.execute(
                "INSERT INTO article(link,source,title,published,summary) VALUES(?,?,?,?,?)",
                (self.link, "Research Feed", "Threat report", "2026-11-21", "An excerpt mentioning indicators."),
            )
            conn.executemany(
                "INSERT INTO article_ioc(article_link,ioc_type,ioc_value) VALUES(?,?,?)",
                [(self.link, "cve", "CVE-2026-12345"), (self.link, "domain", "bad.example.net"), (self.link, "ip", "8.8.8.8")],
            )
        self.client = TestClient(app)

    def tearDown(self):
        self.client.close()
        db.DB_PATH = self.old_db_path
        self.tmp.cleanup()

    def test_article_page_shows_tagged_unverified_indicators(self):
        response = self.client.get("/intel/article", params={"link": self.link})
        self.assertEqual(200, response.status_code)
        self.assertIn("Threat report", response.text)
        self.assertIn("CVE-2026-12345", response.text)
        self.assertIn("bad.example.net", response.text)
        self.assertIn("8.8.8.8", response.text)
        self.assertIn("unverified", response.text.lower())


if __name__ == "__main__":
    unittest.main()
