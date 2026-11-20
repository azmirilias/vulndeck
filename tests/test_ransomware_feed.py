from tempfile import TemporaryDirectory
import unittest

from fastapi.testclient import TestClient

from app import db
from app.web import app


class RansomwareFeedTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.old_db_path = db.DB_PATH
        db.DB_PATH = f"{self.tmp.name}/test.db"
        db.init_db()
        with db.connect(write=True) as conn:
            conn.execute(
                "INSERT INTO ransomware(id,group_name,victim,discovered,sector,url,source) "
                "VALUES(?,?,?,?,?,?,?)",
                ("test-id", "TestGroup", "Example Victim", "2026-11-21", "health", "https://source.example/post", "ransomware.live"),
            )
        self.client = TestClient(app)

    def tearDown(self):
        self.client.close()
        db.DB_PATH = self.old_db_path
        self.tmp.cleanup()

    def test_ransomware_rss_contains_attributed_victim_metadata(self):
        response = self.client.get("/ransomware/feed.xml")
        self.assertEqual(200, response.status_code)
        self.assertIn("application/rss+xml", response.headers["content-type"])
        self.assertIn("Example Victim", response.text)
        self.assertIn("TestGroup", response.text)
        self.assertIn("https://source.example/post", response.text)


if __name__ == "__main__":
    unittest.main()
