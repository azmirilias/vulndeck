from tempfile import TemporaryDirectory
import unittest

from fastapi.testclient import TestClient

from app import db
from app.web import app


class BreachPageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.old_db_path = db.DB_PATH
        db.DB_PATH = f"{self.tmp.name}/test.db"
        db.init_db()
        with db.connect(write=True) as conn:
            conn.execute(
                "INSERT INTO breach(name,title,domain,breach_date,added_date,pwn_count,data_classes) "
                "VALUES(?,?,?,?,?,?,?)",
                ("ExampleBreach", "Example breach", "example.net", "2026-11-20", "2026-11-21T00:00:00", 42, "Email addresses"),
            )
            conn.execute(
                "INSERT INTO article(link,source,title,published,summary) VALUES(?,?,?,?,?)",
                ("https://dailydarkweb.net/example-report", "DailyDarkWeb", "Alleged breach report", "2026-11-21", "Publisher excerpt"),
            )
        self.client = TestClient(app)

    def tearDown(self):
        self.client.close()
        db.DB_PATH = self.old_db_path
        self.tmp.cleanup()

    def test_breach_page_separates_hibp_metadata_from_unverified_reports(self):
        response = self.client.get("/breaches")
        self.assertEqual(200, response.status_code)
        self.assertIn("Example breach", response.text)
        self.assertIn("Alleged breach report", response.text)
        self.assertIn("not independently verified", response.text.lower())


if __name__ == "__main__":
    unittest.main()
