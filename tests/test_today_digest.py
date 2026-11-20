from datetime import datetime, timedelta, timezone
from tempfile import TemporaryDirectory
import unittest

from fastapi.testclient import TestClient

from app import db
from app.web import app


class TodayDigestTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.old_db_path = db.DB_PATH
        db.DB_PATH = f"{self.tmp.name}/test.db"
        db.init_db()
        today = datetime.now(timezone.utc).date().isoformat()
        yesterday = (datetime.now(timezone.utc).date() - timedelta(days=1)).isoformat()
        with db.connect(write=True) as conn:
            conn.execute(
                "INSERT INTO kev(cve_id,vendor,product,name,date_added) VALUES(?,?,?,?,?)",
                ("CVE-2026-11111", "Example", "Product", "Today CVE", today),
            )
            conn.execute(
                "INSERT INTO kev(cve_id,vendor,product,name,date_added) VALUES(?,?,?,?,?)",
                ("CVE-2026-11112", "Example", "Product", "Yesterday CVE", yesterday),
            )
            conn.execute(
                "INSERT INTO ransomware(id,group_name,victim,discovered) VALUES(?,?,?,?)",
                ("rw-today", "Group", "Today Victim", today),
            )
            conn.execute(
                "INSERT INTO ransomware(id,group_name,victim,discovered) VALUES(?,?,?,?)",
                ("rw-old", "Group", "Old Victim", yesterday),
            )
            conn.execute(
                "INSERT INTO breach(name,title,breach_date,added_date) VALUES(?,?,?,?)",
                ("today", "Today Breach", yesterday, today),
            )
            conn.execute(
                "INSERT INTO breach(name,title,breach_date,added_date) VALUES(?,?,?,?)",
                ("old", "Old Breach", yesterday, yesterday),
            )
            conn.execute(
                "INSERT INTO article(link,source,title,published) VALUES(?,?,?,?)",
                ("https://intel.example/today", "Feed", "Today Article", today),
            )
            conn.execute(
                "INSERT INTO article(link,source,title,published) VALUES(?,?,?,?)",
                ("https://intel.example/old", "Feed", "Old Article", yesterday),
            )
            conn.execute(
                "INSERT INTO poc(cve_id,repo,url,published) VALUES(?,?,?,?)",
                ("CVE-2026-11111", "owner/today-poc", "https://github.com/owner/today-poc", today),
            )
        self.client = TestClient(app)

    def tearDown(self):
        self.client.close()
        db.DB_PATH = self.old_db_path
        self.tmp.cleanup()

    def test_today_digest_excludes_older_records(self):
        response = self.client.get("/today")
        self.assertEqual(200, response.status_code)
        self.assertIn("Today CVE", response.text)
        self.assertIn("Today Victim", response.text)
        self.assertIn("Today Breach", response.text)
        self.assertIn("Today Article", response.text)
        self.assertNotIn("Yesterday CVE", response.text)
        self.assertNotIn("Old Victim", response.text)
        self.assertNotIn("Old Breach", response.text)
        self.assertNotIn("Old Article", response.text)


if __name__ == "__main__":
    unittest.main()
