import unittest
from tempfile import TemporaryDirectory

from fastapi.testclient import TestClient

from app import db
from app.web import app


class AboutAuthorPageTests(unittest.TestCase):
    def test_about_page_introduces_azmir_as_author_and_owner(self):
        with TemporaryDirectory() as tmp:
            old_db_path = db.DB_PATH
            db.DB_PATH = f"{tmp}/test.db"
            try:
                db.init_db()
                with TestClient(app) as client:
                    response = client.get("/about")
            finally:
                db.DB_PATH = old_db_path
        self.assertEqual(200, response.status_code)
        self.assertIn("Author and owner", response.text)
        self.assertIn("Azmir Ilias", response.text)
        self.assertIn("https://www.azmirilias.com", response.text)
        self.assertIn("Malaysia", response.text)


if __name__ == "__main__":
    unittest.main()
