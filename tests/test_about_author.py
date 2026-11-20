import unittest

from fastapi.testclient import TestClient

from app.web import app


class AboutAuthorPageTests(unittest.TestCase):
    def test_about_page_introduces_azmir_as_author_and_owner(self):
        with TestClient(app) as client:
            response = client.get("/about")
        self.assertEqual(200, response.status_code)
        self.assertIn("Author and owner", response.text)
        self.assertIn("Azmir Ilias", response.text)
        self.assertIn("https://www.azmirilias.com", response.text)
        self.assertIn("Malaysia", response.text)


if __name__ == "__main__":
    unittest.main()
