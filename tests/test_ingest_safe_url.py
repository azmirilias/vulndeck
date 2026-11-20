import unittest

from app.ingest import is_safe_http_url


class FeedLinkSafetyTests(unittest.TestCase):
    def test_allows_http_and_https_urls_with_hosts(self):
        self.assertTrue(is_safe_http_url("https://example.com/report"))
        self.assertTrue(is_safe_http_url("http://example.net/feed"))

    def test_rejects_script_and_hostless_urls(self):
        self.assertFalse(is_safe_http_url("javascript:alert(1)"))
        self.assertFalse(is_safe_http_url("data:text/html,hello"))
        self.assertFalse(is_safe_http_url("/relative/path"))


if __name__ == "__main__":
    unittest.main()
