import unittest

from app.ingest import _parse_date


class FeedDateNormalizationTests(unittest.TestCase):
    def test_normalizes_rfc2822_datetime_with_timezone(self):
        self.assertEqual("2026-11-18", _parse_date("Wed, 18 Nov 2026 23:30:00 +0000"))

    def test_normalizes_date_only_rfc2822_value(self):
        self.assertEqual("2026-11-18", _parse_date("Wed, 18 Nov 2026"))

    def test_normalizes_iso8601_with_timezone(self):
        self.assertEqual("2026-11-20", _parse_date("2026-11-20T15:13:48+00:00"))


if __name__ == "__main__":
    unittest.main()
