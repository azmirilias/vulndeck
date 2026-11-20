import unittest

from app.web import _summary_retry_after


class SummaryCooldownTests(unittest.TestCase):
    def test_first_request_is_allowed_even_when_monotonic_clock_is_small(self):
        self.assertEqual(0, _summary_retry_after(None, 5.0))

    def test_recent_request_returns_remaining_cooldown(self):
        self.assertEqual(25, _summary_retry_after(10.0, 15.0))
        self.assertEqual(0, _summary_retry_after(10.0, 40.0))


if __name__ == "__main__":
    unittest.main()
