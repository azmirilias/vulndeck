import unittest

from app import ingest


class ExtractIocsTests(unittest.TestCase):
    def test_extracts_cve_public_ipv4_and_domain_mentions(self):
        found = ingest.extract_iocs(
            "CVE-2026-12345 contacted 8.8.8.8, 203.0.113.7 and bad.example.net"
        )
        self.assertIn(("cve", "CVE-2026-12345"), found)
        self.assertIn(("domain", "bad.example.net"), found)

    def test_does_not_publish_private_or_reserved_addresses_as_iocs(self):
        found = ingest.extract_iocs(
            "10.0.0.8 192.168.1.2 127.0.0.1 999.999.999.999 203.0.113.7"
        )
        self.assertFalse(any(kind == "ip" for kind, _ in found))

    def test_deduplicates_and_lowercases_domain_mentions(self):
        found = ingest.extract_iocs("Bad.Example.net bad.example.net")
        self.assertEqual([("domain", "bad.example.net")], found)

    def test_ignores_documentation_domains(self):
        found = ingest.extract_iocs("example.com example.org")
        self.assertEqual([], found)


if __name__ == "__main__":
    unittest.main()
