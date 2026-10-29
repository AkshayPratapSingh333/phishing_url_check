"""
Legacy test file — backward-compatible tests for the original API.

These tests use the new ``src.inspector`` module but maintain the
same test structure as the original ``test_phishing_checker.py``.
"""

import unittest

from src.inspector import inspect_url_simple
from src.parser import parse_url


# Backward-compatible aliases
def inspect_url(raw_url):
    return inspect_url_simple(raw_url)


def parsed_hostname(raw_url):
    result = parse_url(raw_url)
    return result.hostname if result else None


SAFE_MESSAGE = (
    "No listed warning signs were detected. "
    "This does NOT prove the URL is safe. Attackers can "
    "craft URLs that avoid all six checks."
)


class InspectUrlTests(unittest.TestCase):
    def test_https_example_has_no_listed_warnings(self):
        findings = inspect_url("https://www.example.com/login")
        self.assertEqual(findings, [SAFE_MESSAGE])

    def test_at_symbol_and_http(self):
        findings = inspect_url("http://example.com@sample.invalid")
        self.assertTrue(any("@" in item for item in findings))
        self.assertTrue(any("HTTP" in item for item in findings))

    def test_percent_encoded_at_symbol(self):
        findings = inspect_url("https://example.com%40sample.invalid")
        self.assertTrue(any("@" in item for item in findings))

    def test_long_url(self):
        long_url = "https://www.example.com/" + ("a" * 100)
        findings = inspect_url(long_url)
        self.assertTrue(any("long" in item.lower() for item in findings))

    def test_ipv4_hostname(self):
        findings = inspect_url("https://192.168.1.1/login")
        self.assertTrue(any("IP address" in item for item in findings))

    def test_many_hostname_segments(self):
        findings = inspect_url("https://a.b.c.d.e.example.invalid")
        self.assertTrue(any("segment" in item.lower() for item in findings))

    def test_punycode_marker(self):
        findings = inspect_url("https://xn--exmple-cua.com")
        self.assertTrue(any("punycode" in item.lower() for item in findings))

    def test_http_scheme_only_when_typed(self):
        without_scheme = inspect_url("www.example.com/login")
        self.assertEqual(without_scheme, [SAFE_MESSAGE])
        with_http = inspect_url("http://www.example.com/login")
        self.assertTrue(any("HTTP" in item for item in with_http))

    def test_empty_input(self):
        self.assertEqual(inspect_url("   "), ["No URL entered."])

    def test_parsed_hostname(self):
        self.assertEqual(
            parsed_hostname("https://www.example.com/login"),
            "www.example.com",
        )


if __name__ == "__main__":
    unittest.main()
