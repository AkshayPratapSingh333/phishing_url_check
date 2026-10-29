"""
Integration tests for the inspector façade.

These tests exercise the full pipeline: parsing → rule engine →
InspectionResult construction.  They verify the same sample URLs
from the workbook test evidence table.
"""

import pytest

from src.models import Severity, InspectionResult
from src.inspector import inspect_url, inspect_url_simple


class TestInspectUrlIntegration:
    """End-to-end tests matching the workbook test table."""

    def test_clean_https_url_no_warnings(self):
        """Workbook row 1: https://www.example.com/login"""
        result = inspect_url("https://www.example.com/login")
        assert result.error is None
        assert result.hostname == "www.example.com"
        assert not result.has_warnings
        assert result.warning_count == 0
        assert any("NOT prove" in f.message for f in result.findings)

    def test_at_symbol_and_http(self):
        """Workbook row 2: http://example.com@sample.invalid"""
        result = inspect_url("http://example.com@sample.invalid")
        assert result.hostname == "sample.invalid"
        rule_ids = {f.rule_id for f in result.findings}
        assert "AT_SYMBOL" in rule_ids
        assert "HTTP_SCHEME" in rule_ids

    def test_long_url(self):
        """Workbook row 3: URL over 100 characters."""
        long_url = "https://www.example.com/" + "a" * 100
        result = inspect_url(long_url)
        assert any(f.rule_id == "LONG_URL" for f in result.findings)

    def test_ip_hostname(self):
        """Workbook row 4: https://192.168.1.1/login"""
        result = inspect_url("https://192.168.1.1/login")
        assert any(f.rule_id == "IP_HOSTNAME" for f in result.findings)
        assert result.hostname == "192.168.1.1"

    def test_many_hostname_segments(self):
        """Workbook row 5: https://a.b.c.d.e.example.invalid"""
        result = inspect_url("https://a.b.c.d.e.example.invalid")
        assert any(f.rule_id == "MANY_SEGMENTS" for f in result.findings)

    def test_punycode_hostname(self):
        """Workbook row 6: https://xn--exmple-cua.com"""
        result = inspect_url("https://xn--exmple-cua.com")
        assert any(f.rule_id == "PUNYCODE" for f in result.findings)

    def test_http_scheme_only_when_typed(self):
        """Workbook row 7 & 10: HTTP flagged only when user typed it."""
        with_http = inspect_url("http://www.example.com/login")
        assert any(f.rule_id == "HTTP_SCHEME" for f in with_http.findings)

        without_scheme = inspect_url("www.example.com/login")
        assert not any(
            f.rule_id == "HTTP_SCHEME" for f in without_scheme.findings
        )

    def test_percent_encoded_at(self):
        """Workbook row 8: https://example.com%40sample.invalid"""
        result = inspect_url("https://example.com%40sample.invalid")
        assert any(f.rule_id == "AT_SYMBOL" for f in result.findings)


class TestInspectUrlEdgeCases:
    """Edge cases and error handling."""

    def test_empty_input(self):
        result = inspect_url("")
        assert result.error == "No URL entered."
        assert len(result.findings) == 0

    def test_whitespace_input(self):
        result = inspect_url("   \t  ")
        assert result.error == "No URL entered."

    def test_malformed_url_returns_error(self):
        result = inspect_url("http://[bad")
        assert result.error == "Could not parse the URL."
        assert result.findings == []

    def test_multiple_warnings_combined(self):
        """A URL with many warning signs triggers all matching rules."""
        nasty_url = (
            "http://xn--evil.a.b.c.d.e.192.168.1.1.example.com@evil.invalid/"
            + "x" * 200
        )
        result = inspect_url(nasty_url)
        rule_ids = {f.rule_id for f in result.findings}
        assert "AT_SYMBOL" in rule_ids
        assert "LONG_URL" in rule_ids
        assert "HTTP_SCHEME" in rule_ids

    def test_is_safe_always_false(self):
        """The is_safe field must NEVER be True."""
        safe_result = inspect_url("https://www.example.com")
        assert safe_result.is_safe is False

        unsafe_result = inspect_url("http://192.168.1.1")
        assert unsafe_result.is_safe is False


class TestInspectUrlSimpleBackwardCompat:
    """Tests for the backward-compatible simple API."""

    def test_returns_list_of_strings(self):
        messages = inspect_url_simple("https://www.example.com")
        assert isinstance(messages, list)
        assert all(isinstance(m, str) for m in messages)

    def test_empty_input_returns_error(self):
        messages = inspect_url_simple("")
        assert messages == ["No URL entered."]

    def test_warning_returns_message_text(self):
        messages = inspect_url_simple("https://192.168.1.1/login")
        assert any("IP address" in m for m in messages)


class TestInspectionResultProperties:
    """Tests for computed properties on InspectionResult."""

    def test_max_severity_with_warnings(self):
        result = inspect_url("http://192.168.1.1/login")
        assert result.max_severity.value >= Severity.MEDIUM.value

    def test_max_severity_no_warnings(self):
        result = inspect_url("https://www.example.com/login")
        assert result.max_severity == Severity.INFO

    def test_warning_count(self):
        result = inspect_url("http://example.com@evil.invalid")
        assert result.warning_count >= 2  # @ and HTTP
