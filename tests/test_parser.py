"""
Unit tests for the URL parser module.

Tests cover normalisation, hostname extraction, scheme detection,
label splitting, and edge cases (empty input, missing scheme,
percent-encoded characters).
"""

import pytest

from src.parser import parse_url, ParsedURL


class TestParseUrlBasic:
    """Tests for basic parsing behaviour."""

    def test_returns_none_for_empty_string(self):
        assert parse_url("") is None

    def test_returns_none_for_whitespace_only(self):
        assert parse_url("   \t\n  ") is None

    def test_strips_whitespace(self):
        result = parse_url("  https://example.com  ")
        assert result is not None
        assert result.original == "https://example.com"

    def test_https_scheme_detected(self):
        result = parse_url("https://www.example.com/login")
        assert result is not None
        assert result.scheme == "https"
        assert result.user_typed_scheme is True

    def test_http_scheme_detected(self):
        result = parse_url("http://www.example.com/login")
        assert result is not None
        assert result.scheme == "http"
        assert result.user_typed_scheme is True

    def test_missing_scheme_adds_http_for_parsing(self):
        result = parse_url("www.example.com/login")
        assert result is not None
        assert result.user_typed_scheme is False
        assert result.normalised.startswith("http://")

    def test_hostname_extraction(self):
        result = parse_url("https://www.example.com/path?q=1")
        assert result is not None
        assert result.hostname == "www.example.com"

    def test_hostname_is_lowercase(self):
        result = parse_url("https://WWW.EXAMPLE.COM")
        assert result is not None
        assert result.hostname == "www.example.com"


class TestParseUrlLabels:
    """Tests for hostname label splitting."""

    def test_three_labels(self):
        result = parse_url("https://www.example.com")
        assert result is not None
        assert result.hostname_labels == ("www", "example", "com")

    def test_single_label(self):
        result = parse_url("http://localhost/path")
        assert result is not None
        assert result.hostname_labels == ("localhost",)

    def test_many_labels(self):
        result = parse_url("https://a.b.c.d.e.f.example.com")
        assert result is not None
        assert len(result.hostname_labels) == 8


class TestParseUrlDecoding:
    """Tests for percent-decoded URL."""

    def test_percent_encoded_at_is_decoded(self):
        result = parse_url("https://example.com%40evil.invalid")
        assert result is not None
        assert "@" in result.decoded

    def test_normal_url_decoded_matches(self):
        result = parse_url("https://example.com/path")
        assert result is not None
        assert result.decoded == result.normalised


class TestParseUrlLength:
    """Tests for full_length tracking."""

    def test_length_matches_stripped_input(self):
        url = "https://example.com/path"
        result = parse_url(f"  {url}  ")
        assert result is not None
        assert result.full_length == len(url)
