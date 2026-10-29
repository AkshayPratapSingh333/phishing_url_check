"""
Unit tests for individual URL inspection rules.

Each rule class is tested in isolation with crafted ParsedURL
inputs. Tests verify both positive matches (rule fires) and
negative matches (rule returns None).
"""

import pytest

from src.models import Severity
from src.parser import parse_url
from src.rules.at_symbol import AtSymbolRule
from src.rules.long_url import LongURLRule
from src.rules.ip_hostname import IPHostnameRule
from src.rules.many_segments import ManySegmentsRule
from src.rules.punycode import PunycodeRule
from src.rules.http_scheme import HTTPSchemeRule


# ── Helper ────────────────────────────────────────────────────

def _parse(url: str):
    """Convenience: parse a URL and assert it's not None."""
    result = parse_url(url)
    assert result is not None, f"parse_url returned None for: {url!r}"
    return result


# ══════════════════════════════════════════════════════════════
# Rule 1: @ Symbol
# ══════════════════════════════════════════════════════════════

class TestAtSymbolRule:
    rule = AtSymbolRule()

    @pytest.mark.parametrize("url", [
        "http://example.com@evil.invalid",
        "https://user:pass@evil.invalid",
        "https://example.com%40evil.invalid",  # percent-encoded @
    ])
    def test_detects_at_symbol(self, url):
        finding = self.rule.check(_parse(url))
        assert finding is not None
        assert finding.rule_id == "AT_SYMBOL"
        assert finding.severity == Severity.HIGH

    @pytest.mark.parametrize("url", [
        "https://www.example.com/login",
        "https://example.com/path?q=1",
    ])
    def test_no_at_symbol(self, url):
        finding = self.rule.check(_parse(url))
        assert finding is None


# ══════════════════════════════════════════════════════════════
# Rule 2: Long URL
# ══════════════════════════════════════════════════════════════

class TestLongURLRule:
    rule = LongURLRule(threshold=100)

    def test_detects_long_url(self):
        long_url = "https://example.com/" + "a" * 100
        finding = self.rule.check(_parse(long_url))
        assert finding is not None
        assert finding.rule_id == "LONG_URL"
        assert finding.severity == Severity.LOW

    def test_short_url_passes(self):
        finding = self.rule.check(_parse("https://example.com"))
        assert finding is None

    def test_exact_threshold_not_flagged(self):
        """URL at exactly 100 chars should NOT be flagged (> not >=)."""
        # "https://example.com/" is 20 chars, add 80 more
        url = "https://example.com/" + "a" * 80
        assert len(url) == 100
        finding = self.rule.check(_parse(url))
        assert finding is None

    def test_custom_threshold(self):
        rule = LongURLRule(threshold=20)
        finding = rule.check(_parse("https://www.example.com/long"))
        assert finding is not None


# ══════════════════════════════════════════════════════════════
# Rule 3: IP Hostname
# ══════════════════════════════════════════════════════════════

class TestIPHostnameRule:
    rule = IPHostnameRule()

    @pytest.mark.parametrize("url", [
        "https://192.168.1.1/login",
        "http://10.0.0.1/page",
        "https://255.255.255.0/admin",
    ])
    def test_detects_ip_hostname(self, url):
        finding = self.rule.check(_parse(url))
        assert finding is not None
        assert finding.rule_id == "IP_HOSTNAME"
        assert finding.severity == Severity.HIGH

    @pytest.mark.parametrize("url", [
        "https://www.example.com",
        "https://123.example.com",  # starts with number but is a domain
    ])
    def test_domain_not_flagged(self, url):
        finding = self.rule.check(_parse(url))
        assert finding is None


# ══════════════════════════════════════════════════════════════
# Rule 4: Many Hostname Segments
# ══════════════════════════════════════════════════════════════

class TestManySegmentsRule:
    rule = ManySegmentsRule(threshold=5)

    @pytest.mark.parametrize("url,expected_labels", [
        ("https://a.b.c.d.e.example.invalid", 7),
        ("https://one.two.three.four.five.com", 6),
    ])
    def test_detects_many_segments(self, url, expected_labels):
        finding = self.rule.check(_parse(url))
        assert finding is not None
        assert finding.rule_id == "MANY_SEGMENTS"

    @pytest.mark.parametrize("url", [
        "https://www.example.com",        # 3 labels
        "https://sub.www.example.com",    # 4 labels
    ])
    def test_few_segments_pass(self, url):
        finding = self.rule.check(_parse(url))
        assert finding is None


# ══════════════════════════════════════════════════════════════
# Rule 5: Punycode
# ══════════════════════════════════════════════════════════════

class TestPunycodeRule:
    rule = PunycodeRule()

    def test_detects_punycode(self):
        finding = self.rule.check(_parse("https://xn--exmple-cua.com"))
        assert finding is not None
        assert finding.rule_id == "PUNYCODE"
        assert finding.severity == Severity.MEDIUM

    def test_normal_domain_passes(self):
        finding = self.rule.check(_parse("https://example.com"))
        assert finding is None

    def test_xn_in_path_not_flagged(self):
        """xn-- in the path (not hostname) should NOT trigger."""
        finding = self.rule.check(_parse("https://example.com/xn--page"))
        assert finding is None


# ══════════════════════════════════════════════════════════════
# Rule 6: HTTP Scheme
# ══════════════════════════════════════════════════════════════

class TestHTTPSchemeRule:
    rule = HTTPSchemeRule()

    def test_detects_http(self):
        finding = self.rule.check(_parse("http://www.example.com"))
        assert finding is not None
        assert finding.rule_id == "HTTP_SCHEME"

    def test_https_passes(self):
        finding = self.rule.check(_parse("https://www.example.com"))
        assert finding is None

    def test_missing_scheme_not_flagged(self):
        """URLs without a typed scheme should NOT trigger HTTP warning."""
        finding = self.rule.check(_parse("www.example.com"))
        assert finding is None

    def test_http_case_insensitive(self):
        finding = self.rule.check(_parse("HTTP://WWW.EXAMPLE.COM"))
        assert finding is not None
