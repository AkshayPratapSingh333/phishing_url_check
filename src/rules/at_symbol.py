"""
Rule 1 — @ symbol detection.

The ``@`` character in a URL separates "userinfo" from the real
hostname.  ``example.com@evil.invalid`` sends the browser to
``evil.invalid``, but a quick glance might see ``example.com``.

This rule also checks for percent-encoded ``@`` (``%40``) after
URL-decoding.
"""

from __future__ import annotations

from typing import Optional

from src.models import Finding, Severity
from src.parser import ParsedURL
from src.rules import Rule


class AtSymbolRule(Rule):
    rule_id = "AT_SYMBOL"
    name = "@ Symbol Detected"
    severity = Severity.HIGH
    honest_limit = (
        "Rare in normal links, but some legitimate services "
        "use userinfo in URLs."
    )

    def check(self, parsed: ParsedURL) -> Optional[Finding]:
        """
        Return a finding if ``@`` appears in the normalised URL
        or in its percent-decoded form.
        """
        has_at = "@" in parsed.normalised or "@" in parsed.decoded
        if has_at:
            return self._make_finding(
                message=(
                    "Contains an @ symbol. Text before @ may be ignored "
                    "by the browser — the real destination could differ "
                    "from what you see at first glance."
                ),
                matched_value="@",
            )
        return None
