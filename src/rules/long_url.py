"""
Rule 2 — Unusually long URL detection.

Long URLs can push the real hostname off-screen or bury it inside
a wall of path segments and query parameters.  This rule flags
URLs exceeding a configurable character threshold.
"""

from __future__ import annotations

from typing import Optional

from src.models import Finding, Severity
from src.parser import ParsedURL
from src.rules import Rule

# Default threshold from the workbook.
LONG_URL_THRESHOLD = 100


class LongURLRule(Rule):
    rule_id = "LONG_URL"
    name = "Unusually Long URL"
    severity = Severity.LOW
    honest_limit = (
        "Many legitimate URLs (maps, tracking links, SSO callbacks) "
        "exceed 100 characters."
    )

    def __init__(self, threshold: int = LONG_URL_THRESHOLD) -> None:
        self._threshold = threshold

    def check(self, parsed: ParsedURL) -> Optional[Finding]:
        """Return a finding if the URL exceeds the length threshold."""
        if parsed.full_length > self._threshold:
            return self._make_finding(
                message=(
                    f"URL is {parsed.full_length} characters long "
                    f"(threshold: {self._threshold}). Long URLs can hide "
                    f"the real destination far to the right."
                ),
                matched_value=str(parsed.full_length),
            )
        return None
