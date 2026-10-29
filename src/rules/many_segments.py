"""
Rule 4 — Many hostname segments / subdomains.

Attackers stack subdomains (e.g. ``a.b.c.d.e.evil.invalid``) so
that a trusted-looking label appears somewhere in the hostname.
Five or more labels is the workbook threshold.
"""

from __future__ import annotations

from typing import Optional

from src.models import Finding, Severity
from src.parser import ParsedURL
from src.rules import Rule

# Default threshold from the workbook.
MANY_SEGMENTS_THRESHOLD = 5


class ManySegmentsRule(Rule):
    rule_id = "MANY_SEGMENTS"
    name = "Many Hostname Segments"
    severity = Severity.MEDIUM
    honest_limit = (
        "Large organisations (especially CDNs and cloud providers) "
        "sometimes use deeply nested subdomains."
    )

    def __init__(self, threshold: int = MANY_SEGMENTS_THRESHOLD) -> None:
        self._threshold = threshold

    def check(self, parsed: ParsedURL) -> Optional[Finding]:
        """Return a finding if the hostname has ≥ *threshold* labels."""
        label_count = len(parsed.hostname_labels)
        if label_count >= self._threshold:
            return self._make_finding(
                message=(
                    f"Hostname has {label_count} segments "
                    f"({'.'.join(parsed.hostname_labels)}). "
                    f"Stacking subdomains is a common phishing technique "
                    f"to make a URL look official."
                ),
                matched_value=str(label_count),
            )
        return None
