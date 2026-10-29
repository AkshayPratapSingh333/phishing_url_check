"""
Rule 6 — HTTP (unencrypted) scheme detection.

HTTP transmits data without encryption, so anything typed on the
page (passwords, credit cards) can be intercepted in transit.

Design note:
    HTTP is flagged **only** when the user explicitly typed
    ``http://``.  If the scheme was absent, the parser injects
    ``http://`` for parsing purposes — that injection is NOT
    treated as a user-typed scheme.
"""

from __future__ import annotations

from typing import Optional

from src.models import Finding, Severity
from src.parser import ParsedURL
from src.rules import Rule


class HTTPSchemeRule(Rule):
    rule_id = "HTTP_SCHEME"
    name = "HTTP (Unencrypted) Scheme"
    severity = Severity.MEDIUM
    honest_limit = (
        "HTTPS alone does not prove trust. A site can have a valid "
        "certificate and still be a phishing page."
    )

    def check(self, parsed: ParsedURL) -> Optional[Finding]:
        """
        Return a finding if the user explicitly typed ``http://``.
        """
        if parsed.user_typed_scheme and parsed.scheme == "http":
            return self._make_finding(
                message=(
                    "Uses the HTTP scheme (unencrypted). Data sent over "
                    "HTTP can be intercepted in transit. Note: HTTPS "
                    "alone does not prove that a site is trustworthy."
                ),
                matched_value="http://",
            )
        return None
