"""
Rule 5 — Punycode marker (``xn--``) detection.

Punycode encodes non-ASCII characters in domain names.  Attackers
use it to register look-alike domains (homograph attacks) where,
for example, a Cyrillic "а" replaces a Latin "a".  Seeing ``xn--``
in a hostname means international characters were encoded.
"""

from __future__ import annotations

from typing import Optional

from src.models import Finding, Severity
from src.parser import ParsedURL
from src.rules import Rule

_PUNYCODE_MARKER = "xn--"


class PunycodeRule(Rule):
    rule_id = "PUNYCODE"
    name = "Punycode-Style Hostname"
    severity = Severity.MEDIUM
    honest_limit = (
        "Real international websites (e.g. in Chinese, Arabic, or "
        "Cyrillic) use punycode legitimately."
    )

    def check(self, parsed: ParsedURL) -> Optional[Finding]:
        """Return a finding if the hostname contains ``xn--``."""
        if parsed.hostname and _PUNYCODE_MARKER in parsed.hostname:
            return self._make_finding(
                message=(
                    f"Hostname contains the punycode marker '{_PUNYCODE_MARKER}'. "
                    f"This can hide look-alike foreign characters that "
                    f"mimic familiar domain names (homograph attack)."
                ),
                matched_value=_PUNYCODE_MARKER,
            )
        return None
