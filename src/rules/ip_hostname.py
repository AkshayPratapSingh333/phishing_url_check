"""
Rule 3 — IP-address hostname detection.

Legitimate brands use domain names (e.g. ``google.com``), not raw
IP addresses.  An IP hostname like ``http://192.168.1.1/login``
should prompt extra scrutiny, though some internal tools use IPs.
"""

from __future__ import annotations

import re
from typing import Optional

from src.models import Finding, Severity
from src.parser import ParsedURL
from src.rules import Rule

# Matches four groups of 1–3 digits separated by dots.
# Does NOT enforce the 0–255 range — that is acceptable for an
# awareness-level check.
_IPV4_PATTERN = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")


class IPHostnameRule(Rule):
    rule_id = "IP_HOSTNAME"
    name = "IP-Address Hostname"
    severity = Severity.HIGH
    honest_limit = (
        "Some internal tools and development servers use IP addresses "
        "legitimately."
    )

    def check(self, parsed: ParsedURL) -> Optional[Finding]:
        """Return a finding if the hostname matches an IPv4 pattern."""
        if parsed.hostname and _IPV4_PATTERN.fullmatch(parsed.hostname):
            return self._make_finding(
                message=(
                    f"Hostname is an IP address ({parsed.hostname}) instead "
                    f"of a recognisable domain name. Real brands almost "
                    f"always use named domains."
                ),
                matched_value=parsed.hostname,
            )
        return None
