"""
Inspector façade — the single high-level entry point for URL inspection.

This module composes the parser, rule registry, and data models into
one function call: :func:`inspect_url`.  Every other module in the
project is a dependency of this one; consumers should import only
from here.
"""

from __future__ import annotations

from src.models import Finding, InspectionResult, Severity
from src.parser import parse_url
from src.rules.registry import run_all_rules


# ── Sentinel finding for "no warnings" ────────────────────────
_NO_WARNINGS_FINDING = Finding(
    rule_id="NO_WARNINGS",
    title="No Warning Signs Found",
    message=(
        "No listed warning signs were detected. "
        "This does NOT prove the URL is safe. Attackers can "
        "craft URLs that avoid all six checks."
    ),
    severity=Severity.INFO,
    honest_limit="Absence of warning signs is never proof of safety.",
)


def inspect_url(raw_url: str) -> InspectionResult:
    """
    Inspect a raw URL string for phishing warning signs.

    Returns an :class:`InspectionResult` containing zero or more
    :class:`Finding` objects.  If no rule matched, a single INFO
    finding is included reminding the user that this does not
    prove safety.

    This function **never** opens a network connection.

    Parameters:
        raw_url: The URL string exactly as the user typed it.

    Returns:
        A fully populated :class:`InspectionResult`.
    """
    try:
        parsed = parse_url(raw_url)
    except ValueError:
        result = InspectionResult(raw_url=raw_url)
        result.error = "Could not parse the URL."
        return result

    # ── Handle empty / unparseable input ──────────────────────
    if parsed is None:
        result = InspectionResult(raw_url=raw_url)
        result.error = "No URL entered."
        return result

    if parsed.hostname is None:
        result = InspectionResult(
            raw_url=raw_url,
            scheme=parsed.scheme,
        )
        result.error = "Could not identify a hostname in the URL."
        return result

    # ── Run all registered rules ──────────────────────────────
    findings = run_all_rules(parsed)

    if not findings:
        findings = [_NO_WARNINGS_FINDING]

    return InspectionResult(
        raw_url=raw_url,
        hostname=parsed.hostname,
        scheme=parsed.scheme,
        findings=findings,
    )


def inspect_url_simple(raw_url: str) -> list[str]:
    """
    Backward-compatible wrapper that returns a flat list of
    message strings, matching the original ``inspect_url`` API.

    This is provided so that existing tests and scripts continue
    to work without modification.
    """
    result = inspect_url(raw_url)
    if result.error:
        return [result.error]
    return [f.message for f in result.findings]
