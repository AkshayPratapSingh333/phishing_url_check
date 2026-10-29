"""
Data models for the Phishing URL Awareness Checker.

Uses dataclasses and Enum for type-safe, self-documenting structures.
These models are the shared vocabulary between the rule engine,
the inspector façade, and the CLI formatter.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional


class Severity(Enum):
    """
    Risk severity assigned to a warning finding.

    Values are ordered so that comparisons like
    ``Severity.HIGH.value > Severity.LOW.value`` are meaningful.
    The ordering is used by the formatter to sort output.
    """

    INFO = auto()       # Contextual note, not a warning sign
    LOW = auto()        # Mild indicator, very common in honest URLs
    MEDIUM = auto()     # Noteworthy; user should look twice
    HIGH = auto()       # Strong phishing indicator in most contexts
    CRITICAL = auto()   # Almost never seen in legitimate URLs


@dataclass(frozen=True, slots=True)
class Finding:
    """
    A single warning sign detected (or absence thereof) in a URL.

    Attributes:
        rule_id:     Machine-readable identifier (e.g. ``"AT_SYMBOL"``).
        title:       Short human-readable label (e.g. ``"@ Symbol Detected"``).
        message:     Explanation shown to the user.
        severity:    One of the :class:`Severity` levels.
        honest_limit: Why honest URLs might trigger this rule too.
        matched_value: The substring or value that triggered the rule.
    """

    rule_id: str
    title: str
    message: str
    severity: Severity
    honest_limit: str = ""
    matched_value: Optional[str] = None


@dataclass(slots=True)
class InspectionResult:
    """
    Complete result of inspecting a single URL string.

    Attributes:
        raw_url:      The original string the user typed.
        hostname:     Parsed hostname (may be ``None`` on bad input).
        scheme:       The scheme part of the URL, if present.
        findings:     List of :class:`Finding` objects (may be empty).
        error:        A human-readable error string if parsing failed.
        is_safe:      **Always** ``False``. This field exists only so
                      that no consumer ever accidentally treats an empty
                      findings list as "safe".
    """

    raw_url: str
    hostname: Optional[str] = None
    scheme: Optional[str] = None
    findings: list[Finding] = field(default_factory=list)
    error: Optional[str] = None
    is_safe: bool = field(default=False, init=False, repr=False)

    @property
    def has_warnings(self) -> bool:
        """Return ``True`` when at least one finding has severity > INFO."""
        return any(f.severity != Severity.INFO for f in self.findings)

    @property
    def max_severity(self) -> Severity:
        """Return the highest severity among all findings."""
        if not self.findings:
            return Severity.INFO
        return max(self.findings, key=lambda f: f.severity.value).severity

    @property
    def warning_count(self) -> int:
        """Number of findings with severity above INFO."""
        return sum(1 for f in self.findings if f.severity != Severity.INFO)
