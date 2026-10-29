"""
Abstract base class for all URL inspection rules.

Every concrete rule inherits from :class:`Rule` and implements
the ``check`` method. Rules are self-describing: each carries
its own ``rule_id``, display ``name``, and ``honest_limit`` text
so the system can produce complete output without any hard-coded
strings outside the rule class.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from src.models import Finding, Severity
from src.parser import ParsedURL


class Rule(ABC):
    """
    Base class for a single URL text inspection rule.

    Subclasses must set the class-level attributes ``rule_id``,
    ``name``, ``severity``, and ``honest_limit``, then implement
    :meth:`check`.
    """

    rule_id: str = ""
    name: str = ""
    severity: Severity = Severity.MEDIUM
    honest_limit: str = ""

    @abstractmethod
    def check(self, parsed: ParsedURL) -> Optional[Finding]:
        """
        Inspect the parsed URL and return a :class:`Finding` if
        the warning sign is present, or ``None`` otherwise.
        """
        ...

    def _make_finding(
        self,
        message: str,
        matched_value: Optional[str] = None,
        severity: Optional[Severity] = None,
    ) -> Finding:
        """Helper to build a :class:`Finding` from this rule's metadata."""
        return Finding(
            rule_id=self.rule_id,
            title=self.name,
            message=message,
            severity=severity or self.severity,
            honest_limit=self.honest_limit,
            matched_value=matched_value,
        )
