"""
Rule registry — automatic discovery and execution of all rules.

New rules are registered by adding them to the ``_ALL_RULE_CLASSES``
tuple. The :func:`run_all_rules` function instantiates each rule,
calls ``check``, and collects non-``None`` findings.

This design makes it trivial to add or remove a check without
touching any other module.
"""

from __future__ import annotations

from typing import Sequence

from src.models import Finding
from src.parser import ParsedURL
from src.rules.at_symbol import AtSymbolRule
from src.rules.long_url import LongURLRule
from src.rules.ip_hostname import IPHostnameRule
from src.rules.many_segments import ManySegmentsRule
from src.rules.punycode import PunycodeRule
from src.rules.http_scheme import HTTPSchemeRule
from src.rules import Rule


# ── Ordered list of all active rules ──────────────────────────
# The execution order matches the workbook table (1–6).
_ALL_RULE_CLASSES: tuple[type[Rule], ...] = (
    AtSymbolRule,
    LongURLRule,
    IPHostnameRule,
    ManySegmentsRule,
    PunycodeRule,
    HTTPSchemeRule,
)


def get_registered_rules() -> tuple[Rule, ...]:
    """Return an instance of every registered rule, in order."""
    return tuple(cls() for cls in _ALL_RULE_CLASSES)


def run_all_rules(parsed: ParsedURL) -> list[Finding]:
    """
    Execute every registered rule against *parsed* and return
    a list of findings (only rules that matched).

    The returned list preserves the registration order.
    """
    findings: list[Finding] = []
    for rule in get_registered_rules():
        result = rule.check(parsed)
        if result is not None:
            findings.append(result)
    return findings


def list_rule_summaries() -> list[dict[str, str]]:
    """
    Return metadata for every registered rule.

    Useful for help screens and documentation generators.
    """
    return [
        {
            "rule_id": r.rule_id,
            "name": r.name,
            "severity": r.severity.name,
            "honest_limit": r.honest_limit,
        }
        for r in get_registered_rules()
    ]
