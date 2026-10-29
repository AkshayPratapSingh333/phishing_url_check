"""
Tests for the rule registry module.
"""

from src.rules.registry import get_registered_rules, run_all_rules, list_rule_summaries
from src.parser import parse_url
from src.rules import Rule


class TestRuleRegistry:
    """Verify the registry discovers and runs rules correctly."""

    def test_all_six_rules_registered(self):
        rules = get_registered_rules()
        assert len(rules) == 6

    def test_all_rules_are_rule_subclasses(self):
        for rule in get_registered_rules():
            assert isinstance(rule, Rule)

    def test_all_rules_have_metadata(self):
        for rule in get_registered_rules():
            assert rule.rule_id, f"Rule {rule} has no rule_id"
            assert rule.name, f"Rule {rule} has no name"
            assert rule.honest_limit, f"Rule {rule} has no honest_limit"

    def test_run_all_rules_returns_findings(self):
        parsed = parse_url("http://192.168.1.1/login")
        assert parsed is not None
        findings = run_all_rules(parsed)
        assert len(findings) >= 1  # at least IP hostname

    def test_run_all_rules_clean_url(self):
        parsed = parse_url("https://www.example.com")
        assert parsed is not None
        findings = run_all_rules(parsed)
        assert len(findings) == 0  # no warnings

    def test_list_rule_summaries(self):
        summaries = list_rule_summaries()
        assert len(summaries) == 6
        for s in summaries:
            assert "rule_id" in s
            assert "name" in s
            assert "severity" in s


class TestRuleOrder:
    """Verify that rules execute in workbook order."""

    def test_order_matches_workbook(self):
        rules = get_registered_rules()
        expected_ids = [
            "AT_SYMBOL",
            "LONG_URL",
            "IP_HOSTNAME",
            "MANY_SEGMENTS",
            "PUNYCODE",
            "HTTP_SCHEME",
        ]
        actual_ids = [r.rule_id for r in rules]
        assert actual_ids == expected_ids
