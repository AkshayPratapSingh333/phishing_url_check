"""
Unit tests for data models (Finding, InspectionResult, Severity).
"""

import pytest

from src.models import Finding, InspectionResult, Severity


class TestSeverityOrdering:
    """Verify that Severity enum values are properly ordered."""

    def test_ordering(self):
        assert Severity.INFO.value < Severity.LOW.value
        assert Severity.LOW.value < Severity.MEDIUM.value
        assert Severity.MEDIUM.value < Severity.HIGH.value
        assert Severity.HIGH.value < Severity.CRITICAL.value

    def test_all_values_unique(self):
        values = [s.value for s in Severity]
        assert len(values) == len(set(values))


class TestFinding:
    """Verify Finding dataclass behaviour."""

    def test_creation(self):
        f = Finding(
            rule_id="TEST",
            title="Test Rule",
            message="Test message",
            severity=Severity.HIGH,
        )
        assert f.rule_id == "TEST"
        assert f.severity == Severity.HIGH

    def test_frozen(self):
        f = Finding(
            rule_id="TEST",
            title="Test",
            message="msg",
            severity=Severity.LOW,
        )
        with pytest.raises(AttributeError):
            f.rule_id = "CHANGED"

    def test_optional_fields_default(self):
        f = Finding(
            rule_id="TEST",
            title="Test",
            message="msg",
            severity=Severity.INFO,
        )
        assert f.honest_limit == ""
        assert f.matched_value is None


class TestInspectionResult:
    """Verify InspectionResult computed properties."""

    def test_is_safe_always_false(self):
        result = InspectionResult(raw_url="test")
        assert result.is_safe is False

    def test_has_warnings_false_when_only_info(self):
        result = InspectionResult(
            raw_url="test",
            findings=[
                Finding(
                    rule_id="X", title="X", message="m",
                    severity=Severity.INFO,
                )
            ],
        )
        assert result.has_warnings is False

    def test_has_warnings_true_with_medium(self):
        result = InspectionResult(
            raw_url="test",
            findings=[
                Finding(
                    rule_id="X", title="X", message="m",
                    severity=Severity.MEDIUM,
                )
            ],
        )
        assert result.has_warnings is True

    def test_warning_count(self):
        result = InspectionResult(
            raw_url="test",
            findings=[
                Finding(rule_id="A", title="A", message="m",
                        severity=Severity.INFO),
                Finding(rule_id="B", title="B", message="m",
                        severity=Severity.HIGH),
                Finding(rule_id="C", title="C", message="m",
                        severity=Severity.LOW),
            ],
        )
        assert result.warning_count == 2

    def test_max_severity(self):
        result = InspectionResult(
            raw_url="test",
            findings=[
                Finding(rule_id="A", title="A", message="m",
                        severity=Severity.LOW),
                Finding(rule_id="B", title="B", message="m",
                        severity=Severity.CRITICAL),
                Finding(rule_id="C", title="C", message="m",
                        severity=Severity.MEDIUM),
            ],
        )
        assert result.max_severity == Severity.CRITICAL

    def test_max_severity_empty(self):
        result = InspectionResult(raw_url="test")
        assert result.max_severity == Severity.INFO
