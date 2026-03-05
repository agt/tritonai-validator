"""Tests for the constraint parsing and matching system."""
import pytest

from app.constraints.boolean import BooleanConstraintParser
from app.constraints.numeric import NumericConstraintParser


class TestNumericConstraintParser:
    parser = NumericConstraintParser()

    # --- Exact ---
    @pytest.mark.parametrize("value,expected", [
        (1000, True),
        (999, False),
        (1001, False),
    ])
    def test_exact(self, value, expected):
        cs = self.parser.parse("1000")
        assert cs.matches(value) is expected

    # --- Range ---
    @pytest.mark.parametrize("value,expected", [
        (2000, True),
        (2500, True),
        (3000, True),
        (1999, False),
        (3001, False),
    ])
    def test_range(self, value, expected):
        cs = self.parser.parse("2000-3000")
        assert cs.matches(value) is expected

    # --- Greater than ---
    @pytest.mark.parametrize("value,expected", [
        (5000001, True),
        (5000000, False),
        (0, False),
    ])
    def test_greater_than(self, value, expected):
        cs = self.parser.parse(">5000000")
        assert cs.matches(value) is expected

    # --- Less than ---
    @pytest.mark.parametrize("value,expected", [
        (499, True),
        (500, False),
        (0, True),
    ])
    def test_less_than(self, value, expected):
        cs = self.parser.parse("<500")
        assert cs.matches(value) is expected

    # --- >= ---
    def test_gte(self):
        cs = self.parser.parse(">=1000")
        assert cs.matches(1000) is True
        assert cs.matches(999) is False

    # --- <= ---
    def test_lte(self):
        cs = self.parser.parse("<=1000")
        assert cs.matches(1000) is True
        assert cs.matches(1001) is False

    # --- Multi-token (OR semantics) ---
    def test_multi_token(self):
        cs = self.parser.parse("1000,1001,2000-3000,>5000000")
        assert cs.matches(1000) is True
        assert cs.matches(1001) is True
        assert cs.matches(2500) is True
        assert cs.matches(9999999) is True
        assert cs.matches(999) is False
        assert cs.matches(1500) is False
        assert cs.matches(5000000) is False

    def test_empty_annotation_raises(self):
        with pytest.raises(ValueError):
            self.parser.parse("")

    def test_bad_token_raises(self):
        with pytest.raises(ValueError):
            self.parser.parse("foo")

    def test_inverted_range_raises(self):
        with pytest.raises(ValueError):
            self.parser.parse("3000-2000")

    def test_boolean_value_does_not_match(self):
        cs = self.parser.parse("1000")
        # booleans should not match numeric constraints
        assert cs.matches(True) is False
        assert cs.matches(False) is False


class TestBooleanConstraintParser:
    parser = BooleanConstraintParser()

    def test_true(self):
        cs = self.parser.parse("true")
        assert cs.matches(True) is True
        assert cs.matches(False) is False

    def test_false(self):
        cs = self.parser.parse("false")
        assert cs.matches(False) is True
        assert cs.matches(True) is False

    def test_case_insensitive(self):
        cs = self.parser.parse("True")
        assert cs.matches(True) is True

    def test_string_matching(self):
        cs = self.parser.parse("false")
        assert cs.matches("false") is True
        assert cs.matches("true") is False

    def test_invalid_raises(self):
        with pytest.raises(ValueError):
            self.parser.parse("yes")
