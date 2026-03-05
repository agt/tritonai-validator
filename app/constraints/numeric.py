"""
Numeric constraint parsers.

Supported token formats (comma-separated in the annotation value):
  - Exact value:      "1000"          → matches only 1000
  - Closed range:     "2000-3000"     → matches 2000 ≤ x ≤ 3000
  - Greater-than:     ">5000000"      → matches x > 5000000
  - Less-than:        "<500"          → matches x < 500
  - Greater-or-equal: ">=1000"        → matches x ≥ 1000
  - Less-or-equal:    "<=1000"        → matches x ≤ 1000
"""
from __future__ import annotations

import re
from typing import Any

from .base import Constraint, ConstraintParser, ConstraintSet

# Regex patterns for each token type (evaluated in order)
_RANGE_RE = re.compile(r"^(\d+)-(\d+)$")
_GTE_RE = re.compile(r"^>=(\d+)$")
_LTE_RE = re.compile(r"^<=(\d+)$")
_GT_RE = re.compile(r"^>(\d+)$")
_LT_RE = re.compile(r"^<(\d+)$")
_EXACT_RE = re.compile(r"^(\d+)$")


def _to_int(value: Any) -> int | None:
    """Coerce *value* to int, returning None on failure."""
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


class ExactNumericConstraint(Constraint):
    def __init__(self, value: int) -> None:
        self._value = value

    def matches(self, value: Any) -> bool:
        v = _to_int(value)
        return v is not None and v == self._value

    def __repr__(self) -> str:
        return f"exact({self._value})"


class RangeConstraint(Constraint):
    def __init__(self, low: int, high: int) -> None:
        if low > high:
            raise ValueError(f"Range low ({low}) must be ≤ high ({high})")
        self._low = low
        self._high = high

    def matches(self, value: Any) -> bool:
        v = _to_int(value)
        return v is not None and self._low <= v <= self._high

    def __repr__(self) -> str:
        return f"range({self._low}-{self._high})"


class GreaterThanConstraint(Constraint):
    def __init__(self, threshold: int) -> None:
        self._threshold = threshold

    def matches(self, value: Any) -> bool:
        v = _to_int(value)
        return v is not None and v > self._threshold

    def __repr__(self) -> str:
        return f">{self._threshold}"


class LessThanConstraint(Constraint):
    def __init__(self, threshold: int) -> None:
        self._threshold = threshold

    def matches(self, value: Any) -> bool:
        v = _to_int(value)
        return v is not None and v < self._threshold

    def __repr__(self) -> str:
        return f"<{self._threshold}"


class GreaterThanOrEqualConstraint(Constraint):
    def __init__(self, threshold: int) -> None:
        self._threshold = threshold

    def matches(self, value: Any) -> bool:
        v = _to_int(value)
        return v is not None and v >= self._threshold

    def __repr__(self) -> str:
        return f">={self._threshold}"


class LessThanOrEqualConstraint(Constraint):
    def __init__(self, threshold: int) -> None:
        self._threshold = threshold

    def matches(self, value: Any) -> bool:
        v = _to_int(value)
        return v is not None and v <= self._threshold

    def __repr__(self) -> str:
        return f"<={self._threshold}"


def _parse_numeric_token(token: str) -> Constraint:
    """Parse a single numeric token into the appropriate Constraint."""
    token = token.strip()

    if m := _RANGE_RE.match(token):
        return RangeConstraint(int(m.group(1)), int(m.group(2)))
    if m := _GTE_RE.match(token):
        return GreaterThanOrEqualConstraint(int(m.group(1)))
    if m := _LTE_RE.match(token):
        return LessThanOrEqualConstraint(int(m.group(1)))
    if m := _GT_RE.match(token):
        return GreaterThanConstraint(int(m.group(1)))
    if m := _LT_RE.match(token):
        return LessThanConstraint(int(m.group(1)))
    if m := _EXACT_RE.match(token):
        return ExactNumericConstraint(int(m.group(1)))

    raise ValueError(f"Cannot parse numeric constraint token: {token!r}")


class NumericConstraintParser(ConstraintParser):
    """Parses comma-separated numeric constraint expressions."""

    def parse(self, annotation_value: str) -> ConstraintSet:
        tokens = [t.strip() for t in annotation_value.split(",") if t.strip()]
        if not tokens:
            raise ValueError(f"Empty numeric constraint annotation: {annotation_value!r}")
        return ConstraintSet([_parse_numeric_token(t) for t in tokens])
