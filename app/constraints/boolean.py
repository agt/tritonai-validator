"""
Boolean constraint parser.

Permitted annotation values: "true" or "false" (case-insensitive).
"""
from __future__ import annotations

from typing import Any

from .base import Constraint, ConstraintParser, ConstraintSet


class BooleanConstraint(Constraint):
    def __init__(self, expected: bool) -> None:
        self._expected = expected

    def matches(self, value: Any) -> bool:
        if isinstance(value, bool):
            return value == self._expected
        if isinstance(value, str):
            lower = value.strip().lower()
            if lower == "true":
                return self._expected is True
            if lower == "false":
                return self._expected is False
        return False

    def __repr__(self) -> str:
        return f"bool({'true' if self._expected else 'false'})"


class BooleanConstraintParser(ConstraintParser):
    """Parses a single boolean annotation value ("true" or "false")."""

    def parse(self, annotation_value: str) -> ConstraintSet:
        v = annotation_value.strip().lower()
        if v == "true":
            return ConstraintSet([BooleanConstraint(True)])
        if v == "false":
            return ConstraintSet([BooleanConstraint(False)])
        raise ValueError(
            f"Invalid boolean constraint value {annotation_value!r}; expected 'true' or 'false'"
        )
