"""
Node selector constraint parser.

Supported token format (comma-separated in the annotation value):
  key=value pairs, e.g. "partition=a" or "rack=b,rack=c"

The constraint is satisfied if pod.spec.nodeSelector contains at least one
entry matching ANY of the annotation tokens (OR semantics across tokens).
"""
from __future__ import annotations

import re
from typing import Any

from .base import Constraint, ConstraintParser, ConstraintSet, NegatedConstraint

_TOKEN_RE = re.compile(r"^([^=]+)=(.+)$")


class NodeSelectorsConstraint(Constraint):
    """Matches when a nodeSelector dict contains the expected key=value pair."""

    def __init__(self, key: str, value: str) -> None:
        self._key = key.strip()
        self._value = value.strip()

    def matches(self, node_selector: Any) -> bool:
        """Return True if *node_selector* dict contains this key=value pair."""
        if not isinstance(node_selector, dict):
            return False
        return node_selector.get(self._key) == self._value

    def __repr__(self) -> str:
        return f"nodeSelectors({self._key}={self._value})"


class NodeSelectorsConstraintParser(ConstraintParser):
    """Parses comma-separated key=value node selector expressions."""

    def parse(self, annotation_value: str) -> ConstraintSet:
        tokens = [t.strip() for t in annotation_value.split(",") if t.strip()]
        if not tokens:
            raise ValueError(f"Empty nodeSelectors constraint annotation: {annotation_value!r}")
        constraints: list[Constraint] = []
        for token in tokens:
            negated = token.startswith("!")
            inner = token[1:].strip() if negated else token
            m = _TOKEN_RE.match(inner)
            if not m:
                raise ValueError(
                    f"Invalid nodeSelectors constraint token {token!r}; "
                    f"expected 'key=value' or '!key=value' format"
                )
            c: Constraint = NodeSelectorsConstraint(m.group(1), m.group(2))
            constraints.append(NegatedConstraint(c) if negated else c)
        return ConstraintSet(constraints)
