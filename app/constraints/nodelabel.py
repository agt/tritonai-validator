"""
Node label (nodeSelector) constraint parser.

Supported token format (comma-separated in the annotation value):
  key=value pairs, e.g. "partition=a" or "rack=b,rack=c"

The constraint is satisfied if pod.spec.nodeSelector contains at least one
entry matching ANY of the annotation tokens (OR semantics across tokens).
"""
from __future__ import annotations

import re
from typing import Any

from .base import Constraint, ConstraintParser, ConstraintSet

_TOKEN_RE = re.compile(r"^([^=]+)=(.+)$")


class NodeLabelConstraint(Constraint):
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
        return f"nodeLabel({self._key}={self._value})"


class NodeLabelConstraintParser(ConstraintParser):
    """Parses comma-separated key=value node label expressions."""

    def parse(self, annotation_value: str) -> ConstraintSet:
        tokens = [t.strip() for t in annotation_value.split(",") if t.strip()]
        if not tokens:
            raise ValueError(f"Empty nodeLabel constraint annotation: {annotation_value!r}")
        constraints = []
        for token in tokens:
            m = _TOKEN_RE.match(token)
            if not m:
                raise ValueError(
                    f"Invalid nodeLabel constraint token {token!r}; "
                    f"expected 'key=value' format"
                )
            constraints.append(NodeLabelConstraint(m.group(1), m.group(2)))
        return ConstraintSet(constraints)
