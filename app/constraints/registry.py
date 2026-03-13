"""
Constraint registry: maps annotation keys to their parsers.

To add a new ConstraintSet-based annotation constraint:
  1. Implement a ConstraintParser subclass in an appropriate module.
  2. Add an entry to CONSTRAINT_REGISTRY below.
  3. Add a FieldSpec entry in app/validator.py (_FIELD_SPECS).

For annotation constraints that do not fit the ConstraintSet model (e.g. glob-
pattern lists like allowedNfsVolumes), implement the validation logic directly in
app/validator.py and call it from validate_pod().
"""
from __future__ import annotations

from ..config import POLICY_PREFIX
from .base import ConstraintParser, ConstraintSet
from .nodeselectors import NodeSelectorsConstraintParser
from .numeric import NumericConstraintParser

# ---------------------------------------------------------------------------
# Registry: annotation key → parser instance
# ---------------------------------------------------------------------------
CONSTRAINT_REGISTRY: dict[str, ConstraintParser] = {
    f"{POLICY_PREFIX}runAsUser": NumericConstraintParser(),
    f"{POLICY_PREFIX}runAsGroup": NumericConstraintParser(),
    f"{POLICY_PREFIX}fsGroup": NumericConstraintParser(),
    f"{POLICY_PREFIX}supplementalGroups": NumericConstraintParser(),
    f"{POLICY_PREFIX}nodeSelectors": NodeSelectorsConstraintParser(),
}


def get_constraint_parser(annotation_key: str) -> ConstraintParser | None:
    """Return the parser for *annotation_key*, or None if unsupported."""
    return CONSTRAINT_REGISTRY.get(annotation_key)


def parse_annotation(annotation_key: str, annotation_value: str) -> ConstraintSet:
    """Parse *annotation_value* using the parser registered for *annotation_key*.

    Raises ``KeyError`` if the key is not registered.
    Raises ``ValueError`` if the value is malformed.
    """
    parser = CONSTRAINT_REGISTRY[annotation_key]
    return parser.parse(annotation_value)
