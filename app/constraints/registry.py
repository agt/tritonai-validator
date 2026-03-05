"""
Constraint registry: maps annotation keys to their parsers.

To add a new annotation-backed constraint:
  1. Implement a ConstraintParser subclass in an appropriate module.
  2. Add an entry to CONSTRAINT_REGISTRY below.
  3. Add a FieldValidator entry in app/validator.py.
"""
from __future__ import annotations

from .base import ConstraintParser, ConstraintSet
from .boolean import BooleanConstraintParser
from .numeric import NumericConstraintParser

# ---------------------------------------------------------------------------
# Registry: annotation key → parser instance
# ---------------------------------------------------------------------------
CONSTRAINT_REGISTRY: dict[str, ConstraintParser] = {
    "sc.dsmlp.ucsd.edu/runAsUser": NumericConstraintParser(),
    "sc.dsmlp.ucsd.edu/runAsGroup": NumericConstraintParser(),
    "sc.dsmlp.ucsd.edu/fsGroup": NumericConstraintParser(),
    "sc.dsmlp.ucsd.edu/supplementalGroups": NumericConstraintParser(),
    "sc.dsmlp.ucsd.edu/allowPrivilegeEscalation": BooleanConstraintParser(),
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
