"""
Base classes for the extensible constraint system.

To add a new constraint type:
1. Create a new Constraint subclass implementing `matches(value) -> bool`.
2. Create a ConstraintParser subclass implementing `parse(annotation_value) -> ConstraintSet`.
3. Register the parser in registry.py.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class Constraint(ABC):
    """A single parsed constraint token.

    A value satisfies the constraint if ``matches`` returns True.
    Subclasses should be immutable and implement ``__repr__`` for error messages.
    """

    @abstractmethod
    def matches(self, value: Any) -> bool:
        """Return True if *value* satisfies this constraint."""

    @abstractmethod
    def __repr__(self) -> str:
        """Human-readable description used in rejection messages."""


class ConstraintSet:
    """An ordered collection of constraints parsed from one annotation value.

    A value satisfies the ConstraintSet if it matches **any** of the individual
    constraints (i.e. constraints within a single annotation are OR-ed together).

    Example:  "1000,2000-3000,>5000000"  →  exact(1000) OR range(2000-3000) OR >(5000000)
    """

    def __init__(self, constraints: list[Constraint]) -> None:
        if not constraints:
            raise ValueError("ConstraintSet must contain at least one Constraint")
        self.constraints = constraints

    def matches(self, value: Any) -> bool:
        return any(c.matches(value) for c in self.constraints)

    def description(self) -> str:
        return " OR ".join(repr(c) for c in self.constraints)

    def __repr__(self) -> str:
        return f"ConstraintSet([{self.description()}])"


class ConstraintParser(ABC):
    """Parses a raw annotation string into a :class:`ConstraintSet`."""

    @abstractmethod
    def parse(self, annotation_value: str) -> ConstraintSet:
        """Parse *annotation_value* and return the corresponding ConstraintSet.

        Raises ``ValueError`` if the annotation value is malformed.
        """
