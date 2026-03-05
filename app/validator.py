"""
Core pod validation logic.

Applies per-namespace security constraints to an incoming Pod spec.

Validation rules per annotation
────────────────────────────────
sc.dsmlp.ucsd.edu/runAsUser          →  REQUIRED_SCALAR  (see below)
sc.dsmlp.ucsd.edu/runAsGroup         →  REQUIRED_SCALAR
sc.dsmlp.ucsd.edu/allowPrivilegeEscalation  →  REQUIRED_SCALAR

sc.dsmlp.ucsd.edu/fsGroup            →  OPTIONAL_SCALAR  (pod-level only in k8s)
sc.dsmlp.ucsd.edu/supplementalGroups →  OPTIONAL_LIST    (pod-level only in k8s)

REQUIRED_SCALAR semantics
  - If the pod-level securityContext carries the field → it must match.
  - All container/initContainer securityContexts that carry the field → must match.
  - If the pod-level securityContext is *absent* (or does not set the field),
    EVERY container and initContainer must carry a securityContext that sets the
    field and the value must match.

OPTIONAL_SCALAR / OPTIONAL_LIST semantics
  - The constraint is satisfied if the field is absent everywhere.
  - If the field *is* present (pod-level only for fsGroup/supplementalGroups),
    the value(s) must match.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable

from .constraints.base import ConstraintSet
from .constraints.registry import CONSTRAINT_REGISTRY, parse_annotation

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _pod_sc(pod_spec: dict[str, Any]) -> dict[str, Any]:
    return pod_spec.get("securityContext") or {}


def _containers(pod_spec: dict[str, Any]) -> list[dict[str, Any]]:
    return list(pod_spec.get("containers") or [])


def _init_containers(pod_spec: dict[str, Any]) -> list[dict[str, Any]]:
    return list(pod_spec.get("initContainers") or [])


def _all_containers(pod_spec: dict[str, Any]) -> list[dict[str, Any]]:
    return _containers(pod_spec) + _init_containers(pod_spec)


def _container_sc(container: dict[str, Any]) -> dict[str, Any]:
    return container.get("securityContext") or {}


def _container_name(container: dict[str, Any]) -> str:
    return container.get("name", "<unnamed>")


# ---------------------------------------------------------------------------
# Validation strategies
# ---------------------------------------------------------------------------


class FieldBehavior(Enum):
    REQUIRED_SCALAR = auto()
    """Field must be present on every container when absent at pod level."""

    OPTIONAL_SCALAR = auto()
    """Field is optional; if present it must match (pod-level only)."""

    OPTIONAL_LIST = auto()
    """Field is an optional list; every element must match (pod-level only)."""


@dataclass
class FieldSpec:
    """Describes how to extract and validate one security field."""

    # dot-path name for messages
    display_name: str
    # behavior enum
    behavior: FieldBehavior
    # extracts scalar/list from a securityContext dict; returns None if absent
    extract: Callable[[dict[str, Any]], Any]


# Maps annotation key suffix (after "sc.dsmlp.ucsd.edu/") to its FieldSpec
_FIELD_SPECS: dict[str, FieldSpec] = {
    "runAsUser": FieldSpec(
        display_name="runAsUser",
        behavior=FieldBehavior.REQUIRED_SCALAR,
        extract=lambda sc: sc.get("runAsUser"),
    ),
    "runAsGroup": FieldSpec(
        display_name="runAsGroup",
        behavior=FieldBehavior.REQUIRED_SCALAR,
        extract=lambda sc: sc.get("runAsGroup"),
    ),
    "allowPrivilegeEscalation": FieldSpec(
        display_name="allowPrivilegeEscalation",
        behavior=FieldBehavior.REQUIRED_SCALAR,
        extract=lambda sc: sc.get("allowPrivilegeEscalation"),
    ),
    "fsGroup": FieldSpec(
        display_name="fsGroup",
        behavior=FieldBehavior.OPTIONAL_SCALAR,
        extract=lambda sc: sc.get("fsGroup"),
    ),
    "supplementalGroups": FieldSpec(
        display_name="supplementalGroups",
        behavior=FieldBehavior.OPTIONAL_LIST,
        extract=lambda sc: sc.get("supplementalGroups"),
    ),
}


# ---------------------------------------------------------------------------
# Per-field validators
# ---------------------------------------------------------------------------


def _validate_required_scalar(
    field_name: str,
    spec: FieldSpec,
    pod_spec: dict[str, Any],
    constraint_set: ConstraintSet,
) -> list[str]:
    """Validate a REQUIRED_SCALAR field (e.g. runAsUser, allowPrivilegeEscalation)."""
    errors: list[str] = []
    pod_sc = _pod_sc(pod_spec)
    pod_value = spec.extract(pod_sc)
    pod_has_value = pod_value is not None

    # Validate pod-level value if present
    if pod_has_value:
        if not constraint_set.matches(pod_value):
            errors.append(
                f"Pod securityContext.{field_name}={pod_value!r} does not satisfy "
                f"constraint [{constraint_set.description()}]"
            )

    for container in _all_containers(pod_spec):
        cname = _container_name(container)
        csc = _container_sc(container)
        c_value = spec.extract(csc)

        if c_value is not None:
            # Container sets the field → must match regardless
            if not constraint_set.matches(c_value):
                errors.append(
                    f"Container {cname!r} securityContext.{field_name}={c_value!r} "
                    f"does not satisfy constraint [{constraint_set.description()}]"
                )
        elif not pod_has_value:
            # Pod-level absent AND container doesn't set it → required
            errors.append(
                f"Container {cname!r} must set securityContext.{field_name} "
                f"(no pod-level default); constraint: [{constraint_set.description()}]"
            )

    return errors


def _validate_optional_scalar(
    field_name: str,
    spec: FieldSpec,
    pod_spec: dict[str, Any],
    constraint_set: ConstraintSet,
) -> list[str]:
    """Validate an OPTIONAL_SCALAR field (e.g. fsGroup).

    Absent everywhere → OK.  Present → must match.
    Note: fsGroup and supplementalGroups are pod-scope only in Kubernetes;
    container securityContexts do not carry these fields.
    """
    errors: list[str] = []
    pod_sc = _pod_sc(pod_spec)
    pod_value = spec.extract(pod_sc)

    if pod_value is not None and not constraint_set.matches(pod_value):
        errors.append(
            f"Pod securityContext.{field_name}={pod_value!r} does not satisfy "
            f"constraint [{constraint_set.description()}]"
        )

    return errors


def _validate_optional_list(
    field_name: str,
    spec: FieldSpec,
    pod_spec: dict[str, Any],
    constraint_set: ConstraintSet,
) -> list[str]:
    """Validate an OPTIONAL_LIST field (e.g. supplementalGroups).

    Absent or empty → OK.  Each element present → must match.
    """
    errors: list[str] = []
    pod_sc = _pod_sc(pod_spec)
    values = spec.extract(pod_sc)

    if values:  # None or [] → satisfied
        for v in values:
            if not constraint_set.matches(v):
                errors.append(
                    f"Pod securityContext.{field_name} entry {v!r} does not satisfy "
                    f"constraint [{constraint_set.description()}]"
                )

    return errors


_BEHAVIOR_HANDLERS: dict[
    FieldBehavior,
    Callable[[str, FieldSpec, dict[str, Any], ConstraintSet], list[str]],
] = {
    FieldBehavior.REQUIRED_SCALAR: _validate_required_scalar,
    FieldBehavior.OPTIONAL_SCALAR: _validate_optional_scalar,
    FieldBehavior.OPTIONAL_LIST: _validate_optional_list,
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


@dataclass
class ValidationResult:
    allowed: bool
    errors: list[str] = field(default_factory=list)

    @property
    def message(self) -> str:
        return "; ".join(self.errors) if self.errors else ""


def validate_pod(
    namespace_annotations: dict[str, str],
    pod_spec: dict[str, Any],
) -> ValidationResult:
    """Validate *pod_spec* against the security constraints in *namespace_annotations*.

    Parameters
    ----------
    namespace_annotations:
        The ``sc.dsmlp.ucsd.edu/*`` annotations scraped from the pod's namespace.
        Keys are full annotation strings (e.g. ``"sc.dsmlp.ucsd.edu/runAsUser"``).
    pod_spec:
        The ``spec`` sub-dict from the Pod's ``object`` in the AdmissionRequest.

    Returns
    -------
    ValidationResult with ``allowed=True`` iff all constraints pass.
    """
    # Collect annotations that match known constraint keys
    active_constraints: dict[str, ConstraintSet] = {}
    parse_errors: list[str] = []

    for annotation_key in CONSTRAINT_REGISTRY:
        if annotation_key not in namespace_annotations:
            continue
        annotation_value = namespace_annotations[annotation_key]
        try:
            active_constraints[annotation_key] = parse_annotation(
                annotation_key, annotation_value
            )
        except ValueError as exc:
            parse_errors.append(
                f"Namespace annotation {annotation_key!r} is malformed: {exc}"
            )

    if parse_errors:
        return ValidationResult(allowed=False, errors=parse_errors)

    # No security annotations → reject (policy must be explicit)
    if not active_constraints:
        return ValidationResult(
            allowed=False,
            errors=[
                "Pod rejected: the namespace has no sc.dsmlp.ucsd.edu/* annotations; "
                "security policy must be explicitly defined."
            ],
        )

    # Apply each active constraint
    all_errors: list[str] = []
    for annotation_key, constraint_set in active_constraints.items():
        field_suffix = annotation_key.split("/", 1)[1]  # e.g. "runAsUser"
        spec = _FIELD_SPECS.get(field_suffix)
        if spec is None:
            logger.warning("No FieldSpec registered for annotation key %r; skipping", annotation_key)
            continue

        handler = _BEHAVIOR_HANDLERS[spec.behavior]
        field_errors = handler(field_suffix, spec, pod_spec, constraint_set)
        all_errors.extend(field_errors)

    return ValidationResult(allowed=len(all_errors) == 0, errors=all_errors)
