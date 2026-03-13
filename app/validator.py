"""
Core pod validation logic.

Applies per-namespace security constraints to an incoming Pod spec.

Validation rules per annotation
────────────────────────────────
<PREFIX>/policy.runAsUser          →  REQUIRED_SCALAR  (see below)
<PREFIX>/policy.runAsGroup         →  REQUIRED_SCALAR

<PREFIX>/policy.fsGroup            →  OPTIONAL_SCALAR  (pod-level only in k8s)
<PREFIX>/policy.supplementalGroups →  OPTIONAL_LIST    (pod-level only in k8s)
<PREFIX>/policy.nodeSelectors       →  NODE_SELECTOR    (see below)
<PREFIX>/policy.tolerations        →  TOLERATION_ALLOWLIST (see below)

Where <PREFIX> is the ANNOTATION_PREFIX env var (default: tritonai-admission-webhook).

NODE_SELECTOR semantics
  - pod.spec.nodeName must be absent (bypassing nodeSelector is not permitted).
  - pod.spec.nodeSelector must contain at least one entry matching ANY annotation token.

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

TOLERATION_ALLOWLIST semantics
  - Annotation absent → no restriction; any pod tolerations are permitted.
  - Annotation present → every pod toleration must be covered by at least one entry.
  - Each entry is "key=value:effect" where any field may contain fnmatch-style globs.
  - A value pattern of "*" additionally matches tolerations with operator "Exists"
    (i.e. no value field), in addition to Equal with any value.

Hardcoded constraints (always enforced, not annotation-driven)
──────────────────────────────────────────────────────────────
securityContext.runAsNonRoot must be true; enforced via _validate_required_scalar
  with a fixed BooleanConstraint(True) — pod-level True covers all containers;
  if absent at pod level every container (including initContainers and
  ephemeralContainers) must individually set it to True.
"""
from __future__ import annotations

import fnmatch
import logging
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable

from .config import ANNOTATION_NS, POLICY_PREFIX
from .constraints.base import ConstraintSet
from .constraints.boolean import BooleanConstraint
from .constraints.nodeselectors import negated_keys as _nodeselectors_negated_keys
from .constraints.registry import CONSTRAINT_REGISTRY, parse_annotation
from .pod_helpers import (
    _all_containers,
    _container_name,
    _container_sc,
    _is_node_kubernetes_toleration,
    _pod_sc,
)

logger = logging.getLogger(__name__)


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

    NODE_SELECTOR = auto()
    """pod.spec.nodeName must be absent; nodeSelector must match at least one token."""


@dataclass
class FieldSpec:
    """Describes how to extract and validate one security field."""

    # dot-path name for messages
    display_name: str
    # behavior enum
    behavior: FieldBehavior
    # extracts scalar/list from a securityContext dict; returns None if absent
    extract: Callable[[dict[str, Any]], Any]


# Maps annotation key suffix (after POLICY_PREFIX) to its FieldSpec
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
    "nodeSelectors": FieldSpec(
        display_name="nodeSelectors",
        behavior=FieldBehavior.NODE_SELECTOR,
        extract=lambda sc: None,  # handler reads pod_spec directly
    ),
    "runAsNonRoot": FieldSpec(
        display_name="runAsNonRoot",
        behavior=FieldBehavior.REQUIRED_SCALAR,
        extract=lambda sc: sc.get("runAsNonRoot"),
    ),
}


# ---------------------------------------------------------------------------
# Per-field validators
# ---------------------------------------------------------------------------


def _validate_required_scalar(
    field_name: str,
    spec: FieldSpec,
    pod_spec: dict[str, Any],
    constraint_sets: list[ConstraintSet],
) -> list[str]:
    """Validate a REQUIRED_SCALAR field against all active constraint sets (AND semantics)."""
    errors: list[str] = []
    pod_sc = _pod_sc(pod_spec)
    pod_value = spec.extract(pod_sc)
    pod_has_value = pod_value is not None

    # Validate pod-level value if present — must satisfy every constraint set
    if pod_has_value:
        for cs in constraint_sets:
            if not cs.matches(pod_value):
                errors.append(
                    f"Pod securityContext.{field_name}={pod_value!r} does not satisfy "
                    f"constraint [{cs.description()}]"
                )

    for container in _all_containers(pod_spec):
        cname = _container_name(container)
        csc = _container_sc(container)
        c_value = spec.extract(csc)

        if c_value is not None:
            # Container sets the field → must match every constraint set
            for cs in constraint_sets:
                if not cs.matches(c_value):
                    errors.append(
                        f"Container {cname!r} securityContext.{field_name}={c_value!r} "
                        f"does not satisfy constraint [{cs.description()}]"
                    )
        elif not pod_has_value:
            # Pod-level absent AND container doesn't set it → required
            all_desc = ", ".join(cs.description() for cs in constraint_sets)
            errors.append(
                f"Container {cname!r} must set securityContext.{field_name} "
                f"(no pod-level default); constraint: [{all_desc}]"
            )

    return errors


def _validate_optional_scalar(
    field_name: str,
    spec: FieldSpec,
    pod_spec: dict[str, Any],
    constraint_sets: list[ConstraintSet],
) -> list[str]:
    """Validate an OPTIONAL_SCALAR field against all active constraint sets.

    Absent everywhere → OK.  Present → must match every constraint set.
    Note: fsGroup and supplementalGroups are pod-scope only in Kubernetes;
    container securityContexts do not carry these fields.
    """
    errors: list[str] = []
    pod_sc = _pod_sc(pod_spec)
    pod_value = spec.extract(pod_sc)

    if pod_value is not None:
        for cs in constraint_sets:
            if not cs.matches(pod_value):
                errors.append(
                    f"Pod securityContext.{field_name}={pod_value!r} does not satisfy "
                    f"constraint [{cs.description()}]"
                )

    return errors


def _validate_optional_list(
    field_name: str,
    spec: FieldSpec,
    pod_spec: dict[str, Any],
    constraint_sets: list[ConstraintSet],
) -> list[str]:
    """Validate an OPTIONAL_LIST field against all active constraint sets.

    Absent or empty → OK.  Each element present → must match every constraint set.
    """
    errors: list[str] = []
    pod_sc = _pod_sc(pod_spec)
    values = spec.extract(pod_sc)

    if values:  # None or [] → satisfied
        for v in values:
            for cs in constraint_sets:
                if not cs.matches(v):
                    errors.append(
                        f"Pod securityContext.{field_name} entry {v!r} does not satisfy "
                        f"constraint [{cs.description()}]"
                    )

    return errors


def _validate_node_selector(
    field_name: str,
    spec: FieldSpec,
    pod_spec: dict[str, Any],
    constraint_sets: list[ConstraintSet],
) -> list[str]:
    """Validate NODE_SELECTOR behavior against all active constraint sets.

    Rules:
    1. pod.spec.nodeName must be absent — direct node binding bypasses nodeSelector.
    2. pod.spec.nodeSelector must satisfy every active constraint set.
    3. For negated tokens (!key=value), the label key must not appear in any
       nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution
       .nodeSelectorTerms[].matchExpressions[].key — nodeAffinity can otherwise
       be used to route pods around the restriction.
    """
    errors: list[str] = []

    node_name = pod_spec.get("nodeName")
    if node_name:
        errors.append(
            f"Pod must not set nodeName when {POLICY_PREFIX}nodeSelectors is "
            f"enforced by the namespace; found nodeName={node_name!r}"
        )

    node_selector: dict[str, str] = pod_spec.get("nodeSelector") or {}
    for cs in constraint_sets:
        if not cs.matches(node_selector):
            errors.append(
                f"Pod nodeSelector {node_selector!r} does not satisfy "
                f"nodeSelectors constraint [{cs.description()}]"
            )

    prohibited = _nodeselectors_negated_keys(constraint_sets)
    if prohibited:
        terms = (
            (pod_spec.get("affinity") or {})
            .get("nodeAffinity", {})
            .get("requiredDuringSchedulingIgnoredDuringExecution", {})
            .get("nodeSelectorTerms") or []
        )
        for term in terms:
            for expr in term.get("matchExpressions") or []:
                key = expr.get("key")
                if key in prohibited:
                    errors.append(
                        f"Pod nodeAffinity references key {key!r} which is "
                        f"prohibited by the nodeSelectors constraint"
                    )

    return errors


_BEHAVIOR_HANDLERS: dict[
    FieldBehavior,
    Callable[[str, FieldSpec, dict[str, Any], list[ConstraintSet]], list[str]],
] = {
    FieldBehavior.REQUIRED_SCALAR: _validate_required_scalar,
    FieldBehavior.OPTIONAL_SCALAR: _validate_optional_scalar,
    FieldBehavior.OPTIONAL_LIST: _validate_optional_list,
    FieldBehavior.NODE_SELECTOR: _validate_node_selector,
}


# ---------------------------------------------------------------------------
# Hardcoded security constraints (always enforced, not annotation-driven)
# ---------------------------------------------------------------------------

_ALLOWED_CAPABILITIES: frozenset[str] = frozenset({"NET_BIND_SERVICE"})

_ALLOWED_VOLUME_TYPES: frozenset[str] = frozenset({
    "configMap",
    "downwardAPI",
    "emptyDir",
    "image",
    "nfs",
    "persistentVolumeClaim",
    "secret",
    "serviceAccountToken",
    "clusterTrustBundle",
    "podCertificate",
    "projected",
})


def _validate_hardcoded_constraints(pod_spec: dict[str, Any]) -> list[str]:
    """Enforce security constraints that apply to every pod, regardless of namespace annotations.

    Pod-level:
      - hostNetwork, hostPID, hostIPC must each be absent or false.
      - securityContext.sysctls must be absent or empty.
      - securityContext.runAsUser must not be 0 (root).

    Per container (containers, initContainers, ephemeralContainers):
      - securityContext.runAsUser must not be 0 (root).
      - securityContext.allowPrivilegeEscalation must be explicitly false.
      - securityContext.privileged must be absent or false.
      - securityContext.capabilities.add must be absent, empty, or contain only NET_BIND_SERVICE.
      - securityContext.procMount must be absent, empty string, or "Default".
      - ports[*].hostPort must be absent or 0.

    Volume type checking is handled separately by _validate_volume_types(), which also
    applies the prohibitedVolumeTypes namespace annotation.
    """
    errors: list[str] = []

    # Pod-level: host namespaces
    for field in ("hostNetwork", "hostPID", "hostIPC"):
        value = pod_spec.get(field)
        if value is not None and value is not False:
            errors.append(
                f"Pod {field} must be absent or false; found {value!r}"
            )

    # Pod-level: sysctls
    pod_sc = _pod_sc(pod_spec)
    sysctls = pod_sc.get("sysctls")
    if sysctls:  # non-None and non-empty list
        errors.append(
            f"Pod securityContext.sysctls must be absent or empty; found {sysctls!r}"
        )

    # Pod-level: runAsUser must not be 0
    pod_run_as_user = pod_sc.get("runAsUser")
    if pod_run_as_user is not None and pod_run_as_user == 0:
        errors.append("Pod securityContext.runAsUser must not be 0 (root)")

    # Container-level checks
    for container in _all_containers(pod_spec):
        cname = _container_name(container)
        csc = _container_sc(container)

        ape = csc.get("allowPrivilegeEscalation")
        if ape is not False:
            errors.append(
                f"Container {cname!r} securityContext.allowPrivilegeEscalation must be "
                f"explicitly false; found {ape!r}"
            )

        privileged = csc.get("privileged")
        if privileged is not None and privileged is not False:
            errors.append(
                f"Container {cname!r} securityContext.privileged must be absent or false; "
                f"found {privileged!r}"
            )

        caps_add = (csc.get("capabilities") or {}).get("add") or []
        disallowed = [c for c in caps_add if c not in _ALLOWED_CAPABILITIES]
        if disallowed:
            errors.append(
                f"Container {cname!r} securityContext.capabilities.add contains disallowed "
                f"capabilities {disallowed!r}; only NET_BIND_SERVICE is permitted"
            )

        proc_mount = csc.get("procMount")
        if proc_mount is not None and proc_mount not in ("", "Default"):
            errors.append(
                f"Container {cname!r} securityContext.procMount must be absent or 'Default'; "
                f"found {proc_mount!r}"
            )

        for port in container.get("ports") or []:
            host_port = port.get("hostPort")
            if host_port is not None and host_port != 0:
                errors.append(
                    f"Container {cname!r} port {port.get('containerPort', '?')!r} "
                    f"must not set hostPort; found hostPort={host_port!r}"
                )

        run_as_user = csc.get("runAsUser")
        if run_as_user is not None and run_as_user == 0:
            errors.append(
                f"Container {cname!r} securityContext.runAsUser must not be 0 (root)"
            )

    return errors


# ---------------------------------------------------------------------------
# Volume type constraint (hardcoded base set + optional namespace restriction)
# ---------------------------------------------------------------------------

_PROHIBITED_VOLUME_TYPES_KEY = f"{POLICY_PREFIX}prohibitedVolumeTypes"


def _validate_volume_types(
    pod_spec: dict[str, Any],
    annotation_layers: list[dict[str, str]],
) -> list[str]:
    """Validate volume types and env/envFrom sources against the prohibitedVolumeTypes annotation.

    The base permitted volume type set is _ALLOWED_VOLUME_TYPES.  Any layer's
    prohibitedVolumeTypes annotation may further restrict it.  A type prohibited
    by ANY layer is prohibited overall (AND semantics across layers).
    A missing or empty annotation in a layer means no additional restriction from
    that layer.

    When a type is prohibited, the corresponding env/envFrom sources are also blocked
    across all containers, initContainers, and ephemeralContainers:

      configMap   → env[].valueFrom.configMapKeyRef, envFrom[].configMapRef
      secret      → env[].valueFrom.secretKeyRef,    envFrom[].secretRef
      downwardAPI → env[].valueFrom.fieldRef,         env[].valueFrom.resourceFieldRef

    Type names in an annotation that are not in the base permitted set are
    ignored (with a warning), since they were never allowed to begin with.
    """
    prohibited: frozenset[str] = frozenset()
    for layer in annotation_layers:
        raw = layer.get(_PROHIBITED_VOLUME_TYPES_KEY, "")
        if raw.strip():
            names = [t.strip() for t in raw.split(",") if t.strip()]
            unknown = [n for n in names if n not in _ALLOWED_VOLUME_TYPES]
            for u in unknown:
                logger.warning(
                    "Annotation %r lists %r which is not in the base permitted volume type set; ignored.",
                    _PROHIBITED_VOLUME_TYPES_KEY, u,
                )
            prohibited |= frozenset(n for n in names if n in _ALLOWED_VOLUME_TYPES)

    effective_allowed = _ALLOWED_VOLUME_TYPES - prohibited

    errors: list[str] = []

    # Volume type check
    for volume in pod_spec.get("volumes") or []:
        vol_name = volume.get("name", "<unnamed>")
        disallowed_types = [k for k in volume if k != "name" and k not in effective_allowed]
        for vol_type in disallowed_types:
            errors.append(
                f"Volume {vol_name!r} uses disallowed type {vol_type!r}; "
                f"permitted types: {sorted(effective_allowed)}"
            )

    # Env / envFrom source checks
    if prohibited:
        for container in _all_containers(pod_spec):
            cname = _container_name(container)

            for env_entry in container.get("env") or []:
                value_from = env_entry.get("valueFrom") or {}
                env_name = env_entry.get("name", "<unnamed>")

                if "configMap" in prohibited and "configMapKeyRef" in value_from:
                    errors.append(
                        f"Container {cname!r} env var {env_name!r} uses configMapKeyRef; "
                        f"configMap access is prohibited in this namespace"
                    )
                if "secret" in prohibited and "secretKeyRef" in value_from:
                    errors.append(
                        f"Container {cname!r} env var {env_name!r} uses secretKeyRef; "
                        f"secret access is prohibited in this namespace"
                    )
                if "downwardAPI" in prohibited:
                    if "fieldRef" in value_from:
                        errors.append(
                            f"Container {cname!r} env var {env_name!r} uses fieldRef "
                            f"(downward API); downwardAPI access is prohibited in this namespace"
                        )
                    if "resourceFieldRef" in value_from:
                        errors.append(
                            f"Container {cname!r} env var {env_name!r} uses resourceFieldRef "
                            f"(downward API); downwardAPI access is prohibited in this namespace"
                        )

            for ef in container.get("envFrom") or []:
                if "configMap" in prohibited and "configMapRef" in ef:
                    ref_name = (ef["configMapRef"] or {}).get("name", "<unnamed>")
                    errors.append(
                        f"Container {cname!r} envFrom uses configMapRef {ref_name!r}; "
                        f"configMap access is prohibited in this namespace"
                    )
                if "secret" in prohibited and "secretRef" in ef:
                    ref_name = (ef["secretRef"] or {}).get("name", "<unnamed>")
                    errors.append(
                        f"Container {cname!r} envFrom uses secretRef {ref_name!r}; "
                        f"secret access is prohibited in this namespace"
                    )

    return errors


# ---------------------------------------------------------------------------
# NFS volume annotation constraint
# ---------------------------------------------------------------------------

_NFS_ANNOTATION_KEY = f"{POLICY_PREFIX}allowedNfsVolumes"


def _validate_nfs_volumes(
    pod_spec: dict[str, Any],
    annotation_layers: list[dict[str, str]],
) -> list[str]:
    """Validate pod NFS volumes against the allowedNfsVolumes annotation across all layers.

    AND semantics across layers: a volume must be permitted by every layer that
    carries the annotation.  A layer with a missing annotation is treated as
    "no NFS volumes permitted" for that layer.

    Within each layer, at least one positive (non-negated) pattern must match,
    and no negated pattern (``!pattern``) may match.
    """
    nfs_volumes = [v for v in (pod_spec.get("volumes") or []) if "nfs" in v]
    if not nfs_volumes:
        return []

    errors: list[str] = []
    for volume in nfs_volumes:
        vol_name = volume.get("name", "<unnamed>")
        nfs = volume["nfs"]
        server = nfs.get("server", "")
        path = nfs.get("path", "")
        resource = f"{server}:{path}"

        for layer in annotation_layers:
            raw = layer.get(_NFS_ANNOTATION_KEY, "")
            tokens = [t.strip() for t in raw.split(",") if t.strip()] if raw.strip() else []
            positive = [t for t in tokens if not t.startswith("!")]
            negated = [t[1:].strip() for t in tokens if t.startswith("!")]

            # Check negated patterns first: none may match
            blocked = False
            for pat in negated:
                if fnmatch.fnmatch(resource, pat):
                    errors.append(
                        f"NFS volume {vol_name!r} ({resource!r}) matches negated pattern "
                        f"'!{pat}' in {_NFS_ANNOTATION_KEY!r}"
                    )
                    blocked = True
                    break

            if not blocked:
                # Check positive patterns (if any exist, one must match)
                if positive and not any(fnmatch.fnmatch(resource, p) for p in positive):
                    errors.append(
                        f"NFS volume {vol_name!r} ({resource!r}) does not match any entry in "
                        f"{_NFS_ANNOTATION_KEY!r}"
                    )
                elif not positive and not negated:
                    # No patterns at all → deny (layer has no NFS allowlist)
                    errors.append(
                        f"NFS volume {vol_name!r} ({resource!r}) does not match any entry in "
                        f"{_NFS_ANNOTATION_KEY!r}"
                    )

    return errors


# ---------------------------------------------------------------------------
# Toleration allowlist constraint (annotation-driven)
# ---------------------------------------------------------------------------

_TOLERATIONS_KEY = f"{POLICY_PREFIX}tolerations"


def _parse_toleration_token(token: str) -> tuple[str, str, str]:
    """Parse a single toleration token into (key_pattern, value_pattern, effect_pattern).

    Raises ``ValueError`` on malformed tokens.
    """
    if ":" not in token:
        raise ValueError(f"expected 'key=value:effect' format, got {token!r}")
    kv_part, effect_pat = token.rsplit(":", 1)
    effect_pat = effect_pat.strip()
    if "=" not in kv_part:
        raise ValueError(f"expected 'key=value' before ':', got {kv_part!r}")
    key_pat, value_pat = kv_part.split("=", 1)
    return (key_pat.strip(), value_pat.strip(), effect_pat)


def _parse_permitted_tolerations(
    raw: str,
) -> tuple[list[tuple[str, str, str]], list[tuple[str, str, str]]]:
    """Parse the tolerations annotation into positive and negated tuples.

    Returns ``(positive, negated)`` where each list contains
    ``(key_pattern, value_pattern, effect_pattern)`` tuples.

    Raises ``ValueError`` on malformed tokens.
    """
    positive: list[tuple[str, str, str]] = []
    negated: list[tuple[str, str, str]] = []
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        if token.startswith("!"):
            negated.append(_parse_toleration_token(token[1:].strip()))
        else:
            positive.append(_parse_toleration_token(token))
    if not positive and not negated:
        raise ValueError("no permitted toleration entries parsed from annotation value")
    return positive, negated


def _toleration_permitted(
    tol: dict[str, Any],
    key_pat: str,
    value_pat: str,
    effect_pat: str,
) -> bool:
    """Return True if *tol* is covered by the given (key, value, effect) pattern triple."""
    tol_key = tol.get("key", "")
    tol_effect = tol.get("effect", "")
    tol_operator = tol.get("operator", "Equal")

    if not fnmatch.fnmatch(tol_key, key_pat):
        return False
    if not fnmatch.fnmatch(tol_effect, effect_pat):
        return False

    # value_pat == "*": matches both Equal (any value) and Exists (no value field)
    if value_pat == "*":
        return True

    # Non-wildcard value pattern: pod must be using Equal operator with a matching value
    if tol_operator == "Exists":
        return False
    return fnmatch.fnmatch(tol.get("value", ""), value_pat)


def _validate_tolerations(
    pod_spec: dict[str, Any],
    annotation_layers: list[dict[str, str]],
) -> list[str]:
    """Validate pod tolerations against the tolerations annotation across all layers.

    AND semantics across layers: a toleration must be permitted by every layer
    that carries the annotation.  A layer without the annotation imposes no
    restriction for that layer.

    Within each layer: annotation absent → no restriction; annotation present →
    every pod toleration must match at least one positive (non-negated) entry
    (if any positive entries exist), and must **not** match any negated entry.

    ``node.kubernetes.io/*`` tolerations are always implicitly permitted.
    Each entry may use fnmatch-style globs in any field.
    A value pattern of ``"*"`` additionally covers the ``Exists`` operator.
    """
    tolerations = pod_spec.get("tolerations") or []
    if not tolerations:
        return []

    errors: list[str] = []
    for layer in annotation_layers:
        raw = layer.get(_TOLERATIONS_KEY)
        if raw is None:
            continue  # this layer imposes no toleration restriction

        try:
            permitted, denied = _parse_permitted_tolerations(raw.strip())
        except ValueError as exc:
            errors.append(f"Namespace annotation {_TOLERATIONS_KEY!r} is malformed: {exc}")
            continue

        for tol in tolerations:
            if _is_node_kubernetes_toleration(tol):
                continue  # always implicitly permitted

            # Check negated entries first: none may match
            blocked = False
            for kp, vp, ep in denied:
                if _toleration_permitted(tol, kp, vp, ep):
                    errors.append(
                        f"Pod toleration {tol!r} matches negated entry in "
                        f"namespace annotation {_TOLERATIONS_KEY!r}"
                    )
                    blocked = True
                    break

            # If not blocked by negation, check positive entries
            if not blocked and permitted:
                if not any(_toleration_permitted(tol, kp, vp, ep) for kp, vp, ep in permitted):
                    errors.append(
                        f"Pod toleration {tol!r} is not permitted by "
                        f"namespace annotation {_TOLERATIONS_KEY!r}"
                    )

    return errors


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
    annotation_layers: list[dict[str, str]],
    pod_spec: dict[str, Any],
) -> ValidationResult:
    """Validate *pod_spec* against the security constraints in *annotation_layers*.

    Parameters
    ----------
    annotation_layers:
        Ordered list of per-source annotation dicts (e.g. one per policy ConfigMap
        then the namespace's own annotations).  Each dict contains only
        ``<ANNOTATION_PREFIX>/*`` keys.  AND semantics are applied across layers:
        the pod must satisfy every constraint from every layer.
    pod_spec:
        The ``spec`` sub-dict from the Pod's ``object`` in the AdmissionRequest.

    Returns
    -------
    ValidationResult with ``allowed=True`` iff all constraints pass.
    """
    # Collect annotations that match known constraint keys.
    # For each key, accumulate one ConstraintSet per layer that supplies it.
    active_constraints: dict[str, list[ConstraintSet]] = {}
    parse_errors: list[str] = []

    for layer in annotation_layers:
        for annotation_key in CONSTRAINT_REGISTRY:
            if annotation_key not in layer:
                continue
            try:
                cs = parse_annotation(annotation_key, layer[annotation_key])
                active_constraints.setdefault(annotation_key, []).append(cs)
            except ValueError as exc:
                parse_errors.append(
                    f"Namespace annotation {annotation_key!r} is malformed: {exc}"
                )

    if parse_errors:
        return ValidationResult(allowed=False, errors=parse_errors)

    # No security annotations in any layer → reject (policy must be explicit)
    if not active_constraints:
        return ValidationResult(
            allowed=False,
            errors=[
                f"Pod rejected: the namespace has no {ANNOTATION_NS}policy.* annotations; "
                "security policy must be explicitly defined."
            ],
        )

    # Apply each active constraint — AND across all layers' ConstraintSets
    all_errors: list[str] = []
    for annotation_key, constraint_set_list in active_constraints.items():
        field_suffix = annotation_key.removeprefix(POLICY_PREFIX)  # e.g. "runAsUser"
        spec = _FIELD_SPECS.get(field_suffix)
        if spec is None:
            logger.warning("No FieldSpec registered for annotation key %r; skipping", annotation_key)
            continue

        handler = _BEHAVIOR_HANDLERS[spec.behavior]
        field_errors = handler(field_suffix, spec, pod_spec, constraint_set_list)
        all_errors.extend(field_errors)

    # Apply hardcoded constraints (always enforced)
    all_errors.extend(_validate_hardcoded_constraints(pod_spec))
    _runasnonroot_cs = ConstraintSet([BooleanConstraint(True)])
    all_errors.extend(
        _validate_required_scalar("runAsNonRoot", _FIELD_SPECS["runAsNonRoot"], pod_spec, [_runasnonroot_cs])
    )

    # Apply volume type constraint (hardcoded base set, optionally narrowed by annotation)
    all_errors.extend(_validate_volume_types(pod_spec, annotation_layers))

    # Apply NFS volume constraint (annotation-driven, missing annotation = deny all NFS)
    all_errors.extend(_validate_nfs_volumes(pod_spec, annotation_layers))

    # Apply toleration allowlist (annotation-driven, missing annotation = no restriction)
    all_errors.extend(_validate_tolerations(pod_spec, annotation_layers))

    return ValidationResult(allowed=len(all_errors) == 0, errors=all_errors)
