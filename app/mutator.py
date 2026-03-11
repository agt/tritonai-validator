"""
Core pod mutation logic for the MutatingAdmissionWebhook.

For each active constraint annotation on the namespace, the mutator reads the
corresponding default annotation (<DEFAULT_PREFIX><field>) and applies it only
where the relevant field is **absent** (empty).  Fields that are already set are
left untouched — the downstream ValidatingAdmissionWebhook is responsible for
rejecting any values that violate policy.

   REQUIRED_SCALAR fields (runAsUser, runAsGroup)
     The pod-level securityContext is patched (or created from scratch) to
     supply the default for any container that does not carry the field itself.

   OPTIONAL_SCALAR fields (fsGroup)
     Absent is always acceptable; no default is injected.

   OPTIONAL_LIST fields (supplementalGroups)
     If <DEFAULT_PREFIX>supplementalGroups is present, its value is parsed as a
     comma-separated list of integers (e.g. "1000,2022,3900" or a single value
     "1000") and injected into pod.spec.securityContext.supplementalGroups only
     when that field is absent or an empty list.  Any existing non-empty list is
     left untouched.

   NODE_SELECTOR (nodeLabel)
     • pod.spec.nodeName is always removed — it unconditionally bypasses nodeSelector.
     • The default key=value label is injected only when the pod specifies no
       nodeSelector at all.  Any existing nodeSelector (regardless of content)
       is left untouched.

   runAsNonRoot (hardcoded, unconditional)
     pod.spec.securityContext.runAsNonRoot is always set to True when the field
     is absent.  Existing values (including False) are left untouched so the
     downstream validator can reject them.

   tolerations (optional default injection)
     If <DEFAULT_PREFIX>tolerations is present on the namespace, its value is
     parsed as a comma-separated list of "key=value:effect" tokens and injected
     when the pod carries no user-defined tolerations.
     Tolerations whose key is in the node.kubernetes.io/* namespace are
     considered system-managed (added automatically by Kubernetes for node
     conditions) and are ignored when deciding whether defaults should be
     applied; they are preserved in the final list, with defaults appended.
     A value of "*" for the toleration value produces operator "Exists";
     any other value produces operator "Equal".

Returns a (possibly empty) list of RFC 6902 JSON Patch operations.  The caller
base64-encodes the JSON-serialised list and returns it to the API server, which
then re-runs the mutated pod through all registered ValidatingAdmissionWebhooks.
"""
from __future__ import annotations

import copy
import logging
from typing import Any

from .config import DEFAULT_PREFIX, POLICY_PREFIX
from .pod_helpers import _all_containers, _container_sc, _is_node_kubernetes_toleration
from .validator import FieldBehavior, _FIELD_SPECS

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# JSON Pointer helpers (RFC 6901)
# ---------------------------------------------------------------------------


def _escape_ptr_segment(segment: str) -> str:
    """Escape a single JSON Pointer path segment."""
    return segment.replace("~", "~0").replace("/", "~1")


def _ptr(*segments: str) -> str:
    """Build a JSON Pointer string from path segments."""
    return "/" + "/".join(_escape_ptr_segment(s) for s in segments)


# ---------------------------------------------------------------------------
# Default value parsing
# ---------------------------------------------------------------------------


def _parse_default(
    field_name: str,
    annotation_key: str,
    ns_annotations: dict[str, str],
) -> Any:
    """Return the parsed default value for *field_name*, or None on failure.

    Logs a warning and returns None if:
    - the default annotation is absent from the namespace, or
    - the raw string cannot be parsed for the field type.
    """
    default_key = f"{DEFAULT_PREFIX}{field_name}"

    if default_key not in ns_annotations:
        logger.warning(
            "Constraint annotation %r is active but default annotation %r is absent "
            "from the namespace; cannot auto-remediate %r.",
            annotation_key, default_key, field_name,
        )
        return None

    raw = ns_annotations[default_key].strip()

    try:
        if field_name == "supplementalGroups":
            values = [int(v.strip()) for v in raw.split(",") if v.strip()]
            if not values:
                raise ValueError("empty supplementalGroups default")
            return values
        elif field_name in ("runAsUser", "runAsGroup", "fsGroup"):
            return int(raw)
        elif field_name == "nodeLabel":
            if "=" not in raw:
                raise ValueError(f"expected 'key=value' format, got {raw!r}")
            key, val = raw.split("=", 1)
            return (key.strip(), val.strip())
        else:
            logger.warning("No default parser registered for field %r; skipping.", field_name)
            return None
    except (ValueError, TypeError) as exc:
        logger.warning(
            "Cannot parse default annotation %r=%r: %s; skipping auto-remediation for %r.",
            default_key, raw, exc, field_name,
        )
        return None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _any_container_missing_field(pod: dict[str, Any], field_name: str) -> bool:
    """Return True if any container, initContainer, or ephemeralContainer is
    missing *field_name* in its securityContext (or has no securityContext)."""
    for container in _all_containers(pod):
        if field_name not in _container_sc(container):
            return True
    return False


# ---------------------------------------------------------------------------
# Per-behavior mutators
# ---------------------------------------------------------------------------


def _mutate_required_scalar(
    field_name: str,
    pod: dict[str, Any],
    default_value: Any,
    patches: list[dict[str, Any]],
) -> None:
    """Supply a pod-level default for REQUIRED_SCALAR fields that are absent.

    Only containers that do not set the field themselves need coverage.
    Containers that already carry the field (even with a non-conforming value)
    are left untouched; the validator will reject them if necessary.
    """
    pod_sc: dict[str, Any] | None = pod.get("securityContext")

    if pod_sc is not None:
        if pod_sc.get(field_name) is None and _any_container_missing_field(pod, field_name):
            pod_sc[field_name] = default_value
            patches.append({
                "op": "add",
                "path": _ptr("spec", "securityContext", field_name),
                "value": default_value,
            })
    else:
        if _any_container_missing_field(pod, field_name):
            pod["securityContext"] = {field_name: default_value}
            patches.append({
                "op": "add",
                "path": "/spec/securityContext",
                "value": {field_name: default_value},
            })


def _mutate_optional_list(
    field_name: str,
    pod: dict[str, Any],
    default_value: list[Any],
    patches: list[dict[str, Any]],
) -> None:
    """Supply a pod-level default for OPTIONAL_LIST fields when absent or empty.

    These fields (e.g. supplementalGroups) live only in the pod-level
    securityContext.  Injects the default when the field is absent or an empty
    list; any existing non-empty list is left untouched.
    """
    pod_sc: dict[str, Any] | None = pod.get("securityContext")

    if pod_sc is not None:
        if pod_sc.get(field_name):  # non-None, non-empty → leave untouched
            return
        pod_sc[field_name] = default_value
        patches.append({
            "op": "add",
            "path": _ptr("spec", "securityContext", field_name),
            "value": default_value,
        })
    else:
        pod["securityContext"] = {field_name: default_value}
        patches.append({
            "op": "add",
            "path": "/spec/securityContext",
            "value": {field_name: default_value},
        })


def _mutate_run_as_non_root(
    pod: dict[str, Any],
    patches: list[dict[str, Any]],
) -> None:
    """Unconditionally inject runAsNonRoot=True into pod-level securityContext if absent.

    Only patches when securityContext.runAsNonRoot is absent (None).
    Existing values — including False — are left untouched; the validator rejects them.
    """
    pod_sc: dict[str, Any] | None = pod.get("securityContext")

    if pod_sc is not None:
        if pod_sc.get("runAsNonRoot") is None:
            pod_sc["runAsNonRoot"] = True
            patches.append({
                "op": "add",
                "path": _ptr("spec", "securityContext", "runAsNonRoot"),
                "value": True,
            })
    else:
        pod["securityContext"] = {"runAsNonRoot": True}
        patches.append({
            "op": "add",
            "path": "/spec/securityContext",
            "value": {"runAsNonRoot": True},
        })


def _mutate_node_selector(
    pod: dict[str, Any],
    default_label: tuple[str, str] | None,
    patches: list[dict[str, Any]],
) -> None:
    """Mutate pod scheduling fields when nodeLabel is active.

    • nodeName is always removed — it unconditionally bypasses nodeSelector.
    • The default key=value label is injected only when nodeSelector is completely
      absent.  If the pod already specifies any nodeSelector entries, it is left
      untouched.
    """
    if pod.get("nodeName"):
        del pod["nodeName"]
        patches.append({"op": "remove", "path": "/spec/nodeName"})

    if default_label is None:
        return

    if pod.get("nodeSelector"):
        return  # pod already specifies a nodeSelector; leave it alone

    key, value = default_label
    pod["nodeSelector"] = {key: value}
    patches.append({
        "op": "add",
        "path": "/spec/nodeSelector",
        "value": {key: value},
    })


def _parse_default_tolerations(raw: str) -> list[dict[str, Any]]:
    """Parse a comma-separated toleration string into a list of Toleration dicts.

    Format: ``"key=value:effect[,key=value:effect,...]"``

    * If *value* is the literal string ``"*"``, the resulting Toleration uses
      operator ``"Exists"`` and omits the ``value`` field.
    * Any other *value* produces operator ``"Equal"`` with the ``value`` field set.

    Raises ``ValueError`` on malformed tokens.
    """
    result = []
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        if ":" not in token:
            raise ValueError(f"expected 'key=value:effect' format, got {token!r}")
        kv_part, effect = token.rsplit(":", 1)
        effect = effect.strip()
        if "=" not in kv_part:
            raise ValueError(f"expected 'key=value' before ':', got {kv_part!r}")
        key, value = kv_part.split("=", 1)
        key = key.strip()
        value = value.strip()
        if value == "*":
            result.append({"key": key, "operator": "Exists", "effect": effect})
        else:
            result.append({"key": key, "operator": "Equal", "value": value, "effect": effect})
    if not result:
        raise ValueError("no tolerations parsed from empty annotation value")
    return result


def _mutate_tolerations(
    pod: dict[str, Any],
    ns_annotations: dict[str, str],
    patches: list[dict[str, Any]],
) -> None:
    """Inject default tolerations when the pod has no user-defined tolerations.

    Fires when ``<DEFAULT_PREFIX>tolerations`` is present **and** the
    pod's toleration list contains no toleration outside the ``node.kubernetes.io/*``
    key namespace (which Kubernetes itself adds automatically for node conditions).

    When ``node.kubernetes.io/*`` tolerations are present they are preserved; the
    defaults are appended after them so the resulting list contains both.
    """
    default_key = f"{DEFAULT_PREFIX}tolerations"
    if default_key not in ns_annotations:
        return

    existing: list[dict[str, Any]] = pod.get("tolerations") or []
    node_k8s = [t for t in existing if _is_node_kubernetes_toleration(t)]
    custom = [t for t in existing if not _is_node_kubernetes_toleration(t)]

    if custom:  # pod already has user-defined tolerations → leave untouched
        return

    raw = ns_annotations[default_key].strip()
    try:
        defaults = _parse_default_tolerations(raw)
    except ValueError as exc:
        logger.warning(
            "Cannot parse default annotation %r=%r: %s; skipping toleration injection.",
            default_key, raw, exc,
        )
        return

    new_tolerations = node_k8s + defaults
    pod["tolerations"] = new_tolerations
    patches.append({
        "op": "add",
        "path": "/spec/tolerations",
        "value": new_tolerations,
    })


# Dispatch table: FieldBehavior → mutator function (excludes NODE_SELECTOR)
_SC_MUTATORS = {
    FieldBehavior.REQUIRED_SCALAR: _mutate_required_scalar,
    FieldBehavior.OPTIONAL_LIST: _mutate_optional_list,
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def _compute_mutations(
    namespace_annotations: dict[str, str],
    pod_spec: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Apply namespace defaults to *pod_spec* and return (mutated_spec, patches).

    Parameters
    ----------
    namespace_annotations:
        All ``<ANNOTATION_PREFIX>/*`` annotations scraped from the pod's namespace,
        including both policy.* constraint annotations and default.* annotations.
    pod_spec:
        The ``spec`` sub-dict from the Pod's AdmissionRequest object.

    Returns
    -------
    A tuple of (mutated pod spec dict, RFC 6902 JSON Patch operation list).
    The patch paths are relative to ``/spec`` (i.e. they start with ``/spec/``).
    """
    pod = copy.deepcopy(pod_spec)
    patches: list[dict[str, Any]] = []

    # --- securityContext fields (REQUIRED_SCALAR only) ---
    for field_suffix, field_spec in _FIELD_SPECS.items():
        mutator = _SC_MUTATORS.get(field_spec.behavior)
        if mutator is None:
            continue  # OPTIONAL_SCALAR has no mutations; NODE_SELECTOR handled below

        annotation_key = f"{POLICY_PREFIX}{field_suffix}"
        if annotation_key not in namespace_annotations:
            continue

        default_value = _parse_default(field_suffix, annotation_key, namespace_annotations)
        if default_value is None:
            continue

        mutator(field_suffix, pod, default_value, patches)

    # --- nodeLabel (NODE_SELECTOR) ---
    node_label_key = f"{POLICY_PREFIX}nodeLabel"
    if node_label_key in namespace_annotations:
        nl_default = _parse_default("nodeLabel", node_label_key, namespace_annotations)
        _mutate_node_selector(pod, nl_default, patches)

    # --- runAsNonRoot (hardcoded, always True, unconditional) ---
    _mutate_run_as_non_root(pod, patches)

    # --- tolerations (optional default injection) ---
    _mutate_tolerations(pod, namespace_annotations, patches)

    return pod, patches


def mutate_pod(
    namespace_annotations: dict[str, str],
    pod_spec: dict[str, Any],
) -> list[dict[str, Any]]:
    """Compute RFC 6902 JSON Patch operations to fill in missing defaults in *pod_spec*.

    Returns a (possibly empty) list of JSON Patch operation dicts.  Returns an
    empty list when no constraint annotations are active or no mutations are needed.
    The caller is responsible for JSON-serialising and base64-encoding the list.
    """
    _, patches = _compute_mutations(namespace_annotations, pod_spec)
    return patches


def mutate_pod_spec(
    namespace_annotations: dict[str, str],
    pod_spec: dict[str, Any],
) -> dict[str, Any]:
    """Apply namespace defaults to *pod_spec* and return the resulting spec dict.

    Equivalent to ``mutate_pod`` but returns the mutated spec rather than the
    patch list.  Used by the validating webhook when it needs to pre-apply
    defaults before validating a workload's pod template.
    """
    mutated, _ = _compute_mutations(namespace_annotations, pod_spec)
    return mutated
