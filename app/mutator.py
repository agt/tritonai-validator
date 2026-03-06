"""
Core pod mutation logic for the MutatingAdmissionWebhook.

For each active constraint annotation on the namespace, the mutator reads the
corresponding default annotation (sc.dsmlp.ucsd.edu/default.<field>) and applies
it only where the relevant field is **absent** (empty).  Fields that are already
set are left untouched — the downstream ValidatingAdmissionWebhook is responsible
for rejecting any values that violate policy.

   REQUIRED_SCALAR fields (runAsUser, runAsGroup, allowPrivilegeEscalation)
     The pod-level securityContext is patched (or created from scratch) to
     supply the default for any container that does not carry the field itself.

   OPTIONAL_SCALAR fields (fsGroup) and OPTIONAL_LIST fields (supplementalGroups)
     Absent is always acceptable for these fields, so no default is injected.

   NODE_SELECTOR (nodeLabel)
     • pod.spec.nodeName is always removed — it unconditionally bypasses nodeSelector.
     • If nodeSelector does not already contain the key specified in the default
       label, that key=value pair is injected.  If the key is already present
       (regardless of its value), it is left untouched.

Returns a (possibly empty) list of RFC 6902 JSON Patch operations.  The caller
base64-encodes the JSON-serialised list and returns it to the API server, which
then re-runs the mutated pod through all registered ValidatingAdmissionWebhooks.
"""
from __future__ import annotations

import copy
import logging
from typing import Any

from .validator import FieldBehavior, _FIELD_SPECS

logger = logging.getLogger(__name__)

DEFAULT_ANNOTATION_PREFIX = "sc.dsmlp.ucsd.edu/default."


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
    default_key = f"{DEFAULT_ANNOTATION_PREFIX}{field_name}"

    if default_key not in ns_annotations:
        logger.warning(
            "Constraint annotation %r is active but default annotation %r is absent "
            "from the namespace; cannot auto-remediate %r.",
            annotation_key, default_key, field_name,
        )
        return None

    raw = ns_annotations[default_key].strip()

    try:
        if field_name in ("runAsUser", "runAsGroup", "fsGroup", "supplementalGroups"):
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


_CONTAINER_KINDS = ("containers", "initContainers", "ephemeralContainers")


def _any_container_missing_field(pod: dict[str, Any], field_name: str) -> bool:
    """Return True if any container, initContainer, or ephemeralContainer is
    missing *field_name* in its securityContext (or has no securityContext)."""
    for kind in _CONTAINER_KINDS:
        for container in pod.get(kind) or []:
            sc = container.get("securityContext")
            if sc is None or field_name not in sc:
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


def _mutate_node_selector(
    pod: dict[str, Any],
    default_label: tuple[str, str] | None,
    patches: list[dict[str, Any]],
) -> None:
    """Mutate pod scheduling fields when sc.dsmlp.ucsd.edu/nodeLabel is active.

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


# Dispatch table: FieldBehavior → mutator function (excludes NODE_SELECTOR)
_SC_MUTATORS = {
    FieldBehavior.REQUIRED_SCALAR: _mutate_required_scalar,
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def mutate_pod(
    namespace_annotations: dict[str, str],
    pod_spec: dict[str, Any],
) -> list[dict[str, Any]]:
    """Compute RFC 6902 JSON Patch operations to fill in missing defaults in *pod_spec*.

    Parameters
    ----------
    namespace_annotations:
        All ``sc.dsmlp.ucsd.edu/*`` annotations scraped from the pod's namespace,
        including both constraint annotations and ``default.*`` annotations.
    pod_spec:
        The ``spec`` sub-dict from the Pod's AdmissionRequest object.

    Returns
    -------
    A (possibly empty) list of JSON Patch operation dicts.  Returns an empty
    list when no constraint annotations are active or no mutations are needed.
    The caller is responsible for JSON-serialising and base64-encoding the list.
    """
    pod = copy.deepcopy(pod_spec)
    patches: list[dict[str, Any]] = []

    # --- securityContext fields (REQUIRED_SCALAR only) ---
    for field_suffix, field_spec in _FIELD_SPECS.items():
        mutator = _SC_MUTATORS.get(field_spec.behavior)
        if mutator is None:
            continue  # OPTIONAL_SCALAR, OPTIONAL_LIST, NODE_SELECTOR handled elsewhere

        annotation_key = f"sc.dsmlp.ucsd.edu/{field_suffix}"
        if annotation_key not in namespace_annotations:
            continue

        default_value = _parse_default(field_suffix, annotation_key, namespace_annotations)
        if default_value is None:
            continue

        mutator(field_suffix, pod, default_value, patches)

    # --- nodeLabel (NODE_SELECTOR) ---
    node_label_key = "sc.dsmlp.ucsd.edu/nodeLabel"
    if node_label_key in namespace_annotations:
        nl_default = _parse_default("nodeLabel", node_label_key, namespace_annotations)
        _mutate_node_selector(pod, nl_default, patches)

    return patches
