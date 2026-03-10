"""
Shared helpers for reading pod specs and container lists.

Used by both the mutator and validator to avoid duplication.
"""
from __future__ import annotations

from typing import Any


def _pod_sc(pod_spec: dict[str, Any]) -> dict[str, Any]:
    return pod_spec.get("securityContext") or {}


def _all_containers(pod_spec: dict[str, Any]) -> list[dict[str, Any]]:
    return (
        list(pod_spec.get("containers") or [])
        + list(pod_spec.get("initContainers") or [])
        + list(pod_spec.get("ephemeralContainers") or [])
    )


def _container_sc(container: dict[str, Any]) -> dict[str, Any]:
    return container.get("securityContext") or {}


def _container_name(container: dict[str, Any]) -> str:
    return container.get("name", "<unnamed>")


def _is_node_kubernetes_toleration(tol: dict[str, Any]) -> bool:
    """Return True if the toleration key is in the node.kubernetes.io/* namespace.

    Kubernetes itself adds these tolerations automatically for node conditions
    (e.g. node.kubernetes.io/not-ready, node.kubernetes.io/unreachable).
    They are always considered implicitly permitted and are never injected as
    user-configurable defaults.
    """
    return tol.get("key", "").startswith("node.kubernetes.io/")
