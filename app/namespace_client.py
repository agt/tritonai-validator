"""
Kubernetes namespace client.

Fetches namespace annotations so the validator can read per-namespace
security policy annotations.  Supports both in-cluster (service account)
and out-of-cluster (kubeconfig) authentication transparently.
"""
from __future__ import annotations

import logging
from functools import lru_cache

from kubernetes import client, config  # type: ignore[import-untyped]
from kubernetes.client.exceptions import ApiException  # type: ignore[import-untyped]

logger = logging.getLogger(__name__)

# Annotation prefix used by this webhook
ANNOTATION_PREFIX = "sc.dsmlp.ucsd.edu/"


def _load_k8s_config() -> None:
    """Load kubeconfig, preferring in-cluster config."""
    try:
        config.load_incluster_config()
        logger.debug("Loaded in-cluster Kubernetes config")
    except config.ConfigException:
        config.load_kube_config()
        logger.debug("Loaded out-of-cluster kubeconfig")


@lru_cache(maxsize=1)
def _get_core_v1_api() -> client.CoreV1Api:
    _load_k8s_config()
    return client.CoreV1Api()


def get_namespace_security_annotations(namespace: str) -> dict[str, str]:
    """Return a dict of ``sc.dsmlp.ucsd.edu/*`` annotations from *namespace*.

    Returns an empty dict if the namespace has no relevant annotations or
    cannot be retrieved (errors are logged but not re-raised so the webhook
    can return a clear rejection message rather than a 500).

    The returned keys are full annotation strings, e.g.:
        {"sc.dsmlp.ucsd.edu/runAsUser": "1000,2000-3000"}
    """
    try:
        api = _get_core_v1_api()
        ns_obj = api.read_namespace(namespace)
        annotations: dict[str, str] = ns_obj.metadata.annotations or {}
        return {
            key: value
            for key, value in annotations.items()
            if key.startswith(ANNOTATION_PREFIX)
        }
    except ApiException as exc:
        logger.error(
            "Failed to fetch namespace %r annotations: %s %s",
            namespace,
            exc.status,
            exc.reason,
        )
        return {}
    except Exception:
        logger.exception("Unexpected error fetching namespace %r annotations", namespace)
        return {}
