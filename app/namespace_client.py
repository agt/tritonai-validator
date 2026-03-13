"""
Kubernetes namespace client.

Fetches namespace annotations so the validator can read per-namespace
security policy annotations.  Supports both in-cluster (service account)
and out-of-cluster (kubeconfig) authentication transparently.

Policy resolution order
───────────────────────
1. Read the subject pod's namespace labels.
2. Look each ``label=value`` up in the policy index ConfigMap
   (``POLICY_INDEX_CONFIGMAP`` in ``WEBHOOK_NAMESPACE``).  Any matching
   entries identify policy ConfigMaps whose data stands in for namespace
   annotations.
3. If one or more matches are found, fetch those policy ConfigMaps.  Each
   ConfigMap becomes its own annotation layer (in lexical order of the
   matching ``label=value`` key).  The namespace's own annotations are
   appended as an additional layer.
4. If no index entries match, the namespace's own annotations form the
   single layer.

The caller receives a ``list[dict[str, str]]`` — one dict per source layer.
Validators apply AND semantics across layers (a pod must satisfy all layers).
The mutator merges layers before use via ``merge_annotation_layers()``.

Both the index ConfigMap and each policy ConfigMap are cached for
``POLICY_CACHE_TTL`` seconds (default 10 minutes).  On fetch errors the
previously cached value is returned if available; otherwise an empty dict
is used so the webhook degrades gracefully.
"""
from __future__ import annotations

import asyncio
import logging
import time
from functools import lru_cache

from kubernetes import client, config  # type: ignore[import-untyped]
from kubernetes.client.exceptions import ApiException  # type: ignore[import-untyped]

from .config import (
    ANNOTATION_NS,
    POLICY_CACHE_TTL,
    POLICY_INDEX_CONFIGMAP,
    WEBHOOK_NAMESPACE,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Kubernetes client
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# TTL-cached ConfigMap helpers
# ---------------------------------------------------------------------------

# Index cache: maps "label.value" → policy ConfigMap name.
_index_data: dict[str, str] | None = None
_index_expires: float = 0.0

# Per-policy cache: ConfigMap name → (data dict, expiry timestamp).
_policy_cache: dict[str, tuple[dict[str, str], float]] = {}


def _get_index() -> dict[str, str]:
    """Return the index ConfigMap data, refreshing from the API when stale.

    The index ConfigMap lives in ``WEBHOOK_NAMESPACE`` and maps
    ``label.value`` strings to policy ConfigMap names, e.g.::

        data:
          "team.research": research-policy
          "tier.gpu":      gpu-policy

    A missing ConfigMap (404) is treated as an empty index (no label
    mappings configured).  On other errors the last known data is reused;
    if there is no prior data, an empty dict is returned.
    """
    global _index_data, _index_expires
    now = time.monotonic()
    if _index_data is not None and now < _index_expires:
        return _index_data

    try:
        api = _get_core_v1_api()
        cm = api.read_namespaced_config_map(POLICY_INDEX_CONFIGMAP, WEBHOOK_NAMESPACE)
        data: dict[str, str] = cm.data or {}
        logger.debug(
            "Loaded policy index ConfigMap %r/%r (%d entries)",
            WEBHOOK_NAMESPACE, POLICY_INDEX_CONFIGMAP, len(data),
        )
    except ApiException as exc:
        if exc.status == 404:
            logger.debug(
                "Policy index ConfigMap %r/%r not found; no label mappings active.",
                WEBHOOK_NAMESPACE, POLICY_INDEX_CONFIGMAP,
            )
            data = {}
        else:
            logger.warning(
                "Failed to fetch policy index ConfigMap %r/%r: %s %s",
                WEBHOOK_NAMESPACE, POLICY_INDEX_CONFIGMAP, exc.status, exc.reason,
            )
            data = _index_data or {}
    except Exception:
        logger.exception(
            "Unexpected error fetching policy index ConfigMap %r/%r",
            WEBHOOK_NAMESPACE, POLICY_INDEX_CONFIGMAP,
        )
        data = _index_data or {}

    _index_data = data
    _index_expires = now + POLICY_CACHE_TTL
    return data


def _normalise_cm_key(key: str) -> str:
    """Normalise a ConfigMap data key to a full annotation key.

    Accepts any of:
    - bare suffix:          ``policy.runAsUser``
    - arbitrary prefix:     ``other-ns/policy.runAsUser``
    - correct full key:     ``tritonai-admission-webhook/policy.runAsUser``

    All three map to ``tritonai-admission-webhook/policy.runAsUser``.
    """
    if key.startswith(ANNOTATION_NS):
        return key
    suffix = key.split("/", 1)[-1]  # strips any leading "prefix/" if present
    return f"{ANNOTATION_NS}{suffix}"


def _get_policy_cm(name: str) -> dict[str, str]:
    """Return the data from the named policy ConfigMap, refreshing when stale.

    Policy ConfigMaps live in ``WEBHOOK_NAMESPACE`` and their ``data``
    entries can use the full annotation key or a shorter form::

        data:
          policy.runAsUser: "1000,>5000000"          # bare suffix
          default.runAsUser: "1000"                   # bare suffix
          # or equivalently:
          tritonai-admission-webhook/policy.runAsUser: "1000,>5000000"
          arbitrary-prefix/default.runAsUser: "1000"  # any prefix stripped

    All key forms are normalised to the canonical
    ``<ANNOTATION_NS><suffix>`` form before being returned.

    On fetch errors the last cached value is reused; if none exists, an
    empty dict is returned so the webhook degrades gracefully.
    """
    now = time.monotonic()
    cached = _policy_cache.get(name)
    if cached is not None:
        data, expires = cached
        if now < expires:
            return data
        stale_data = data
    else:
        stale_data = {}

    try:
        api = _get_core_v1_api()
        cm = api.read_namespaced_config_map(name, WEBHOOK_NAMESPACE)
        data = {_normalise_cm_key(k): v for k, v in (cm.data or {}).items()}
        logger.debug(
            "Loaded policy ConfigMap %r/%r (%d keys)", WEBHOOK_NAMESPACE, name, len(data)
        )
    except ApiException as exc:
        logger.warning(
            "Failed to fetch policy ConfigMap %r/%r: %s %s",
            WEBHOOK_NAMESPACE, name, exc.status, exc.reason,
        )
        data = stale_data
    except Exception:
        logger.exception(
            "Unexpected error fetching policy ConfigMap %r/%r", WEBHOOK_NAMESPACE, name
        )
        data = stale_data

    _policy_cache[name] = (data, now + POLICY_CACHE_TTL)
    return data


def _resolve_configmap_policy(ns_labels: dict[str, str]) -> list[dict[str, str]]:
    """Return per-ConfigMap annotation layers matched by namespace labels.

    For each ``label=value`` present on the subject namespace, checks the
    policy index for a matching entry.  All matching policy ConfigMaps are
    fetched in **lexical order of the** ``label=value`` **key** and returned
    as individual dicts so that callers can apply AND semantics across layers.

    Returns an empty list when the index is empty or no namespace label
    matches any index entry.
    """
    index = _get_index()
    if not index:
        return []

    # Collect (label.value, configmap_name) pairs for all matching labels.
    matches: list[tuple[str, str]] = []
    for label_key, label_value in ns_labels.items():
        lookup_key = f"{label_key}.{label_value}"
        cm_name = index.get(lookup_key)
        if cm_name:
            matches.append((lookup_key, cm_name))

    if not matches:
        return []

    # Return one layer per ConfigMap, in lexical order of the label=value string.
    matches.sort(key=lambda pair: pair[0])
    layers: list[dict[str, str]] = []
    for lookup_key, cm_name in matches:
        logger.debug(
            "Namespace label %r matched policy ConfigMap %r", lookup_key, cm_name
        )
        layers.append(_get_policy_cm(cm_name))

    return layers


def _fetch_namespace_security_annotations(namespace: str) -> list[dict[str, str]]:
    """Synchronous implementation that fetches namespace annotation layers.

    Returns an ordered list of per-source annotation dicts (each filtered to
    the ``ANNOTATION_NS`` prefix):
      - One dict per matching ConfigMap, in lexical order of label=value key
      - One dict for the namespace's own annotations (always appended last)

    Returns a list containing a single empty dict on errors so the webhook
    emits a clear rejection message rather than a 500.
    """
    try:
        api = _get_core_v1_api()
        ns_obj = api.read_namespace(namespace)
        labels: dict[str, str] = ns_obj.metadata.labels or {}
        annotations: dict[str, str] = ns_obj.metadata.annotations or {}
    except ApiException as exc:
        logger.error(
            "Failed to fetch namespace %r: %s %s", namespace, exc.status, exc.reason
        )
        return [{}]
    except Exception:
        logger.exception("Unexpected error fetching namespace %r", namespace)
        return [{}]

    ns_own = {k: v for k, v in annotations.items() if k.startswith(ANNOTATION_NS)}
    cm_layers = _resolve_configmap_policy(labels)
    return [*cm_layers, ns_own]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def merge_annotation_layers(layers: list[dict[str, str]]) -> dict[str, str]:
    """Merge annotation layers left-to-right (last writer wins).

    Used by the mutator, which injects per-namespace defaults and benefits
    from namespace annotations taking precedence over ConfigMap entries.
    Validators should use AND semantics instead (see ``validate_pod``).
    """
    merged: dict[str, str] = {}
    for layer in layers:
        merged.update(layer)
    return merged


async def get_namespace_security_annotations(namespace: str) -> list[dict[str, str]]:
    """Return per-source annotation layers from *namespace*.

    Each element is a ``dict[str, str]`` containing the ``<ANNOTATION_PREFIX>/*``
    annotations from one policy source (ConfigMap or namespace).  Runs the
    blocking Kubernetes API call in a thread pool via ``asyncio.to_thread()``.
    """
    return await asyncio.to_thread(_fetch_namespace_security_annotations, namespace)
