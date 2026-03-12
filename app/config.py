import os

ANNOTATION_PREFIX: str = os.environ.get("ANNOTATION_PREFIX", "tritonai-admission-webhook")
ANNOTATION_NS: str = f"{ANNOTATION_PREFIX}/"
POLICY_PREFIX: str = f"{ANNOTATION_NS}policy."
DEFAULT_PREFIX: str = f"{ANNOTATION_NS}default."

# ---------------------------------------------------------------------------
# ConfigMap-based policy lookup
# ---------------------------------------------------------------------------


def _detect_webhook_namespace() -> str:
    """Return the namespace this webhook runs in.

    Reads the in-cluster service-account namespace file; falls back to a
    hardcoded default for local development outside a pod.
    """
    try:
        with open("/var/run/secrets/kubernetes.io/serviceaccount/namespace") as f:
            return f.read().strip()
    except OSError:
        return "tgptinf-system"


# Namespace where the webhook itself runs; used for ConfigMap lookups.
WEBHOOK_NAMESPACE: str = _detect_webhook_namespace()

# Name of the index ConfigMap that maps "label.value" → policy ConfigMap name.
POLICY_INDEX_CONFIGMAP: str = os.environ.get(
    "POLICY_INDEX_CONFIGMAP", "pod-security-policy-index"
)

# TTL in seconds for the index ConfigMap cache and per-policy ConfigMap caches.
POLICY_CACHE_TTL: float = float(os.environ.get("POLICY_CACHE_TTL", "600"))
