"""
Kubernetes Admission Webhooks — FastAPI entry point.

Endpoints:
  POST /mutate    MutatingAdmissionWebhook  — patches pods toward compliance
  POST /validate  ValidatingAdmissionWebhook — rejects non-compliant pods

The mutating webhook runs first and attempts to bring pods into compliance
using per-namespace default annotations (<ANNOTATION_PREFIX>/default.*).
The API server then re-runs the (possibly mutated) pod through the validating
webhook, which performs the final accept/reject decision.

TLS termination is expected to be handled externally (e.g. via a sidecar or
ingress), but the server can also be started with SSL certificates directly
via uvicorn's --ssl-keyfile / --ssl-certfile flags.
"""
from __future__ import annotations

import base64
import json
import logging
import os
from typing import Any

from fastapi import FastAPI, HTTPException, Request, Response

from .models import (
    AdmissionResponse,
    AdmissionReview,
    AdmissionReviewResponse,
    StatusDetails,
)
from .mutator import mutate_pod, mutate_pod_spec
from .namespace_client import get_namespace_security_annotations
from .validator import validate_pod

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
app = FastAPI(
    title="TritonAI Pod Security Admission Webhooks",
    description=(
        "Mutating + Validating admission webhooks enforcing per-namespace "
        "per-namespace security policy."
    ),
    version="1.0.0",
)


# ---------------------------------------------------------------------------
# Workload support
# ---------------------------------------------------------------------------

# Maps a workload kind to the key path leading to its pod template spec.
# The path ends at the pod template's "spec" dict (i.e. the container list lives here).
_WORKLOAD_TEMPLATE_PATHS: dict[str, tuple[str, ...]] = {
    "Deployment":  ("spec", "template", "spec"),
    "ReplicaSet":  ("spec", "template", "spec"),
    "StatefulSet": ("spec", "template", "spec"),
    "DaemonSet":   ("spec", "template", "spec"),
    "Job":         ("spec", "template", "spec"),
    "CronJob":     ("spec", "jobTemplate", "spec", "template", "spec"),
}


def _get_template_spec(obj: dict[str, Any], path: tuple[str, ...]) -> dict[str, Any] | None:
    """Walk *path* through *obj* and return the nested dict, or None if missing."""
    node: Any = obj
    for key in path:
        if not isinstance(node, dict):
            return None
        node = node.get(key)
        if not node:
            return None
    return node if isinstance(node, dict) else None


def _template_spec_pointer(path: tuple[str, ...]) -> str:
    """Return the JSON Pointer prefix for the pod template spec (e.g. /spec/template/spec)."""
    return "/" + "/".join(path)


def _rewrite_patch_paths(
    patches: list[dict[str, Any]], template_spec_ptr: str
) -> list[dict[str, Any]]:
    """Rewrite patches produced by mutate_pod (rooted at /spec) to be rooted at *template_spec_ptr*.

    Example: /spec/securityContext → /spec/template/spec/securityContext
    """
    prefix = "/spec"
    return [
        {**p, "path": template_spec_ptr + p["path"][len(prefix):]}
        for p in patches
    ]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _allow(uid: str) -> AdmissionReviewResponse:
    return AdmissionReviewResponse(
        response=AdmissionResponse(uid=uid, allowed=True)
    )


def _deny(uid: str, message: str) -> AdmissionReviewResponse:
    logger.info("Denying pod uid=%s: %s", uid, message)
    return AdmissionReviewResponse(
        response=AdmissionResponse(
            uid=uid,
            allowed=False,
            status=StatusDetails(message=message),
        )
    )


def _json_response(review: AdmissionReviewResponse) -> Response:
    """Serialize using Pydantic (exclude_none) and return as JSONResponse."""
    return Response(
        content=review.model_dump_json(exclude_none=True),
        media_type="application/json",
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.get("/healthz", status_code=200)
async def healthz() -> dict[str, str]:
    """Liveness / readiness probe."""
    return {"status": "ok"}


@app.post("/validate")
async def validate(request: Request) -> Response:
    """ValidatingAdmissionWebhook endpoint.

    Handles Pod resources directly and also validates the pod templates
    embedded in workload resources (Deployment, ReplicaSet, StatefulSet,
    DaemonSet, Job, CronJob).  For workloads, namespace defaults are applied
    to the template spec via the mutator before validation so that the
    validator sees the same spec the API server would ultimately use.
    """
    review = await _parse_admission_review(request)

    if review.request is None:
        raise HTTPException(status_code=400, detail="AdmissionReview missing 'request' field")

    req = review.request
    uid = req.uid
    kind = req.kind.kind

    # Determine whether this is a Pod or a supported workload kind
    template_path = _WORKLOAD_TEMPLATE_PATHS.get(kind)
    is_pod = kind == "Pod"

    if not is_pod and template_path is None:
        logger.debug("Allowing unsupported resource kind=%s uid=%s", kind, uid)
        return _json_response(_allow(uid))

    # Namespace is required for policy look-up
    namespace = req.namespace
    if not namespace:
        return _json_response(
            _deny(uid, f"{kind} has no namespace; cannot determine security policy.")
        )

    obj = req.object or {}

    if is_pod:
        pod_spec: dict[str, Any] = obj.get("spec") or {}
        if not pod_spec:
            return _json_response(_deny(uid, "AdmissionRequest contains no pod spec."))
    else:
        pod_spec = _get_template_spec(obj, template_path) or {}  # type: ignore[arg-type]
        if not pod_spec:
            logger.debug(
                "Allowing %s uid=%s: pod template spec not found or empty", kind, uid
            )
            return _json_response(_allow(uid))

    # Fetch namespace security annotations
    ns_annotations = await get_namespace_security_annotations(namespace)
    logger.debug("Namespace %r annotations: %s", namespace, ns_annotations)

    # For workloads, apply mutations so the validator sees post-mutation defaults
    if not is_pod:
        pod_spec = mutate_pod_spec(ns_annotations, pod_spec)

    # Validate
    result = validate_pod(ns_annotations, pod_spec)

    if result.allowed:
        logger.info(
            "Allowing %s uid=%s in namespace=%s (all constraints satisfied)",
            kind, uid, namespace,
        )
        return _json_response(_allow(uid))

    return _json_response(_deny(uid, result.message))


def _allow_with_patches(
    uid: str, patches: list[dict[str, Any]]
) -> AdmissionReviewResponse:
    """Build an allow response that carries a JSON Patch payload."""
    encoded = base64.b64encode(json.dumps(patches).encode()).decode()
    return AdmissionReviewResponse(
        response=AdmissionResponse(
            uid=uid,
            allowed=True,
            patchType="JSONPatch",
            patch=encoded,
        )
    )


async def _parse_admission_review(request: Request) -> AdmissionReview:
    """Parse and validate the incoming AdmissionReview body."""
    try:
        body = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid JSON body: {exc}") from exc
    try:
        return AdmissionReview.model_validate(body)
    except Exception as exc:
        raise HTTPException(
            status_code=400, detail=f"Invalid AdmissionReview: {exc}"
        ) from exc


@app.post("/mutate")
async def mutate(request: Request) -> Response:
    """MutatingAdmissionWebhook endpoint.

    Only patches **Pod** resources.  All other resource kinds (including
    Deployment, Job, CronJob, etc.) are passed through unmodified.  The
    validating webhook handles workload template validation internally by
    calling the mutator itself before running policy checks.

    Always returns ``allowed: true``; non-compliant pods that could not be
    fully remediated are left for the ValidatingAdmissionWebhook to reject.
    """
    review = await _parse_admission_review(request)

    if review.request is None:
        raise HTTPException(status_code=400, detail="AdmissionReview missing 'request' field")

    req = review.request
    uid = req.uid

    # Only patch Pod resources; pass everything else through unmodified
    if req.kind.kind != "Pod":
        return _json_response(_allow(uid))

    namespace = req.namespace
    obj = req.object or {}
    pod_spec: dict[str, Any] = obj.get("spec") or {}

    if not namespace or not pod_spec:
        # Nothing useful to mutate; validator will handle rejection if needed
        return _json_response(_allow(uid))

    ns_annotations = await get_namespace_security_annotations(namespace)
    patches = mutate_pod(ns_annotations, pod_spec)

    if patches:
        logger.info(
            "Mutating pod uid=%s in namespace=%s: %d patch operation(s)",
            uid, namespace, len(patches),
        )
        return _json_response(_allow_with_patches(uid, patches))

    return _json_response(_allow(uid))


# ---------------------------------------------------------------------------
# Dev entrypoint
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "8443")),
        ssl_keyfile=os.environ.get("TLS_KEY_FILE"),
        ssl_certfile=os.environ.get("TLS_CERT_FILE"),
        log_level=os.environ.get("LOG_LEVEL", "info").lower(),
    )
