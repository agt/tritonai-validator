"""
Kubernetes Admission Webhooks — FastAPI entry point.

Endpoints:
  POST /mutate    MutatingAdmissionWebhook  — patches pods toward compliance
  POST /validate  ValidatingAdmissionWebhook — rejects non-compliant pods

The mutating webhook runs first and attempts to bring pods into compliance
using per-namespace default annotations (sc.dsmlp.ucsd.edu/default.*).
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
from .mutator import mutate_pod
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
        "sc.dsmlp.ucsd.edu/* security policy."
    ),
    version="1.0.0",
)


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
    """ValidatingAdmissionWebhook endpoint."""
    review = await _parse_admission_review(request)

    if review.request is None:
        raise HTTPException(status_code=400, detail="AdmissionReview missing 'request' field")

    req = review.request
    uid = req.uid

    # Only handle Pod resources; allow everything else through
    if req.kind.kind != "Pod":
        logger.debug("Allowing non-Pod resource kind=%s uid=%s", req.kind.kind, uid)
        return _json_response(_allow(uid))

    # Namespace is required for policy look-up
    namespace = req.namespace
    if not namespace:
        return _json_response(
            _deny(uid, "Pod has no namespace; cannot determine security policy.")
        )

    # Pod spec is required
    pod_object = req.object or {}
    pod_spec: dict[str, Any] = pod_object.get("spec") or {}
    if not pod_spec:
        return _json_response(_deny(uid, "AdmissionRequest contains no pod spec."))

    # Fetch namespace security annotations
    ns_annotations = get_namespace_security_annotations(namespace)
    logger.debug(
        "Namespace %r annotations: %s", namespace, ns_annotations
    )

    # Validate
    result = validate_pod(ns_annotations, pod_spec)

    if result.allowed:
        logger.info(
            "Allowing pod uid=%s in namespace=%s (all constraints satisfied)",
            uid,
            namespace,
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

    Attempts to patch the pod spec toward compliance using the namespace's
    ``sc.dsmlp.ucsd.edu/default.*`` annotations.  Always returns
    ``allowed: true``; non-compliant pods that could not be fully remediated
    are left for the ValidatingAdmissionWebhook to reject.
    """
    review = await _parse_admission_review(request)

    if review.request is None:
        raise HTTPException(status_code=400, detail="AdmissionReview missing 'request' field")

    req = review.request
    uid = req.uid

    # Pass non-Pod resources through without modification
    if req.kind.kind != "Pod":
        return _json_response(_allow(uid))

    namespace = req.namespace
    pod_object = req.object or {}
    pod_spec: dict[str, Any] = pod_object.get("spec") or {}

    if not namespace or not pod_spec:
        # Nothing useful to mutate; validator will handle rejection
        return _json_response(_allow(uid))

    ns_annotations = get_namespace_security_annotations(namespace)
    patches = mutate_pod(ns_annotations, pod_spec)

    if patches:
        logger.info(
            "Mutating pod uid=%s in namespace=%s: %d patch operation(s)",
            uid, namespace, len(patches),
        )
        logger.debug(
            "Mutating pod uid=%s in namespace=%s: %d patch operation(s): %s",
            uid, namespace, len(patches),str(patches),
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
