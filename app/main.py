"""
Kubernetes Validating Admission Webhook — FastAPI entry point.

Endpoint:  POST /validate
  Accepts:  AdmissionReview (application/json)
  Returns:  AdmissionReview with response.allowed set

TLS termination is expected to be handled externally (e.g. via a sidecar or
ingress), but the server can also be started with SSL certificates directly
via uvicorn's --ssl-keyfile / --ssl-certfile flags.
"""
from __future__ import annotations

import logging
import os
from typing import Any

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse

from .models import (
    AdmissionResponse,
    AdmissionReview,
    AdmissionReviewResponse,
    StatusDetails,
)
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
    title="TritonAI Pod Security Admission Webhook",
    description=(
        "Validates Pod admission against per-namespace sc.dsmlp.ucsd.edu/* annotations."
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
    """Main admission webhook endpoint."""
    body: dict[str, Any]
    try:
        body = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid JSON body: {exc}") from exc

    try:
        review = AdmissionReview.model_validate(body)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid AdmissionReview: {exc}") from exc

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
