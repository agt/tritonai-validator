"""
Pydantic models for Kubernetes AdmissionReview v1.

Only the fields required by this webhook are modelled; additional fields
present in real requests are ignored via model_config extra="allow".
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class GroupVersionKind(BaseModel):
    model_config = {"extra": "allow"}

    group: str = ""
    version: str = ""
    kind: str = ""


class AdmissionRequest(BaseModel):
    model_config = {"extra": "allow"}

    uid: str
    kind: GroupVersionKind = Field(default_factory=GroupVersionKind)
    namespace: str | None = None
    operation: str = ""
    object: dict[str, Any] | None = None
    oldObject: dict[str, Any] | None = None


class AdmissionReview(BaseModel):
    """Incoming AdmissionReview from the API server."""

    model_config = {"extra": "allow"}

    apiVersion: str = "admission.k8s.io/v1"
    kind: str = "AdmissionReview"
    request: AdmissionRequest | None = None


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class StatusDetails(BaseModel):
    """Optional structured rejection reason returned to the API server."""

    message: str
    reason: str = "Forbidden"
    code: int = 403


class AdmissionResponse(BaseModel):
    uid: str
    allowed: bool
    status: StatusDetails | None = None


class AdmissionReviewResponse(BaseModel):
    """Outgoing AdmissionReview sent back to the API server."""

    apiVersion: str = "admission.k8s.io/v1"
    kind: str = "AdmissionReview"
    response: AdmissionResponse

    def model_dump_json(self, **kwargs: Any) -> str:  # type: ignore[override]
        kwargs.setdefault("exclude_none", True)
        return super().model_dump_json(**kwargs)
