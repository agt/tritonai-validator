"""Integration tests for the FastAPI /validate endpoint."""
import json
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _review(
    uid: str = "test-uid",
    kind: str = "Pod",
    namespace: str = "default",
    pod_spec: dict | None = None,
) -> dict:
    pod_spec = pod_spec or {
        "containers": [{"name": "app", "securityContext": {"runAsUser": 1000}}]
    }
    return {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "request": {
            "uid": uid,
            "kind": {"group": "", "version": "v1", "kind": kind},
            "namespace": namespace,
            "operation": "CREATE",
            "object": {"spec": pod_spec},
        },
    }


NS_ANNOTATIONS = {"sc.dsmlp.ucsd.edu/runAsUser": "1000"}


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------


def test_healthz():
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


# ---------------------------------------------------------------------------
# Non-Pod resources pass through
# ---------------------------------------------------------------------------


def test_non_pod_unsupported_kind_allowed():
    body = _review(kind="ServiceAccount")
    resp = client.post("/validate", json=body)
    assert resp.status_code == 200
    data = resp.json()
    assert data["response"]["allowed"] is True
    assert data["response"]["uid"] == "test-uid"


# ---------------------------------------------------------------------------
# Pod validation
# ---------------------------------------------------------------------------


def test_pod_allowed_when_constraints_satisfied():
    with patch("app.main.get_namespace_security_annotations", return_value=NS_ANNOTATIONS):
        body = _review(
            pod_spec={
                "securityContext": {"runAsNonRoot": True},
                "containers": [{"name": "app", "securityContext": {"runAsUser": 1000}}],
            }
        )
        resp = client.post("/validate", json=body)
    assert resp.status_code == 200
    assert resp.json()["response"]["allowed"] is True


def test_pod_denied_when_constraint_fails():
    with patch("app.main.get_namespace_security_annotations", return_value=NS_ANNOTATIONS):
        body = _review(
            pod_spec={"containers": [{"name": "app", "securityContext": {"runAsUser": 999}}]}
        )
        resp = client.post("/validate", json=body)
    assert resp.status_code == 200
    data = resp.json()
    assert data["response"]["allowed"] is False
    assert "runAsUser" in data["response"]["status"]["message"]


def test_pod_denied_when_no_namespace_annotations():
    with patch("app.main.get_namespace_security_annotations", return_value={}):
        body = _review()
        resp = client.post("/validate", json=body)
    assert resp.status_code == 200
    assert resp.json()["response"]["allowed"] is False


def test_pod_denied_when_missing_namespace():
    body = _review()
    body["request"]["namespace"] = None
    resp = client.post("/validate", json=body)
    assert resp.status_code == 200
    assert resp.json()["response"]["allowed"] is False


# ---------------------------------------------------------------------------
# Malformed requests
# ---------------------------------------------------------------------------


def test_bad_json_returns_400():
    resp = client.post("/validate", content=b"not json", headers={"content-type": "application/json"})
    assert resp.status_code == 400


def test_missing_request_field_returns_400():
    resp = client.post("/validate", json={"apiVersion": "admission.k8s.io/v1", "kind": "AdmissionReview"})
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Response structure conforms to k8s spec
# ---------------------------------------------------------------------------


def test_response_contains_uid():
    with patch("app.main.get_namespace_security_annotations", return_value=NS_ANNOTATIONS):
        body = _review(uid="my-unique-uid-123")
        body["request"]["object"]["spec"]["containers"][0]["securityContext"]["runAsUser"] = 1000
        resp = client.post("/validate", json=body)
    assert resp.json()["response"]["uid"] == "my-unique-uid-123"


def test_response_apiversion_and_kind():
    with patch("app.main.get_namespace_security_annotations", return_value=NS_ANNOTATIONS):
        body = _review()
        resp = client.post("/validate", json=body)
    data = resp.json()
    assert data["apiVersion"] == "admission.k8s.io/v1"
    assert data["kind"] == "AdmissionReview"
