"""Integration tests for workload (Deployment, Job, CronJob, etc.) support
in the /validate and /mutate endpoints."""
import base64
import json
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.main import app, _get_template_spec, _rewrite_patch_paths, _template_spec_pointer

client = TestClient(app)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

NS_ANNOTATIONS = {"sc.dsmlp.ucsd.edu/runAsUser": "1000"}

# A pod spec that satisfies all hardcoded constraints and the runAsUser annotation
_VALID_POD_SPEC = {
    "containers": [
        {"name": "app", "securityContext": {"runAsUser": 1000, "runAsNonRoot": True, "allowPrivilegeEscalation": False}}
    ]
}

# A pod spec that violates runAsUser
_BAD_POD_SPEC = {
    "containers": [
        {"name": "app", "securityContext": {"runAsUser": 999, "runAsNonRoot": True, "allowPrivilegeEscalation": False}}
    ]
}


def _deployment_review(uid="u1", namespace="ns1", pod_spec=None, template_labels=None):
    pod_spec = pod_spec or _VALID_POD_SPEC
    return {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "request": {
            "uid": uid,
            "kind": {"group": "apps", "version": "v1", "kind": "Deployment"},
            "namespace": namespace,
            "operation": "CREATE",
            "object": {
                "spec": {
                    "template": {
                        "metadata": {"labels": template_labels or {"app": "test"}},
                        "spec": pod_spec,
                    }
                }
            },
        },
    }


def _cronjob_review(uid="u1", namespace="ns1", pod_spec=None):
    pod_spec = pod_spec or _VALID_POD_SPEC
    return {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "request": {
            "uid": uid,
            "kind": {"group": "batch", "version": "v1", "kind": "CronJob"},
            "namespace": namespace,
            "operation": "CREATE",
            "object": {
                "spec": {
                    "schedule": "0 * * * *",
                    "jobTemplate": {
                        "spec": {
                            "template": {
                                "spec": pod_spec,
                            }
                        }
                    },
                }
            },
        },
    }


def _workload_review(kind, uid="u1", namespace="ns1", pod_spec=None):
    """Generic workload review builder for kinds with spec.template.spec layout."""
    pod_spec = pod_spec or _VALID_POD_SPEC
    return {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "request": {
            "uid": uid,
            "kind": {"group": "apps", "version": "v1", "kind": kind},
            "namespace": namespace,
            "operation": "CREATE",
            "object": {
                "spec": {
                    "template": {
                        "spec": pod_spec,
                    }
                }
            },
        },
    }


def _decode_patches(response_data: dict) -> list[dict]:
    patch_b64 = response_data["response"]["patch"]
    return json.loads(base64.b64decode(patch_b64))


# ---------------------------------------------------------------------------
# Unit tests for main.py helpers
# ---------------------------------------------------------------------------


class TestGetTemplateSpec:
    def test_simple_path(self):
        obj = {"spec": {"template": {"spec": {"containers": []}}}}
        result = _get_template_spec(obj, ("spec", "template", "spec"))
        assert result == {"containers": []}

    def test_cronjob_path(self):
        obj = {
            "spec": {
                "jobTemplate": {
                    "spec": {
                        "template": {
                            "spec": {"containers": []}
                        }
                    }
                }
            }
        }
        result = _get_template_spec(obj, ("spec", "jobTemplate", "spec", "template", "spec"))
        assert result == {"containers": []}

    def test_missing_intermediate_key_returns_none(self):
        obj = {"spec": {}}
        assert _get_template_spec(obj, ("spec", "template", "spec")) is None

    def test_empty_object_returns_none(self):
        assert _get_template_spec({}, ("spec", "template", "spec")) is None

    def test_non_dict_node_returns_none(self):
        obj = {"spec": "not-a-dict"}
        assert _get_template_spec(obj, ("spec", "template")) is None


class TestTemplateSpecPointer:
    def test_deployment_pointer(self):
        assert _template_spec_pointer(("spec", "template", "spec")) == "/spec/template/spec"

    def test_cronjob_pointer(self):
        assert _template_spec_pointer(
            ("spec", "jobTemplate", "spec", "template", "spec")
        ) == "/spec/jobTemplate/spec/template/spec"


class TestRewritePatchPaths:
    def test_rewrites_securitycontext_path(self):
        patches = [{"op": "add", "path": "/spec/securityContext", "value": {"runAsUser": 1000, "runAsNonRoot": True}}]
        result = _rewrite_patch_paths(patches, "/spec/template/spec")
        assert result[0]["path"] == "/spec/template/spec/securityContext"

    def test_rewrites_nodeselector_path(self):
        patches = [{"op": "add", "path": "/spec/nodeSelector", "value": {"k": "v"}}]
        result = _rewrite_patch_paths(patches, "/spec/template/spec")
        assert result[0]["path"] == "/spec/template/spec/nodeSelector"

    def test_rewrites_nodename_removal(self):
        patches = [{"op": "remove", "path": "/spec/nodeName"}]
        result = _rewrite_patch_paths(patches, "/spec/template/spec")
        assert result[0]["path"] == "/spec/template/spec/nodeName"

    def test_preserves_op_and_value(self):
        patches = [{"op": "add", "path": "/spec/securityContext", "value": 42}]
        result = _rewrite_patch_paths(patches, "/spec/template/spec")
        assert result[0]["op"] == "add"
        assert result[0]["value"] == 42

    def test_rewrites_cronjob_path(self):
        patches = [{"op": "add", "path": "/spec/securityContext", "value": {}}]
        result = _rewrite_patch_paths(patches, "/spec/jobTemplate/spec/template/spec")
        assert result[0]["path"] == "/spec/jobTemplate/spec/template/spec/securityContext"

    def test_empty_patches(self):
        assert _rewrite_patch_paths([], "/spec/template/spec") == []


# ---------------------------------------------------------------------------
# /validate — workload kinds
# ---------------------------------------------------------------------------


class TestValidateWorkloads:
    @pytest.mark.parametrize("kind", ["Deployment", "ReplicaSet", "StatefulSet", "DaemonSet", "Job"])
    def test_valid_workload_allowed(self, kind):
        with patch("app.main.get_namespace_security_annotations", return_value=NS_ANNOTATIONS):
            body = _workload_review(kind, pod_spec=_VALID_POD_SPEC)
            resp = client.post("/validate", json=body)
        assert resp.status_code == 200
        assert resp.json()["response"]["allowed"] is True

    @pytest.mark.parametrize("kind", ["Deployment", "ReplicaSet", "StatefulSet", "DaemonSet", "Job"])
    def test_invalid_workload_denied(self, kind):
        with patch("app.main.get_namespace_security_annotations", return_value=NS_ANNOTATIONS):
            body = _workload_review(kind, pod_spec=_BAD_POD_SPEC)
            resp = client.post("/validate", json=body)
        assert resp.status_code == 200
        data = resp.json()
        assert data["response"]["allowed"] is False
        assert "runAsUser" in data["response"]["status"]["message"]

    def test_valid_cronjob_allowed(self):
        with patch("app.main.get_namespace_security_annotations", return_value=NS_ANNOTATIONS):
            body = _cronjob_review(pod_spec=_VALID_POD_SPEC)
            resp = client.post("/validate", json=body)
        assert resp.status_code == 200
        assert resp.json()["response"]["allowed"] is True

    def test_invalid_cronjob_denied(self):
        with patch("app.main.get_namespace_security_annotations", return_value=NS_ANNOTATIONS):
            body = _cronjob_review(pod_spec=_BAD_POD_SPEC)
            resp = client.post("/validate", json=body)
        assert resp.status_code == 200
        assert resp.json()["response"]["allowed"] is False

    def test_unsupported_kind_passes_through(self):
        body = {
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "request": {
                "uid": "u1",
                "kind": {"group": "", "version": "v1", "kind": "ConfigMap"},
                "namespace": "ns1",
                "operation": "CREATE",
                "object": {"data": {"key": "value"}},
            },
        }
        resp = client.post("/validate", json=body)
        assert resp.status_code == 200
        assert resp.json()["response"]["allowed"] is True

    def test_deployment_defaults_applied_before_validation(self):
        """Mutator defaults are applied to the workload template before validation."""
        annotations = {
            "sc.dsmlp.ucsd.edu/runAsUser": "1000",
            "sc.dsmlp.ucsd.edu/default.runAsUser": "1000",
        }
        # Container has no runAsUser — mutator should inject default, then validator passes
        pod_spec = {
            "containers": [{"name": "app", "securityContext": {"runAsNonRoot": True, "allowPrivilegeEscalation": False}}]
        }
        with patch("app.main.get_namespace_security_annotations", return_value=annotations):
            body = _workload_review("Deployment", pod_spec=pod_spec)
            resp = client.post("/validate", json=body)
        assert resp.status_code == 200
        assert resp.json()["response"]["allowed"] is True

    def test_deployment_missing_namespace_denied(self):
        body = _deployment_review()
        body["request"]["namespace"] = None
        resp = client.post("/validate", json=body)
        assert resp.status_code == 200
        assert resp.json()["response"]["allowed"] is False

    def test_deployment_no_annotations_denied(self):
        with patch("app.main.get_namespace_security_annotations", return_value={}):
            body = _deployment_review(pod_spec=_VALID_POD_SPEC)
            resp = client.post("/validate", json=body)
        assert resp.status_code == 200
        assert resp.json()["response"]["allowed"] is False

    def test_deployment_missing_template_spec_allowed(self):
        """A Deployment with no pod template spec is allowed through (nothing to validate)."""
        body = {
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "request": {
                "uid": "u1",
                "kind": {"group": "apps", "version": "v1", "kind": "Deployment"},
                "namespace": "ns1",
                "operation": "CREATE",
                "object": {"spec": {}},
            },
        }
        resp = client.post("/validate", json=body)
        assert resp.status_code == 200
        assert resp.json()["response"]["allowed"] is True

    def test_response_uid_echoed(self):
        with patch("app.main.get_namespace_security_annotations", return_value=NS_ANNOTATIONS):
            body = _deployment_review(uid="special-uid", pod_spec=_VALID_POD_SPEC)
            resp = client.post("/validate", json=body)
        assert resp.json()["response"]["uid"] == "special-uid"


# ---------------------------------------------------------------------------
# /mutate — workload kinds (all passed through; only Pod is patched)
# ---------------------------------------------------------------------------


class TestMutateWorkloads:
    @pytest.mark.parametrize(
        "kind", ["Deployment", "ReplicaSet", "StatefulSet", "DaemonSet", "Job"]
    )
    def test_workload_kinds_passed_through_unmodified(self, kind):
        """The mutating webhook does not patch workload resources."""
        annotations = {
            "sc.dsmlp.ucsd.edu/runAsUser": "1000",
            "sc.dsmlp.ucsd.edu/default.runAsUser": "1000",
        }
        pod_spec = {"containers": [{"name": "app"}]}
        with patch("app.main.get_namespace_security_annotations", return_value=annotations):
            body = _workload_review(kind, pod_spec=pod_spec)
            resp = client.post("/mutate", json=body)
        assert resp.status_code == 200
        data = resp.json()
        assert data["response"]["allowed"] is True
        assert "patch" not in data["response"]

    def test_cronjob_passed_through_unmodified(self):
        annotations = {
            "sc.dsmlp.ucsd.edu/runAsUser": "1000",
            "sc.dsmlp.ucsd.edu/default.runAsUser": "1000",
        }
        pod_spec = {"containers": [{"name": "app"}]}
        with patch("app.main.get_namespace_security_annotations", return_value=annotations):
            body = _cronjob_review(pod_spec=pod_spec)
            resp = client.post("/mutate", json=body)
        assert resp.status_code == 200
        data = resp.json()
        assert data["response"]["allowed"] is True
        assert "patch" not in data["response"]

    def test_unsupported_kind_passed_through(self):
        body = {
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "request": {
                "uid": "u1",
                "kind": {"group": "", "version": "v1", "kind": "ConfigMap"},
                "namespace": "ns1",
                "operation": "CREATE",
                "object": {"data": {}},
            },
        }
        resp = client.post("/mutate", json=body)
        assert resp.status_code == 200
        data = resp.json()
        assert data["response"]["allowed"] is True
        assert "patch" not in data["response"]

    def test_response_uid_echoed_for_workload(self):
        body = _workload_review("Job", uid="my-job-uid")
        resp = client.post("/mutate", json=body)
        assert resp.json()["response"]["uid"] == "my-job-uid"
