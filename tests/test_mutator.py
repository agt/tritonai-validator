"""Tests for the pod mutation logic."""
import base64
import json
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.mutator import mutate_pod

client = TestClient(app)


# ---------------------------------------------------------------------------
# Helpers (mirrors test_validator.py helpers)
# ---------------------------------------------------------------------------


def _pod(
    pod_sc: dict | None = None,
    containers: list[dict] | None = None,
    init_containers: list[dict] | None = None,
    ephemeral_containers: list[dict] | None = None,
) -> dict:
    spec: dict = {}
    if pod_sc is not None:
        spec["securityContext"] = pod_sc
    spec["containers"] = containers or [{"name": "app"}]
    if init_containers:
        spec["initContainers"] = init_containers
    if ephemeral_containers:
        spec["ephemeralContainers"] = ephemeral_containers
    return spec


def _container(name: str = "app", sc: dict | None = None) -> dict:
    c: dict = {"name": name}
    if sc is not None:
        c["securityContext"] = sc
    return c


def _ops(patches: list[dict], op: str) -> list[dict]:
    return [p for p in patches if p["op"] == op]


def _patch_at(patches: list[dict], path: str) -> dict | None:
    return next((p for p in patches if p["path"] == path), None)


# ---------------------------------------------------------------------------
# No activity when no namespace annotations
# ---------------------------------------------------------------------------


def test_no_patches_when_no_annotations():
    spec = _pod(pod_sc={"runAsNonRoot": True}, containers=[_container(sc={"runAsUser": 999})])
    assert mutate_pod({}, spec) == []


def test_no_patches_when_no_constraint_annotation():
    # default annotation present but no matching constraint annotation
    annotations = {"sc.dsmlp.ucsd.edu/default.runAsUser": "1000"}
    spec = _pod(pod_sc={"runAsNonRoot": True}, containers=[_container(sc={"runAsUser": 999})])
    assert mutate_pod(annotations, spec) == []


# ---------------------------------------------------------------------------
# Default annotation parsing
# ---------------------------------------------------------------------------


def test_no_patches_when_default_annotation_absent(caplog):
    annotations = {"sc.dsmlp.ucsd.edu/runAsUser": "1000"}
    spec = _pod(pod_sc={"runAsNonRoot": True}, containers=[_container(sc=None)])
    patches = mutate_pod(annotations, spec)
    assert patches == []
    assert "default" in caplog.text.lower()


def test_no_patches_when_default_unparseable(caplog):
    annotations = {
        "sc.dsmlp.ucsd.edu/runAsUser": "1000",
        "sc.dsmlp.ucsd.edu/default.runAsUser": "not-a-number",
    }
    spec = _pod(pod_sc={"runAsNonRoot": True}, containers=[_container(sc=None)])
    patches = mutate_pod(annotations, spec)
    assert patches == []
    assert "cannot parse" in caplog.text.lower()


# ---------------------------------------------------------------------------
# runAsUser — REQUIRED_SCALAR mutations
# ---------------------------------------------------------------------------


RUNASUSER_ANNOTATIONS = {
    "sc.dsmlp.ucsd.edu/runAsUser": "1000",
    "sc.dsmlp.ucsd.edu/default.runAsUser": "1000",
}


class TestMutateRunAsUser:

    def test_no_patches_when_already_conforming_pod_sc(self):
        spec = _pod(pod_sc={"runAsUser": 1000, "runAsNonRoot": True})
        assert mutate_pod(RUNASUSER_ANNOTATIONS, spec) == []

    def test_no_patches_when_already_conforming_container_sc(self):
        spec = _pod(pod_sc={"runAsNonRoot": True}, containers=[_container(sc={"runAsUser": 1000})])
        assert mutate_pod(RUNASUSER_ANNOTATIONS, spec) == []

    def test_no_patches_when_wrong_value_already_set_in_container(self):
        # Wrong values are left for the validator to reject; mutator does not touch them.
        spec = _pod(pod_sc={"runAsNonRoot": True}, containers=[_container(sc={"runAsUser": 999})])
        assert mutate_pod(RUNASUSER_ANNOTATIONS, spec) == []

    def test_no_patches_when_wrong_value_already_set_in_pod_sc(self):
        spec = _pod(pod_sc={"runAsUser": 999, "runAsNonRoot": True}, containers=[_container(sc={"runAsUser": 1000})])
        assert mutate_pod(RUNASUSER_ANNOTATIONS, spec) == []

    def test_creates_pod_sc_when_container_has_no_sc(self):
        spec = _pod(containers=[_container(sc=None)])
        patches = mutate_pod(RUNASUSER_ANNOTATIONS, spec)
        p = _patch_at(patches, "/spec/securityContext")
        assert p is not None
        assert p["op"] == "add"
        assert p["value"] == {"runAsUser": 1000}

    def test_creates_pod_sc_when_container_sc_lacks_field(self):
        spec = _pod(containers=[_container(sc={})])
        patches = mutate_pod(RUNASUSER_ANNOTATIONS, spec)
        p = _patch_at(patches, "/spec/securityContext")
        assert p is not None
        assert p["value"] == {"runAsUser": 1000}

    def test_adds_field_to_existing_pod_sc_when_container_lacks_it(self):
        # Pod SC exists (with other fields) but lacks runAsUser; container also lacks it
        spec = _pod(pod_sc={"runAsGroup": 2000}, containers=[_container(sc={})])
        patches = mutate_pod(RUNASUSER_ANNOTATIONS, spec)
        p = _patch_at(patches, "/spec/securityContext/runAsUser")
        assert p is not None
        assert p["op"] == "add"
        assert p["value"] == 1000

    def test_no_pod_sc_creation_when_all_containers_have_field(self):
        # All containers supply runAsUser; pod SC not needed for runAsUser.
        spec = _pod(pod_sc={"runAsNonRoot": True}, containers=[
            _container("c1", sc={"runAsUser": 1000}),
            _container("c2", sc={"runAsUser": 1000}),
        ])
        assert mutate_pod(RUNASUSER_ANNOTATIONS, spec) == []

    def test_no_pod_sc_when_container_has_wrong_value(self):
        # Container has wrong value but field is present — not our job to fix it.
        spec = _pod(pod_sc={"runAsNonRoot": True}, containers=[
            _container("good", sc={"runAsUser": 1000}),
            _container("bad", sc={"runAsUser": 999}),
        ])
        assert mutate_pod(RUNASUSER_ANNOTATIONS, spec) == []

    def test_creates_pod_sc_when_only_ephemeral_container_missing_field(self):
        """No pod SC; ephemeral container has no securityContext → pod SC created."""
        spec = _pod(
            containers=[_container(sc={"runAsUser": 1000})],
            ephemeral_containers=[_container("debug", sc=None)],
        )
        patches = mutate_pod(RUNASUSER_ANNOTATIONS, spec)
        paths = [p["path"] for p in patches]
        assert any("securityContext" in path and "ephemeral" not in path and "containers" not in path
                   for path in paths)

    def test_pod_sc_field_not_updated_if_already_correct_and_container_covered(self):
        # Pod SC has correct value; container also has correct value → no patches
        spec = _pod(
            pod_sc={"runAsUser": 1000, "runAsNonRoot": True},
            containers=[_container(sc={"runAsUser": 1000})],
        )
        assert mutate_pod(RUNASUSER_ANNOTATIONS, spec) == []


# ---------------------------------------------------------------------------
# fsGroup — OPTIONAL_SCALAR (no mutations; absent is always acceptable)
# ---------------------------------------------------------------------------


FSGROUP_ANNOTATIONS = {
    "sc.dsmlp.ucsd.edu/fsGroup": "1000",
    "sc.dsmlp.ucsd.edu/default.fsGroup": "1000",
}


class TestMutateFsGroup:

    def test_no_patches_when_absent(self):
        spec = _pod(pod_sc={"runAsNonRoot": True})
        assert mutate_pod(FSGROUP_ANNOTATIONS, spec) == []

    def test_no_patches_when_no_pod_sc(self):
        spec = _pod(pod_sc={"runAsNonRoot": True})
        assert mutate_pod(FSGROUP_ANNOTATIONS, spec) == []

    def test_no_patches_when_wrong_value(self):
        # Wrong values are left for the validator to reject.
        spec = _pod(pod_sc={"fsGroup": 999, "runAsNonRoot": True})
        assert mutate_pod(FSGROUP_ANNOTATIONS, spec) == []

    def test_no_patches_when_correct(self):
        spec = _pod(pod_sc={"fsGroup": 1000, "runAsNonRoot": True})
        assert mutate_pod(FSGROUP_ANNOTATIONS, spec) == []


# ---------------------------------------------------------------------------
# supplementalGroups — OPTIONAL_LIST (no mutations; absent is always acceptable)
# ---------------------------------------------------------------------------


SG_ANNOTATIONS = {
    "sc.dsmlp.ucsd.edu/supplementalGroups": "1000,2000-3000",
    "sc.dsmlp.ucsd.edu/default.supplementalGroups": "1000",
}


class TestMutateSupplementalGroups:

    def test_no_patches_when_absent(self):
        spec = _pod(pod_sc={"runAsNonRoot": True})
        assert mutate_pod(SG_ANNOTATIONS, spec) == []

    def test_no_patches_when_empty_list(self):
        spec = _pod(pod_sc={"supplementalGroups": [], "runAsNonRoot": True})
        assert mutate_pod(SG_ANNOTATIONS, spec) == []

    def test_no_patches_when_all_conforming(self):
        spec = _pod(pod_sc={"supplementalGroups": [1000, 2500], "runAsNonRoot": True})
        assert mutate_pod(SG_ANNOTATIONS, spec) == []

    def test_no_patches_when_non_conforming(self):
        # Non-conforming values are left for the validator to reject.
        spec = _pod(pod_sc={"supplementalGroups": [1000, 9999], "runAsNonRoot": True})
        assert mutate_pod(SG_ANNOTATIONS, spec) == []


# ---------------------------------------------------------------------------
# nodeLabel — NODE_SELECTOR
# ---------------------------------------------------------------------------


NL_ANNOTATIONS = {
    "sc.dsmlp.ucsd.edu/nodeLabel": "partition=gpu",
    "sc.dsmlp.ucsd.edu/default.nodeLabel": "partition=gpu",
}


class TestMutateNodeLabel:

    def test_no_patches_when_nodeselector_key_already_present(self):
        spec = _pod(pod_sc={"runAsNonRoot": True})
        spec["nodeSelector"] = {"partition": "gpu"}
        assert mutate_pod(NL_ANNOTATIONS, spec) == []

    def test_no_patches_when_key_present_with_different_value(self):
        # Key is present (even with a wrong value) — mutator does not touch it.
        spec = _pod(pod_sc={"runAsNonRoot": True})
        spec["nodeSelector"] = {"partition": "cpu"}
        assert mutate_pod(NL_ANNOTATIONS, spec) == []

    def test_creates_nodeselector_when_absent(self):
        spec = _pod()
        patches = mutate_pod(NL_ANNOTATIONS, spec)
        p = _patch_at(patches, "/spec/nodeSelector")
        assert p is not None
        assert p["op"] == "add"
        assert p["value"] == {"partition": "gpu"}

    def test_no_injection_into_existing_nodeselector(self):
        # Pod already has a nodeSelector with a different key — not touched.
        spec = _pod(pod_sc={"runAsNonRoot": True})
        spec["nodeSelector"] = {"zone": "us-west-2"}
        assert mutate_pod(NL_ANNOTATIONS, spec) == []

    def test_removes_nodename_unconditionally(self):
        spec = _pod()
        spec["nodeName"] = "node-42"
        spec["nodeSelector"] = {"partition": "gpu"}   # key already present
        patches = mutate_pod(NL_ANNOTATIONS, spec)
        removes = _ops(patches, "remove")
        assert any(p["path"] == "/spec/nodeName" for p in removes)

    def test_removes_nodename_and_injects_nodeselector(self):
        spec = _pod()
        spec["nodeName"] = "node-42"
        # nodeSelector absent → both nodeName removal + nodeSelector add
        patches = mutate_pod(NL_ANNOTATIONS, spec)
        assert any(p["op"] == "remove" and p["path"] == "/spec/nodeName" for p in patches)
        assert any(p["path"] == "/spec/nodeSelector" for p in patches)

    def test_nodename_removed_even_without_valid_default(self, caplog):
        annotations = {"sc.dsmlp.ucsd.edu/nodeLabel": "partition=gpu"}  # no default
        spec = _pod()
        spec["nodeName"] = "node-42"
        patches = mutate_pod(annotations, spec)
        assert any(p["op"] == "remove" and p["path"] == "/spec/nodeName" for p in patches)
        assert "cannot" in caplog.text.lower() or "absent" in caplog.text.lower()

    def test_nodeselector_key_with_slash_escaped_in_pointer(self):
        annotations = {
            "sc.dsmlp.ucsd.edu/nodeLabel": "kubernetes.io/hostname=node-1",
            "sc.dsmlp.ucsd.edu/default.nodeLabel": "kubernetes.io/hostname=node-1",
        }
        # nodeSelector absent → default injected; verify pointer escaping
        spec = _pod(pod_sc={"runAsNonRoot": True})
        patches = mutate_pod(annotations, spec)
        p = _patch_at(patches, "/spec/nodeSelector")
        assert p is not None
        assert p["value"] == {"kubernetes.io/hostname": "node-1"}

    def test_existing_nodeselector_suppresses_injection(self):
        # Any pre-existing nodeSelector (even with unrelated keys) prevents injection.
        annotations = {
            "sc.dsmlp.ucsd.edu/nodeLabel": "rack=a,rack=b",
            "sc.dsmlp.ucsd.edu/default.nodeLabel": "rack=a",
        }
        spec = _pod(pod_sc={"runAsNonRoot": True})
        spec["nodeSelector"] = {"zone": "us-west-2"}
        assert mutate_pod(annotations, spec) == []


# ---------------------------------------------------------------------------
# runAsNonRoot — unconditional hardcoded injection
# ---------------------------------------------------------------------------


class TestMutateRunAsNonRoot:
    """runAsNonRoot=True is always injected at pod level when the field is absent."""

    def test_creates_pod_sc_when_none_exists(self):
        """No pod SC at all → pod SC created with runAsNonRoot=True."""
        spec = _pod()
        patches = mutate_pod({}, spec)
        p = _patch_at(patches, "/spec/securityContext")
        assert p is not None
        assert p["op"] == "add"
        assert p["value"] == {"runAsNonRoot": True}

    def test_adds_to_existing_pod_sc(self):
        """Pod SC exists but lacks runAsNonRoot → field added."""
        spec = _pod(pod_sc={"runAsUser": 1000})
        patches = mutate_pod({}, spec)
        p = _patch_at(patches, "/spec/securityContext/runAsNonRoot")
        assert p is not None
        assert p["op"] == "add"
        assert p["value"] is True

    def test_no_patch_when_already_true(self):
        """runAsNonRoot already True → no patch."""
        spec = _pod(pod_sc={"runAsNonRoot": True})
        assert mutate_pod({}, spec) == []

    def test_no_patch_when_false(self):
        """runAsNonRoot=False is left alone; validator rejects it."""
        spec = _pod(pod_sc={"runAsNonRoot": False})
        assert mutate_pod({}, spec) == []

    def test_injected_regardless_of_annotations(self):
        """Injection fires even when namespace has no policy annotations."""
        spec = _pod()
        patches = mutate_pod({}, spec)
        p = _patch_at(patches, "/spec/securityContext")
        assert p is not None
        assert p["value"] == {"runAsNonRoot": True}

    def test_runasnonroot_patch_follows_runasuser_pod_sc_creation(self):
        """When runAsUser creates pod SC, runAsNonRoot is appended as a second patch."""
        spec = _pod(containers=[_container(sc=None)])
        patches = mutate_pod({
            "sc.dsmlp.ucsd.edu/runAsUser": "1000",
            "sc.dsmlp.ucsd.edu/default.runAsUser": "1000",
        }, spec)
        # runAsUser creates pod SC first
        assert _patch_at(patches, "/spec/securityContext") is not None
        # runAsNonRoot then adds to it
        p = _patch_at(patches, "/spec/securityContext/runAsNonRoot")
        assert p is not None
        assert p["value"] is True

    def test_combined_patch_sequence_is_applicable(self):
        """Patch order: create SC (runAsUser) then add field (runAsNonRoot) is valid JSON Patch."""
        spec = _pod(containers=[_container(sc=None)])
        patches = mutate_pod({
            "sc.dsmlp.ucsd.edu/runAsUser": "1000",
            "sc.dsmlp.ucsd.edu/default.runAsUser": "1000",
        }, spec)
        create_idx = next(i for i, p in enumerate(patches) if p["path"] == "/spec/securityContext")
        add_idx = next(i for i, p in enumerate(patches) if p["path"] == "/spec/securityContext/runAsNonRoot")
        assert create_idx < add_idx  # parent created before child


# ---------------------------------------------------------------------------
# Multiple constraints — patches combined correctly
# ---------------------------------------------------------------------------


class TestMultipleConstraintMutations:

    def test_all_fields_patched(self):
        annotations = {
            "sc.dsmlp.ucsd.edu/runAsUser": "1000",
            "sc.dsmlp.ucsd.edu/default.runAsUser": "1000",
            "sc.dsmlp.ucsd.edu/runAsGroup": "2000",
            "sc.dsmlp.ucsd.edu/default.runAsGroup": "2000",
            "sc.dsmlp.ucsd.edu/nodeLabel": "partition=gpu",
            "sc.dsmlp.ucsd.edu/default.nodeLabel": "partition=gpu",
        }
        # Pod with no SC and a nodeName set
        spec = _pod(containers=[_container(sc=None)])
        spec["nodeName"] = "node-1"

        patches = mutate_pod(annotations, spec)
        paths = {p["path"] for p in patches}

        assert any("/spec/securityContext" in path for path in paths)
        assert "/spec/nodeName" in paths
        assert "/spec/nodeSelector" in paths

    def test_partial_remediation_when_one_default_missing(self, caplog):
        annotations = {
            "sc.dsmlp.ucsd.edu/runAsUser": "1000",
            "sc.dsmlp.ucsd.edu/default.runAsUser": "1000",
            "sc.dsmlp.ucsd.edu/runAsGroup": "2000",
            # no default for runAsGroup
        }
        # Container has no SC at all — both fields are absent
        spec = _pod(containers=[_container(sc=None)])
        patches = mutate_pod(annotations, spec)
        # runAsUser default applied (pod SC created); runAsGroup skipped (no default)
        assert any("runAsUser" in str(p.get("value", "")) for p in patches)
        assert not any("runAsGroup" in p["path"] for p in patches)
        assert "default" in caplog.text.lower()


# ---------------------------------------------------------------------------
# /mutate HTTP endpoint
# ---------------------------------------------------------------------------


def _review(
    uid: str = "test-uid",
    kind: str = "Pod",
    namespace: str = "default",
    pod_spec: dict | None = None,
) -> dict:
    pod_spec = pod_spec or {"containers": [{"name": "app"}]}
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


NS_WITH_DEFAULTS = {
    "sc.dsmlp.ucsd.edu/runAsUser": "1000",
    "sc.dsmlp.ucsd.edu/default.runAsUser": "1000",
}


def test_mutate_endpoint_returns_allowed_true():
    with patch("app.main.get_namespace_security_annotations", return_value={}):
        resp = client.post("/mutate", json=_review())
    assert resp.status_code == 200
    assert resp.json()["response"]["allowed"] is True


def test_mutate_endpoint_passes_through_non_pod():
    resp = client.post("/mutate", json=_review(kind="Deployment"))
    assert resp.status_code == 200
    data = resp.json()
    assert data["response"]["allowed"] is True
    assert "patch" not in data["response"]


def test_mutate_endpoint_returns_patch_when_needed():
    with patch(
        "app.main.get_namespace_security_annotations", return_value=NS_WITH_DEFAULTS
    ):
        # Container has no securityContext → runAsUser is absent → default injected
        spec = {"containers": [{"name": "app"}]}
        resp = client.post("/mutate", json=_review(pod_spec=spec))
    assert resp.status_code == 200
    data = resp.json()
    assert data["response"]["allowed"] is True
    assert data["response"]["patchType"] == "JSONPatch"
    raw = base64.b64decode(data["response"]["patch"])
    ops = json.loads(raw)
    assert any("runAsUser" in str(op.get("value", "")) for op in ops)


def test_mutate_endpoint_no_patch_when_already_compliant():
    with patch(
        "app.main.get_namespace_security_annotations", return_value=NS_WITH_DEFAULTS
    ):
        spec = {
            "securityContext": {"runAsNonRoot": True},
            "containers": [{"name": "app", "securityContext": {"runAsUser": 1000}}],
        }
        resp = client.post("/mutate", json=_review(pod_spec=spec))
    assert resp.status_code == 200
    data = resp.json()
    assert data["response"]["allowed"] is True
    assert "patch" not in data["response"]


def test_mutate_endpoint_preserves_uid():
    with patch("app.main.get_namespace_security_annotations", return_value={}):
        resp = client.post("/mutate", json=_review(uid="unique-xyz"))
    assert resp.json()["response"]["uid"] == "unique-xyz"


def test_mutate_endpoint_bad_json_returns_400():
    resp = client.post(
        "/mutate", content=b"not json", headers={"content-type": "application/json"}
    )
    assert resp.status_code == 400
