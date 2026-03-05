"""Tests for the core pod validation logic."""
import pytest

from app.validator import validate_pod


# ---------------------------------------------------------------------------
# Helpers to build pod specs / annotations
# ---------------------------------------------------------------------------


def _pod(
    pod_sc: dict | None = None,
    containers: list[dict] | None = None,
    init_containers: list[dict] | None = None,
) -> dict:
    spec: dict = {}
    if pod_sc is not None:
        spec["securityContext"] = pod_sc
    spec["containers"] = containers or [{"name": "app"}]
    if init_containers:
        spec["initContainers"] = init_containers
    return spec


def _container(name: str = "app", sc: dict | None = None) -> dict:
    c: dict = {"name": name}
    if sc is not None:
        c["securityContext"] = sc
    return c


# ---------------------------------------------------------------------------
# No namespace annotations → always reject
# ---------------------------------------------------------------------------


def test_no_annotations_rejects():
    result = validate_pod({}, _pod())
    assert result.allowed is False
    assert "sc.dsmlp.ucsd.edu" in result.message


# ---------------------------------------------------------------------------
# runAsUser — REQUIRED_SCALAR
# ---------------------------------------------------------------------------


class TestRunAsUser:
    ANNOTATIONS = {"sc.dsmlp.ucsd.edu/runAsUser": "1000"}

    def test_pod_level_match(self):
        spec = _pod(pod_sc={"runAsUser": 1000}, containers=[_container()])
        assert validate_pod(self.ANNOTATIONS, spec).allowed is True

    def test_pod_level_no_match(self):
        spec = _pod(pod_sc={"runAsUser": 999}, containers=[_container()])
        result = validate_pod(self.ANNOTATIONS, spec)
        assert result.allowed is False
        assert "runAsUser" in result.message

    def test_no_pod_sc_container_sets_matching(self):
        spec = _pod(containers=[_container(sc={"runAsUser": 1000})])
        assert validate_pod(self.ANNOTATIONS, spec).allowed is True

    def test_no_pod_sc_container_sets_non_matching(self):
        spec = _pod(containers=[_container(sc={"runAsUser": 999})])
        result = validate_pod(self.ANNOTATIONS, spec)
        assert result.allowed is False

    def test_no_pod_sc_container_missing_field(self):
        """Container has a securityContext but not runAsUser → rejected."""
        spec = _pod(containers=[_container(sc={})])
        result = validate_pod(self.ANNOTATIONS, spec)
        assert result.allowed is False
        assert "must set" in result.message

    def test_no_pod_sc_container_no_sc_at_all(self):
        """Container has no securityContext at all → rejected."""
        spec = _pod(containers=[_container(sc=None)])
        result = validate_pod(self.ANNOTATIONS, spec)
        assert result.allowed is False

    def test_pod_sc_present_containers_override_ok(self):
        """Pod SC present; container also sets runAsUser correctly."""
        spec = _pod(
            pod_sc={"runAsUser": 1000},
            containers=[_container(sc={"runAsUser": 1000})],
        )
        assert validate_pod(self.ANNOTATIONS, spec).allowed is True

    def test_pod_sc_present_container_override_bad(self):
        """Pod SC present; container overrides with bad runAsUser → rejected."""
        spec = _pod(
            pod_sc={"runAsUser": 1000},
            containers=[_container(sc={"runAsUser": 999})],
        )
        result = validate_pod(self.ANNOTATIONS, spec)
        assert result.allowed is False

    def test_init_container_also_validated(self):
        spec = _pod(
            pod_sc=None,
            containers=[_container(sc={"runAsUser": 1000})],
            init_containers=[_container("init", sc={"runAsUser": 999})],
        )
        result = validate_pod(self.ANNOTATIONS, spec)
        assert result.allowed is False
        assert "init" in result.message

    def test_range_constraint(self):
        annotations = {"sc.dsmlp.ucsd.edu/runAsUser": "1000,2000-3000"}
        spec = _pod(containers=[_container(sc={"runAsUser": 2500})])
        assert validate_pod(annotations, spec).allowed is True

    def test_range_constraint_fail(self):
        annotations = {"sc.dsmlp.ucsd.edu/runAsUser": "1000,2000-3000"}
        spec = _pod(containers=[_container(sc={"runAsUser": 1500})])
        assert validate_pod(annotations, spec).allowed is False

    def test_greater_than_constraint(self):
        annotations = {"sc.dsmlp.ucsd.edu/runAsUser": ">5000000"}
        spec = _pod(containers=[_container(sc={"runAsUser": 5000001})])
        assert validate_pod(annotations, spec).allowed is True

    def test_greater_than_boundary_fail(self):
        annotations = {"sc.dsmlp.ucsd.edu/runAsUser": ">5000000"}
        spec = _pod(containers=[_container(sc={"runAsUser": 5000000})])
        assert validate_pod(annotations, spec).allowed is False


# ---------------------------------------------------------------------------
# runAsGroup — REQUIRED_SCALAR (same logic as runAsUser)
# ---------------------------------------------------------------------------


class TestRunAsGroup:
    ANNOTATIONS = {"sc.dsmlp.ucsd.edu/runAsGroup": "2000"}

    def test_pod_level_match(self):
        spec = _pod(pod_sc={"runAsGroup": 2000})
        assert validate_pod(self.ANNOTATIONS, spec).allowed is True

    def test_container_required_when_no_pod_sc(self):
        spec = _pod(containers=[_container(sc=None)])
        assert validate_pod(self.ANNOTATIONS, spec).allowed is False

    def test_container_with_correct_group(self):
        spec = _pod(containers=[_container(sc={"runAsGroup": 2000})])
        assert validate_pod(self.ANNOTATIONS, spec).allowed is True


# ---------------------------------------------------------------------------
# allowPrivilegeEscalation — REQUIRED_SCALAR (boolean)
# ---------------------------------------------------------------------------


class TestAllowPrivilegeEscalation:
    ANNOTATIONS_FALSE = {"sc.dsmlp.ucsd.edu/allowPrivilegeEscalation": "false"}
    ANNOTATIONS_TRUE = {"sc.dsmlp.ucsd.edu/allowPrivilegeEscalation": "true"}

    def test_pod_sc_false_matches_false_annotation(self):
        spec = _pod(pod_sc={"allowPrivilegeEscalation": False})
        assert validate_pod(self.ANNOTATIONS_FALSE, spec).allowed is True

    def test_pod_sc_true_fails_false_annotation(self):
        spec = _pod(pod_sc={"allowPrivilegeEscalation": True})
        result = validate_pod(self.ANNOTATIONS_FALSE, spec)
        assert result.allowed is False

    def test_container_must_set_when_pod_sc_absent(self):
        spec = _pod(containers=[_container(sc=None)])
        result = validate_pod(self.ANNOTATIONS_FALSE, spec)
        assert result.allowed is False

    def test_container_matches(self):
        spec = _pod(containers=[_container(sc={"allowPrivilegeEscalation": False})])
        assert validate_pod(self.ANNOTATIONS_FALSE, spec).allowed is True

    def test_container_bad_value(self):
        spec = _pod(containers=[_container(sc={"allowPrivilegeEscalation": True})])
        result = validate_pod(self.ANNOTATIONS_FALSE, spec)
        assert result.allowed is False


# ---------------------------------------------------------------------------
# fsGroup — OPTIONAL_SCALAR
# ---------------------------------------------------------------------------


class TestFsGroup:
    ANNOTATIONS = {"sc.dsmlp.ucsd.edu/fsGroup": "1000"}

    def test_absent_is_ok(self):
        spec = _pod(pod_sc={})
        assert validate_pod(self.ANNOTATIONS, spec).allowed is True

    def test_no_pod_sc_is_ok(self):
        spec = _pod()
        assert validate_pod(self.ANNOTATIONS, spec).allowed is True

    def test_matching_value_ok(self):
        spec = _pod(pod_sc={"fsGroup": 1000})
        assert validate_pod(self.ANNOTATIONS, spec).allowed is True

    def test_non_matching_value_rejected(self):
        spec = _pod(pod_sc={"fsGroup": 999})
        result = validate_pod(self.ANNOTATIONS, spec)
        assert result.allowed is False
        assert "fsGroup" in result.message


# ---------------------------------------------------------------------------
# supplementalGroups — OPTIONAL_LIST
# ---------------------------------------------------------------------------


class TestSupplementalGroups:
    ANNOTATIONS = {"sc.dsmlp.ucsd.edu/supplementalGroups": "1000,2000-3000"}

    def test_absent_is_ok(self):
        spec = _pod(pod_sc={})
        assert validate_pod(self.ANNOTATIONS, spec).allowed is True

    def test_empty_list_is_ok(self):
        spec = _pod(pod_sc={"supplementalGroups": []})
        assert validate_pod(self.ANNOTATIONS, spec).allowed is True

    def test_all_match(self):
        spec = _pod(pod_sc={"supplementalGroups": [1000, 2500, 3000]})
        assert validate_pod(self.ANNOTATIONS, spec).allowed is True

    def test_one_fails(self):
        spec = _pod(pod_sc={"supplementalGroups": [1000, 9999]})
        result = validate_pod(self.ANNOTATIONS, spec)
        assert result.allowed is False
        assert "supplementalGroups" in result.message


# ---------------------------------------------------------------------------
# Multiple constraints
# ---------------------------------------------------------------------------


class TestMultipleConstraints:
    ANNOTATIONS = {
        "sc.dsmlp.ucsd.edu/runAsUser": "1000",
        "sc.dsmlp.ucsd.edu/runAsGroup": "2000",
        "sc.dsmlp.ucsd.edu/allowPrivilegeEscalation": "false",
        "sc.dsmlp.ucsd.edu/fsGroup": "3000",
    }

    def test_all_pass(self):
        spec = _pod(
            pod_sc={
                "runAsUser": 1000,
                "runAsGroup": 2000,
                "fsGroup": 3000,
            },
            containers=[
                _container(
                    sc={
                        "allowPrivilegeEscalation": False,
                    }
                )
            ],
        )
        assert validate_pod(self.ANNOTATIONS, spec).allowed is True

    def test_one_fails_causes_rejection(self):
        spec = _pod(
            pod_sc={
                "runAsUser": 1000,
                "runAsGroup": 9999,  # wrong
                "fsGroup": 3000,
            },
            containers=[_container(sc={"allowPrivilegeEscalation": False})],
        )
        result = validate_pod(self.ANNOTATIONS, spec)
        assert result.allowed is False
        assert "runAsGroup" in result.message

    def test_multiple_failures_all_reported(self):
        spec = _pod(
            pod_sc={
                "runAsUser": 999,  # wrong
                "runAsGroup": 9999,  # wrong
            },
            containers=[_container(sc={"allowPrivilegeEscalation": True})],  # wrong
        )
        result = validate_pod(self.ANNOTATIONS, spec)
        assert result.allowed is False
        # All three errors should appear
        assert "runAsUser" in result.message
        assert "runAsGroup" in result.message
        assert "allowPrivilegeEscalation" in result.message


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_malformed_annotation_rejects(self):
        annotations = {"sc.dsmlp.ucsd.edu/runAsUser": "foo,bar"}
        spec = _pod(pod_sc={"runAsUser": 1000})
        result = validate_pod(annotations, spec)
        assert result.allowed is False
        assert "malformed" in result.message.lower()

    def test_unknown_annotation_key_ignored(self):
        """Unknown annotation keys (not in CONSTRAINT_REGISTRY) are silently ignored."""
        annotations = {
            "sc.dsmlp.ucsd.edu/runAsUser": "1000",
            "sc.dsmlp.ucsd.edu/unknownFutureFiled": "xyz",
        }
        spec = _pod(containers=[_container(sc={"runAsUser": 1000})])
        # Should pass based on the known constraint; the unknown key is ignored
        assert validate_pod(annotations, spec).allowed is True

    def test_multiple_containers_all_must_pass(self):
        annotations = {"sc.dsmlp.ucsd.edu/runAsUser": "1000"}
        spec = _pod(
            containers=[
                _container("c1", sc={"runAsUser": 1000}),
                _container("c2", sc={"runAsUser": 999}),  # bad
            ]
        )
        result = validate_pod(annotations, spec)
        assert result.allowed is False
        assert "c2" in result.message
