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
    ephemeral_containers: list[dict] | None = None,
    volumes: list[dict] | None = None,
) -> dict:
    spec: dict = {}
    if pod_sc is not None:
        spec["securityContext"] = pod_sc
    spec["containers"] = containers or [{"name": "app"}]
    if init_containers:
        spec["initContainers"] = init_containers
    if ephemeral_containers:
        spec["ephemeralContainers"] = ephemeral_containers
    if volumes is not None:
        spec["volumes"] = volumes
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

    def test_ephemeral_container_also_validated(self):
        spec = _pod(
            pod_sc=None,
            containers=[_container(sc={"runAsUser": 1000})],
            ephemeral_containers=[_container("debug", sc={"runAsUser": 999})],
        )
        result = validate_pod(self.ANNOTATIONS, spec)
        assert result.allowed is False
        assert "debug" in result.message

    def test_no_pod_sc_ephemeral_container_missing_field(self):
        """Ephemeral container without runAsUser and no pod-level SC → rejected."""
        spec = _pod(
            containers=[_container(sc={"runAsUser": 1000})],
            ephemeral_containers=[_container("debug", sc=None)],
        )
        result = validate_pod(self.ANNOTATIONS, spec)
        assert result.allowed is False

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
        "sc.dsmlp.ucsd.edu/fsGroup": "3000",
    }

    def test_all_pass(self):
        spec = _pod(
            pod_sc={"runAsUser": 1000, "runAsGroup": 2000, "fsGroup": 3000},
            containers=[_container(sc={"runAsUser": 1000, "runAsGroup": 2000})],
        )
        assert validate_pod(self.ANNOTATIONS, spec).allowed is True

    def test_one_fails_causes_rejection(self):
        spec = _pod(
            pod_sc={"runAsUser": 1000, "runAsGroup": 9999, "fsGroup": 3000},  # wrong group
        )
        result = validate_pod(self.ANNOTATIONS, spec)
        assert result.allowed is False
        assert "runAsGroup" in result.message

    def test_multiple_failures_all_reported(self):
        spec = _pod(
            pod_sc={"runAsUser": 999, "runAsGroup": 9999},  # both wrong
        )
        result = validate_pod(self.ANNOTATIONS, spec)
        assert result.allowed is False
        assert "runAsUser" in result.message
        assert "runAsGroup" in result.message


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

    def test_ephemeral_container_must_also_pass(self):
        annotations = {"sc.dsmlp.ucsd.edu/runAsUser": "1000"}
        spec = _pod(
            containers=[_container("c1", sc={"runAsUser": 1000})],
            ephemeral_containers=[_container("e1", sc={"runAsUser": 999})],  # bad
        )
        result = validate_pod(annotations, spec)
        assert result.allowed is False
        assert "e1" in result.message


# ---------------------------------------------------------------------------
# nodeLabel — NODE_SELECTOR
# ---------------------------------------------------------------------------


class TestNodeLabel:
    ANNOTATIONS = {"sc.dsmlp.ucsd.edu/nodeLabel": "partition=a"}
    MULTI_ANNOTATIONS = {"sc.dsmlp.ucsd.edu/nodeLabel": "rack=b,rack=c"}

    def test_matching_nodeselector_allowed(self):
        spec = _pod()
        spec["nodeSelector"] = {"partition": "a"}
        assert validate_pod(self.ANNOTATIONS, spec).allowed is True

    def test_extra_nodeselector_entries_allowed(self):
        spec = _pod()
        spec["nodeSelector"] = {"partition": "a", "zone": "us-west-2"}
        assert validate_pod(self.ANNOTATIONS, spec).allowed is True

    def test_wrong_nodeselector_value_rejected(self):
        spec = _pod()
        spec["nodeSelector"] = {"partition": "b"}
        result = validate_pod(self.ANNOTATIONS, spec)
        assert result.allowed is False
        assert "nodeSelector" in result.message

    def test_missing_nodeselector_rejected(self):
        spec = _pod()
        result = validate_pod(self.ANNOTATIONS, spec)
        assert result.allowed is False
        assert "nodeSelector" in result.message

    def test_empty_nodeselector_rejected(self):
        spec = _pod()
        spec["nodeSelector"] = {}
        result = validate_pod(self.ANNOTATIONS, spec)
        assert result.allowed is False

    def test_multi_token_first_value_matches(self):
        spec = _pod()
        spec["nodeSelector"] = {"rack": "b"}
        assert validate_pod(self.MULTI_ANNOTATIONS, spec).allowed is True

    def test_multi_token_second_value_matches(self):
        spec = _pod()
        spec["nodeSelector"] = {"rack": "c"}
        assert validate_pod(self.MULTI_ANNOTATIONS, spec).allowed is True

    def test_multi_token_no_match_rejected(self):
        spec = _pod()
        spec["nodeSelector"] = {"rack": "a"}
        result = validate_pod(self.MULTI_ANNOTATIONS, spec)
        assert result.allowed is False

    def test_nodename_rejected_when_nodelabel_enforced(self):
        spec = _pod()
        spec["nodeName"] = "node-42"
        spec["nodeSelector"] = {"partition": "a"}
        result = validate_pod(self.ANNOTATIONS, spec)
        assert result.allowed is False
        assert "nodeName" in result.message

    def test_nodename_absent_allowed(self):
        spec = _pod()
        spec["nodeSelector"] = {"partition": "a"}
        # nodeName not set at all
        assert validate_pod(self.ANNOTATIONS, spec).allowed is True

    def test_nodename_and_bad_nodeselector_both_reported(self):
        """Both nodeName violation and nodeSelector mismatch should be reported."""
        spec = _pod()
        spec["nodeName"] = "node-42"
        spec["nodeSelector"] = {"rack": "wrong"}
        result = validate_pod(self.ANNOTATIONS, spec)
        assert result.allowed is False
        assert "nodeName" in result.message
        assert "nodeSelector" in result.message

    def test_nodelabel_combined_with_other_constraints(self):
        annotations = {
            "sc.dsmlp.ucsd.edu/runAsUser": "1000",
            "sc.dsmlp.ucsd.edu/nodeLabel": "partition=gpu",
        }
        spec = _pod(containers=[_container(sc={"runAsUser": 1000})])
        spec["nodeSelector"] = {"partition": "gpu"}
        assert validate_pod(annotations, spec).allowed is True

    def test_nodelabel_malformed_annotation_rejected(self):
        annotations = {"sc.dsmlp.ucsd.edu/nodeLabel": "no-equals-sign"}
        spec = _pod()
        spec["nodeSelector"] = {"partition": "a"}
        result = validate_pod(annotations, spec)
        assert result.allowed is False
        assert "malformed" in result.message.lower()


# ---------------------------------------------------------------------------
# Hardcoded security constraints (always enforced)
# ---------------------------------------------------------------------------

# Minimal valid annotations so annotation-based checks pass; we focus on the
# hardcoded constraints in this class.
_ALWAYS_ANNOTATIONS = {"sc.dsmlp.ucsd.edu/runAsUser": "1000"}
_ALWAYS_SPEC_OK = _pod(containers=[_container(sc={"runAsUser": 1000})])


class TestHardcodedConstraints:

    # ------------------------------------------------------------------ #
    # Baseline: a clean pod passes
    # ------------------------------------------------------------------ #

    def test_clean_pod_allowed(self):
        assert validate_pod(_ALWAYS_ANNOTATIONS, _ALWAYS_SPEC_OK).allowed is True

    # ------------------------------------------------------------------ #
    # allowPrivilegeEscalation
    # ------------------------------------------------------------------ #

    def test_allow_privilege_escalation_false_ok(self):
        spec = _pod(containers=[_container(sc={"runAsUser": 1000, "allowPrivilegeEscalation": False})])
        assert validate_pod(_ALWAYS_ANNOTATIONS, spec).allowed is True

    def test_allow_privilege_escalation_absent_ok(self):
        spec = _pod(containers=[_container(sc={"runAsUser": 1000})])
        assert validate_pod(_ALWAYS_ANNOTATIONS, spec).allowed is True

    def test_allow_privilege_escalation_true_rejected(self):
        spec = _pod(containers=[_container(sc={"runAsUser": 1000, "allowPrivilegeEscalation": True})])
        result = validate_pod(_ALWAYS_ANNOTATIONS, spec)
        assert result.allowed is False
        assert "allowPrivilegeEscalation" in result.message

    # ------------------------------------------------------------------ #
    # privileged
    # ------------------------------------------------------------------ #

    def test_privileged_false_ok(self):
        spec = _pod(containers=[_container(sc={"runAsUser": 1000, "privileged": False})])
        assert validate_pod(_ALWAYS_ANNOTATIONS, spec).allowed is True

    def test_privileged_absent_ok(self):
        spec = _pod(containers=[_container(sc={"runAsUser": 1000})])
        assert validate_pod(_ALWAYS_ANNOTATIONS, spec).allowed is True

    def test_privileged_true_rejected(self):
        spec = _pod(containers=[_container(sc={"runAsUser": 1000, "privileged": True})])
        result = validate_pod(_ALWAYS_ANNOTATIONS, spec)
        assert result.allowed is False
        assert "privileged" in result.message

    # ------------------------------------------------------------------ #
    # capabilities.add
    # ------------------------------------------------------------------ #

    def test_capabilities_add_absent_ok(self):
        spec = _pod(containers=[_container(sc={"runAsUser": 1000})])
        assert validate_pod(_ALWAYS_ANNOTATIONS, spec).allowed is True

    def test_capabilities_add_empty_ok(self):
        spec = _pod(containers=[_container(sc={"runAsUser": 1000, "capabilities": {"add": []}})])
        assert validate_pod(_ALWAYS_ANNOTATIONS, spec).allowed is True

    def test_capabilities_add_net_bind_service_ok(self):
        spec = _pod(containers=[_container(sc={"runAsUser": 1000, "capabilities": {"add": ["NET_BIND_SERVICE"]}})])
        assert validate_pod(_ALWAYS_ANNOTATIONS, spec).allowed is True

    def test_capabilities_add_disallowed_rejected(self):
        spec = _pod(containers=[_container(sc={"runAsUser": 1000, "capabilities": {"add": ["SYS_ADMIN"]}})])
        result = validate_pod(_ALWAYS_ANNOTATIONS, spec)
        assert result.allowed is False
        assert "capabilities" in result.message

    def test_capabilities_add_mixed_rejected(self):
        """NET_BIND_SERVICE alongside a disallowed capability → rejected."""
        spec = _pod(containers=[_container(sc={"runAsUser": 1000, "capabilities": {"add": ["NET_BIND_SERVICE", "SYS_PTRACE"]}})])
        result = validate_pod(_ALWAYS_ANNOTATIONS, spec)
        assert result.allowed is False

    # ------------------------------------------------------------------ #
    # procMount
    # ------------------------------------------------------------------ #

    def test_proc_mount_absent_ok(self):
        spec = _pod(containers=[_container(sc={"runAsUser": 1000})])
        assert validate_pod(_ALWAYS_ANNOTATIONS, spec).allowed is True

    def test_proc_mount_default_ok(self):
        spec = _pod(containers=[_container(sc={"runAsUser": 1000, "procMount": "Default"})])
        assert validate_pod(_ALWAYS_ANNOTATIONS, spec).allowed is True

    def test_proc_mount_empty_string_ok(self):
        spec = _pod(containers=[_container(sc={"runAsUser": 1000, "procMount": ""})])
        assert validate_pod(_ALWAYS_ANNOTATIONS, spec).allowed is True

    def test_proc_mount_unmasked_rejected(self):
        spec = _pod(containers=[_container(sc={"runAsUser": 1000, "procMount": "Unmasked"})])
        result = validate_pod(_ALWAYS_ANNOTATIONS, spec)
        assert result.allowed is False
        assert "procMount" in result.message

    # ------------------------------------------------------------------ #
    # sysctls (pod-level)
    # ------------------------------------------------------------------ #

    def test_sysctls_absent_ok(self):
        spec = _pod(pod_sc={"runAsUser": 1000})
        assert validate_pod(_ALWAYS_ANNOTATIONS, spec).allowed is True

    def test_sysctls_empty_ok(self):
        spec = _pod(pod_sc={"runAsUser": 1000, "sysctls": []})
        assert validate_pod(_ALWAYS_ANNOTATIONS, spec).allowed is True

    def test_sysctls_nonempty_rejected(self):
        spec = _pod(pod_sc={"runAsUser": 1000, "sysctls": [{"name": "net.ipv4.tcp_syncookies", "value": "1"}]})
        result = validate_pod(_ALWAYS_ANNOTATIONS, spec)
        assert result.allowed is False
        assert "sysctls" in result.message

    # ------------------------------------------------------------------ #
    # Applies to initContainers and ephemeralContainers too
    # ------------------------------------------------------------------ #

    def test_init_container_privileged_rejected(self):
        spec = _pod(
            containers=[_container(sc={"runAsUser": 1000})],
            init_containers=[_container("init", sc={"runAsUser": 1000, "privileged": True})],
        )
        result = validate_pod(_ALWAYS_ANNOTATIONS, spec)
        assert result.allowed is False
        assert "init" in result.message

    def test_ephemeral_container_allow_privilege_escalation_rejected(self):
        spec = _pod(
            containers=[_container(sc={"runAsUser": 1000})],
            ephemeral_containers=[_container("debug", sc={"runAsUser": 1000, "allowPrivilegeEscalation": True})],
        )
        result = validate_pod(_ALWAYS_ANNOTATIONS, spec)
        assert result.allowed is False
        assert "debug" in result.message


# ---------------------------------------------------------------------------
# Hardcoded volume type constraint
# ---------------------------------------------------------------------------

_ALLOWED_VOLUME_TYPES = [
    "configMap", "downwardAPI", "emptyDir", "image", "nfs",
    "persistentVolumeClaim", "projected", "secret", "serviceAccountToken",
    "clusterTrustBundle", "podCertificate",
]


class TestHardcodedVolumeTypes:

    def _spec(self, *volumes: dict) -> dict:
        """Build a valid pod spec with the given volume dicts."""
        return _pod(
            containers=[_container(sc={"runAsUser": 1000})],
            volumes=list(volumes),
        )

    def test_no_volumes_ok(self):
        assert validate_pod(_ALWAYS_ANNOTATIONS, _pod(containers=[_container(sc={"runAsUser": 1000})])).allowed is True

    def test_each_allowed_non_nfs_type_ok(self):
        for vol_type in _ALLOWED_VOLUME_TYPES:
            if vol_type == "nfs":
                continue  # tested separately; needs allowedNfsVolumes annotation too
            spec = self._spec({"name": "v", vol_type: {}})
            result = validate_pod(_ALWAYS_ANNOTATIONS, spec)
            assert result.allowed is True, f"Expected {vol_type!r} to be allowed; got: {result.message}"

    def test_nfs_type_ok_when_annotation_permits(self):
        anns = {**_ALWAYS_ANNOTATIONS, "sc.dsmlp.ucsd.edu/allowedNfsVolumes": "nfsserver:/path"}
        spec = self._spec({"name": "v", "nfs": {"server": "nfsserver", "path": "/path"}})
        assert validate_pod(anns, spec).allowed is True

    def test_disallowed_type_rejected(self):
        spec = self._spec({"name": "v", "hostPath": {"path": "/host"}})
        result = validate_pod(_ALWAYS_ANNOTATIONS, spec)
        assert result.allowed is False
        assert "hostPath" in result.message

    def test_multiple_volumes_all_allowed_ok(self):
        spec = self._spec(
            {"name": "cfg", "configMap": {"name": "my-cm"}},
            {"name": "tmp", "emptyDir": {}},
        )
        assert validate_pod(_ALWAYS_ANNOTATIONS, spec).allowed is True

    def test_one_disallowed_among_many_rejected(self):
        spec = self._spec(
            {"name": "cfg", "configMap": {}},
            {"name": "bad", "hostPath": {"path": "/etc"}},
            {"name": "tmp", "emptyDir": {}},
        )
        result = validate_pod(_ALWAYS_ANNOTATIONS, spec)
        assert result.allowed is False
        assert "bad" in result.message
        assert "hostPath" in result.message

    def test_error_names_disallowed_type(self):
        spec = self._spec({"name": "mysecret", "hostIPC": {}})
        result = validate_pod(_ALWAYS_ANNOTATIONS, spec)
        assert result.allowed is False
        assert "hostIPC" in result.message
        assert "mysecret" in result.message


# ---------------------------------------------------------------------------
# allowedNfsVolumes annotation constraint
# ---------------------------------------------------------------------------

_NFS_VOL = {"name": "nfs-vol", "nfs": {"server": "10.20.5.3", "path": "/export/data"}}
_NFS_ANNOTATIONS_BASE = {**_ALWAYS_ANNOTATIONS}


def _nfs_spec(*nfs_volumes: dict) -> dict:
    """Pod spec with the given NFS volume dicts."""
    return _pod(
        containers=[_container(sc={"runAsUser": 1000})],
        volumes=list(nfs_volumes),
    )


# ---------------------------------------------------------------------------
# prohibitedVolumeTypes annotation constraint
# ---------------------------------------------------------------------------

_PVT_ANN = "sc.dsmlp.ucsd.edu/prohibitedVolumeTypes"


class TestProhibitedVolumeTypes:

    def _spec(self, *volumes: dict) -> dict:
        return _pod(containers=[_container(sc={"runAsUser": 1000})], volumes=list(volumes))

    def _anns(self, value: str) -> dict:
        return {**_ALWAYS_ANNOTATIONS, _PVT_ANN: value}

    # ------------------------------------------------------------------ #
    # No annotation — base set unchanged
    # ------------------------------------------------------------------ #

    def test_no_annotation_base_types_permitted(self):
        for vol_type in _ALLOWED_VOLUME_TYPES:
            if vol_type == "nfs":
                continue  # nfs also requires allowedNfsVolumes
            spec = self._spec({"name": "v", vol_type: {}})
            result = validate_pod(_ALWAYS_ANNOTATIONS, spec)
            assert result.allowed is True, f"Expected {vol_type!r} allowed without annotation; got: {result.message}"

    # ------------------------------------------------------------------ #
    # Single-type prohibition
    # ------------------------------------------------------------------ #

    def test_prohibited_type_rejected(self):
        spec = self._spec({"name": "tmp", "emptyDir": {}})
        result = validate_pod(self._anns("emptyDir"), spec)
        assert result.allowed is False
        assert "tmp" in result.message
        assert "emptyDir" in result.message

    def test_prohibited_type_absent_from_pod_ok(self):
        spec = self._spec({"name": "cfg", "configMap": {"name": "cm"}})
        assert validate_pod(self._anns("emptyDir"), spec).allowed is True

    def test_prohibit_secret(self):
        spec = self._spec({"name": "s", "secret": {"secretName": "x"}})
        result = validate_pod(self._anns("secret"), spec)
        assert result.allowed is False
        assert "secret" in result.message

    # ------------------------------------------------------------------ #
    # Multiple-type prohibition
    # ------------------------------------------------------------------ #

    def test_prohibit_multiple_types(self):
        spec = self._spec(
            {"name": "tmp", "emptyDir": {}},
            {"name": "s", "secret": {"secretName": "x"}},
        )
        result = validate_pod(self._anns("emptyDir,secret"), spec)
        assert result.allowed is False
        assert "tmp" in result.message
        assert "s" in result.message

    def test_prohibit_multiple_only_matching_reported(self):
        # configMap is not prohibited; emptyDir is
        spec = self._spec(
            {"name": "cfg", "configMap": {}},
            {"name": "tmp", "emptyDir": {}},
        )
        result = validate_pod(self._anns("emptyDir,secret"), spec)
        assert result.allowed is False
        assert "tmp" in result.message
        assert "cfg" not in result.message

    # ------------------------------------------------------------------ #
    # Empty / whitespace annotation — no additional restriction
    # ------------------------------------------------------------------ #

    def test_empty_annotation_no_restriction(self):
        spec = self._spec({"name": "tmp", "emptyDir": {}})
        assert validate_pod(self._anns(""), spec).allowed is True

    def test_whitespace_annotation_no_restriction(self):
        spec = self._spec({"name": "tmp", "emptyDir": {}})
        assert validate_pod(self._anns("   "), spec).allowed is True

    # ------------------------------------------------------------------ #
    # Unknown type names in annotation (not in base set)
    # ------------------------------------------------------------------ #

    def test_unknown_type_name_ignored(self):
        # "notARealType" not in base set; emptyDir still prohibited
        spec = self._spec({"name": "tmp", "emptyDir": {}})
        result = validate_pod(self._anns("notARealType,emptyDir"), spec)
        assert result.allowed is False
        assert "emptyDir" in result.message

    def test_only_unknown_type_no_restriction(self):
        spec = self._spec({"name": "tmp", "emptyDir": {}})
        assert validate_pod(self._anns("notARealType"), spec).allowed is True

    # ------------------------------------------------------------------ #
    # No volumes — always passes
    # ------------------------------------------------------------------ #

    def test_no_volumes_always_ok(self):
        spec = _pod(containers=[_container(sc={"runAsUser": 1000})])
        assert validate_pod(self._anns("emptyDir,secret"), spec).allowed is True

    # ------------------------------------------------------------------ #
    # Types outside the base set remain rejected regardless
    # ------------------------------------------------------------------ #

    def test_base_disallowed_type_always_rejected(self):
        spec = self._spec({"name": "bad", "hostPath": {"path": "/host"}})
        assert validate_pod(_ALWAYS_ANNOTATIONS, spec).allowed is False


class TestAllowedNfsVolumes:

    # ------------------------------------------------------------------ #
    # No NFS volumes — always passes regardless of annotation
    # ------------------------------------------------------------------ #

    def test_no_nfs_volumes_annotation_absent_ok(self):
        spec = _nfs_spec()
        assert validate_pod(_NFS_ANNOTATIONS_BASE, spec).allowed is True

    def test_no_nfs_volumes_annotation_empty_ok(self):
        anns = {**_NFS_ANNOTATIONS_BASE, "sc.dsmlp.ucsd.edu/allowedNfsVolumes": ""}
        assert validate_pod(anns, _nfs_spec()).allowed is True

    def test_no_nfs_volumes_annotation_with_patterns_ok(self):
        anns = {**_NFS_ANNOTATIONS_BASE, "sc.dsmlp.ucsd.edu/allowedNfsVolumes": "10.20.5.3:/export/data"}
        assert validate_pod(anns, _nfs_spec()).allowed is True

    # ------------------------------------------------------------------ #
    # NFS volume present — annotation absent/empty → denied
    # ------------------------------------------------------------------ #

    def test_nfs_volume_annotation_absent_rejected(self):
        result = validate_pod(_NFS_ANNOTATIONS_BASE, _nfs_spec(_NFS_VOL))
        assert result.allowed is False
        assert "nfs-vol" in result.message
        assert "allowedNfsVolumes" in result.message

    def test_nfs_volume_annotation_empty_string_rejected(self):
        anns = {**_NFS_ANNOTATIONS_BASE, "sc.dsmlp.ucsd.edu/allowedNfsVolumes": ""}
        result = validate_pod(anns, _nfs_spec(_NFS_VOL))
        assert result.allowed is False

    def test_nfs_volume_annotation_whitespace_only_rejected(self):
        anns = {**_NFS_ANNOTATIONS_BASE, "sc.dsmlp.ucsd.edu/allowedNfsVolumes": "   "}
        result = validate_pod(anns, _nfs_spec(_NFS_VOL))
        assert result.allowed is False

    # ------------------------------------------------------------------ #
    # Exact matches
    # ------------------------------------------------------------------ #

    def test_exact_match_allowed(self):
        anns = {**_NFS_ANNOTATIONS_BASE, "sc.dsmlp.ucsd.edu/allowedNfsVolumes": "10.20.5.3:/export/data"}
        assert validate_pod(anns, _nfs_spec(_NFS_VOL)).allowed is True

    def test_exact_match_server_mismatch_rejected(self):
        anns = {**_NFS_ANNOTATIONS_BASE, "sc.dsmlp.ucsd.edu/allowedNfsVolumes": "10.20.5.4:/export/data"}
        result = validate_pod(anns, _nfs_spec(_NFS_VOL))
        assert result.allowed is False

    def test_exact_match_path_mismatch_rejected(self):
        anns = {**_NFS_ANNOTATIONS_BASE, "sc.dsmlp.ucsd.edu/allowedNfsVolumes": "10.20.5.3:/export/other"}
        result = validate_pod(anns, _nfs_spec(_NFS_VOL))
        assert result.allowed is False

    def test_multiple_exact_patterns_or_semantics(self):
        anns = {**_NFS_ANNOTATIONS_BASE, "sc.dsmlp.ucsd.edu/allowedNfsVolumes": "itsnfs:/scratch,10.20.5.3:/export/data"}
        assert validate_pod(anns, _nfs_spec(_NFS_VOL)).allowed is True

    # ------------------------------------------------------------------ #
    # Glob matches
    # ------------------------------------------------------------------ #

    def test_glob_server_wildcard_allowed(self):
        vol = {"name": "v", "nfs": {"server": "its-dsmlp-fs03", "path": "/export/workspaces/PROJ_TEST"}}
        anns = {**_NFS_ANNOTATIONS_BASE, "sc.dsmlp.ucsd.edu/allowedNfsVolumes": "its-dsmlp-fs0[1-9]:/export/workspaces/*"}
        assert validate_pod(anns, _nfs_spec(vol)).allowed is True

    def test_glob_path_wildcard_allowed(self):
        vol = {"name": "v", "nfs": {"server": "itsnfs", "path": "/scratch/proj"}}
        anns = {**_NFS_ANNOTATIONS_BASE, "sc.dsmlp.ucsd.edu/allowedNfsVolumes": "itsnfs:/scratch/*"}
        assert validate_pod(anns, _nfs_spec(vol)).allowed is True

    def test_glob_outside_range_rejected(self):
        # its-dsmlp-fs0[1-9] does not match its-dsmlp-fs10
        vol = {"name": "v", "nfs": {"server": "its-dsmlp-fs10", "path": "/export/workspaces/PROJ"}}
        anns = {**_NFS_ANNOTATIONS_BASE, "sc.dsmlp.ucsd.edu/allowedNfsVolumes": "its-dsmlp-fs0[1-9]:/export/workspaces/*"}
        result = validate_pod(anns, _nfs_spec(vol))
        assert result.allowed is False

    def test_glob_full_example_from_spec(self):
        """Reproduce the example from the requirements."""
        anns = {
            **_NFS_ANNOTATIONS_BASE,
            "sc.dsmlp.ucsd.edu/allowedNfsVolumes": (
                "10.20.5.3:/export/data,"
                "itsnfs:/scratch,"
                "its-dsmlp-fs03:/export/workspaces/PROJ_TEST"
            ),
        }
        vol = {"name": "v", "nfs": {"server": "its-dsmlp-fs03", "path": "/export/workspaces/PROJ_TEST"}}
        assert validate_pod(anns, _nfs_spec(vol)).allowed is True

    # ------------------------------------------------------------------ #
    # Multiple NFS volumes
    # ------------------------------------------------------------------ #

    def test_multiple_nfs_all_allowed(self):
        anns = {**_NFS_ANNOTATIONS_BASE, "sc.dsmlp.ucsd.edu/allowedNfsVolumes": "nfs1:/data,nfs2:/data"}
        vol1 = {"name": "v1", "nfs": {"server": "nfs1", "path": "/data"}}
        vol2 = {"name": "v2", "nfs": {"server": "nfs2", "path": "/data"}}
        assert validate_pod(anns, _nfs_spec(vol1, vol2)).allowed is True

    def test_multiple_nfs_one_disallowed_rejected(self):
        anns = {**_NFS_ANNOTATIONS_BASE, "sc.dsmlp.ucsd.edu/allowedNfsVolumes": "nfs1:/data"}
        vol1 = {"name": "v1", "nfs": {"server": "nfs1", "path": "/data"}}
        vol2 = {"name": "v2", "nfs": {"server": "nfs2", "path": "/data"}}
        result = validate_pod(anns, _nfs_spec(vol1, vol2))
        assert result.allowed is False
        assert "v2" in result.message

    # ------------------------------------------------------------------ #
    # NFS volumes alongside other volume types
    # ------------------------------------------------------------------ #

    def test_nfs_alongside_allowed_types_ok(self):
        anns = {**_NFS_ANNOTATIONS_BASE, "sc.dsmlp.ucsd.edu/allowedNfsVolumes": "10.20.5.3:/export/data"}
        spec = _pod(
            containers=[_container(sc={"runAsUser": 1000})],
            volumes=[
                {"name": "cfg", "configMap": {"name": "my-cm"}},
                _NFS_VOL,
            ],
        )
        assert validate_pod(anns, spec).allowed is True
