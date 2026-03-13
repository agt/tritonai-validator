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


def _container(
    name: str = "app",
    sc: dict | None = None,
    env: list | None = None,
    env_from: list | None = None,
    ports: list | None = None,
) -> dict:
    c: dict = {"name": name}
    if sc is not None:
        c["securityContext"] = sc
    if env is not None:
        c["env"] = env
    if env_from is not None:
        c["envFrom"] = env_from
    if ports is not None:
        c["ports"] = ports
    return c


# ---------------------------------------------------------------------------
# No namespace annotations → always reject
# ---------------------------------------------------------------------------


def test_no_annotations_rejects():
    result = validate_pod([{}], _pod())
    assert result.allowed is False
    assert "tritonai-admission-webhook" in result.message


# ---------------------------------------------------------------------------
# runAsUser — REQUIRED_SCALAR
# ---------------------------------------------------------------------------


class TestRunAsUser:
    ANNOTATIONS = {"tritonai-admission-webhook/policy.runAsUser": "1000"}

    def test_pod_level_match(self):
        spec = _pod(pod_sc={"runAsUser": 1000, "runAsNonRoot": True}, containers=[_container(sc={"allowPrivilegeEscalation": False})])
        assert validate_pod(self.ANNOTATIONS, spec).allowed is True

    def test_pod_level_no_match(self):
        spec = _pod(pod_sc={"runAsUser": 999}, containers=[_container()])
        result = validate_pod([self.ANNOTATIONS], spec)
        assert result.allowed is False
        assert "runAsUser" in result.message

    def test_no_pod_sc_container_sets_matching(self):
        spec = _pod(containers=[_container(sc={"runAsUser": 1000, "runAsNonRoot": True, "allowPrivilegeEscalation": False})])
        assert validate_pod(self.ANNOTATIONS, spec).allowed is True

    def test_no_pod_sc_container_sets_non_matching(self):
        spec = _pod(containers=[_container(sc={"runAsUser": 999})])
        result = validate_pod([self.ANNOTATIONS], spec)
        assert result.allowed is False

    def test_no_pod_sc_container_missing_field(self):
        """Container has a securityContext but not runAsUser → rejected."""
        spec = _pod(containers=[_container(sc={})])
        result = validate_pod([self.ANNOTATIONS], spec)
        assert result.allowed is False
        assert "must set" in result.message

    def test_no_pod_sc_container_no_sc_at_all(self):
        """Container has no securityContext at all → rejected."""
        spec = _pod(containers=[_container(sc=None)])
        result = validate_pod([self.ANNOTATIONS], spec)
        assert result.allowed is False

    def test_pod_sc_present_containers_override_ok(self):
        """Pod SC present; container also sets runAsUser correctly."""
        spec = _pod(
            pod_sc={"runAsUser": 1000, "runAsNonRoot": True},
            containers=[_container(sc={"runAsUser": 1000, "allowPrivilegeEscalation": False})],
        )
        assert validate_pod([self.ANNOTATIONS], spec).allowed is True

    def test_pod_sc_present_container_override_bad(self):
        """Pod SC present; container overrides with bad runAsUser → rejected."""
        spec = _pod(
            pod_sc={"runAsUser": 1000},
            containers=[_container(sc={"runAsUser": 999})],
        )
        result = validate_pod([self.ANNOTATIONS], spec)
        assert result.allowed is False

    def test_init_container_also_validated(self):
        spec = _pod(
            pod_sc=None,
            containers=[_container(sc={"runAsUser": 1000})],
            init_containers=[_container("init", sc={"runAsUser": 999})],
        )
        result = validate_pod([self.ANNOTATIONS], spec)
        assert result.allowed is False
        assert "init" in result.message

    def test_ephemeral_container_also_validated(self):
        spec = _pod(
            pod_sc=None,
            containers=[_container(sc={"runAsUser": 1000})],
            ephemeral_containers=[_container("debug", sc={"runAsUser": 999})],
        )
        result = validate_pod([self.ANNOTATIONS], spec)
        assert result.allowed is False
        assert "debug" in result.message

    def test_no_pod_sc_ephemeral_container_missing_field(self):
        """Ephemeral container without runAsUser and no pod-level SC → rejected."""
        spec = _pod(
            containers=[_container(sc={"runAsUser": 1000})],
            ephemeral_containers=[_container("debug", sc=None)],
        )
        result = validate_pod([self.ANNOTATIONS], spec)
        assert result.allowed is False

    def test_range_constraint(self):
        annotations = {"tritonai-admission-webhook/policy.runAsUser": "1000,2000-3000"}
        spec = _pod(pod_sc={"runAsNonRoot": True}, containers=[_container(sc={"runAsUser": 2500, "allowPrivilegeEscalation": False})])
        assert validate_pod(annotations, spec).allowed is True

    def test_range_constraint_fail(self):
        annotations = {"tritonai-admission-webhook/policy.runAsUser": "1000,2000-3000"}
        spec = _pod(containers=[_container(sc={"runAsUser": 1500})])
        assert validate_pod([annotations], spec).allowed is False

    def test_greater_than_constraint(self):
        annotations = {"tritonai-admission-webhook/policy.runAsUser": ">5000000"}
        spec = _pod(pod_sc={"runAsNonRoot": True}, containers=[_container(sc={"runAsUser": 5000001, "allowPrivilegeEscalation": False})])
        assert validate_pod(annotations, spec).allowed is True

    def test_greater_than_boundary_fail(self):
        annotations = {"tritonai-admission-webhook/policy.runAsUser": ">5000000"}
        spec = _pod(containers=[_container(sc={"runAsUser": 5000000})])
        assert validate_pod([annotations], spec).allowed is False


# ---------------------------------------------------------------------------
# runAsGroup — REQUIRED_SCALAR (same logic as runAsUser)
# ---------------------------------------------------------------------------


class TestRunAsGroup:
    ANNOTATIONS = {"tritonai-admission-webhook/policy.runAsGroup": "2000"}

    def test_pod_level_match(self):
        spec = _pod(pod_sc={"runAsGroup": 2000, "runAsNonRoot": True}, containers=[_container(sc={"allowPrivilegeEscalation": False})])
        assert validate_pod(self.ANNOTATIONS, spec).allowed is True

    def test_container_required_when_no_pod_sc(self):
        spec = _pod(containers=[_container(sc=None)])
        assert validate_pod([self.ANNOTATIONS], spec).allowed is False

    def test_container_with_correct_group(self):
        spec = _pod(pod_sc={"runAsNonRoot": True}, containers=[_container(sc={"runAsGroup": 2000, "allowPrivilegeEscalation": False})])
        assert validate_pod(self.ANNOTATIONS, spec).allowed is True


# ---------------------------------------------------------------------------
# fsGroup — OPTIONAL_SCALAR
# ---------------------------------------------------------------------------


class TestFsGroup:
    ANNOTATIONS = {"tritonai-admission-webhook/policy.fsGroup": "1000"}

    def test_absent_is_ok(self):
        spec = _pod(pod_sc={"runAsNonRoot": True}, containers=[_container(sc={"allowPrivilegeEscalation": False})])
        assert validate_pod(self.ANNOTATIONS, spec).allowed is True

    def test_no_pod_sc_is_ok(self):
        spec = _pod(pod_sc={"runAsNonRoot": True}, containers=[_container(sc={"allowPrivilegeEscalation": False})])
        assert validate_pod(self.ANNOTATIONS, spec).allowed is True

    def test_matching_value_ok(self):
        spec = _pod(pod_sc={"fsGroup": 1000, "runAsNonRoot": True}, containers=[_container(sc={"allowPrivilegeEscalation": False})])
        assert validate_pod(self.ANNOTATIONS, spec).allowed is True

    def test_non_matching_value_rejected(self):
        spec = _pod(pod_sc={"fsGroup": 999, "runAsNonRoot": True})
        result = validate_pod([self.ANNOTATIONS], spec)
        assert result.allowed is False
        assert "fsGroup" in result.message


# ---------------------------------------------------------------------------
# supplementalGroups — OPTIONAL_LIST
# ---------------------------------------------------------------------------


class TestSupplementalGroups:
    ANNOTATIONS = {"tritonai-admission-webhook/policy.supplementalGroups": "1000,2000-3000"}

    def test_absent_is_ok(self):
        spec = _pod(pod_sc={"runAsNonRoot": True}, containers=[_container(sc={"allowPrivilegeEscalation": False})])
        assert validate_pod(self.ANNOTATIONS, spec).allowed is True

    def test_empty_list_is_ok(self):
        spec = _pod(pod_sc={"supplementalGroups": [], "runAsNonRoot": True}, containers=[_container(sc={"allowPrivilegeEscalation": False})])
        assert validate_pod(self.ANNOTATIONS, spec).allowed is True

    def test_all_match(self):
        spec = _pod(pod_sc={"supplementalGroups": [1000, 2500, 3000], "runAsNonRoot": True}, containers=[_container(sc={"allowPrivilegeEscalation": False})])
        assert validate_pod(self.ANNOTATIONS, spec).allowed is True

    def test_one_fails(self):
        spec = _pod(pod_sc={"supplementalGroups": [1000, 9999], "runAsNonRoot": True})
        result = validate_pod([self.ANNOTATIONS], spec)
        assert result.allowed is False
        assert "supplementalGroups" in result.message


# ---------------------------------------------------------------------------
# Multiple constraints
# ---------------------------------------------------------------------------


class TestMultipleConstraints:
    ANNOTATIONS = {
        "tritonai-admission-webhook/policy.runAsUser": "1000",
        "tritonai-admission-webhook/policy.runAsGroup": "2000",
        "tritonai-admission-webhook/policy.fsGroup": "3000",
    }

    def test_all_pass(self):
        spec = _pod(
            pod_sc={"runAsUser": 1000, "runAsGroup": 2000, "fsGroup": 3000, "runAsNonRoot": True},
            containers=[_container(sc={"runAsUser": 1000, "runAsGroup": 2000, "allowPrivilegeEscalation": False})],
        )
        assert validate_pod([self.ANNOTATIONS], spec).allowed is True

    def test_one_fails_causes_rejection(self):
        spec = _pod(
            pod_sc={"runAsUser": 1000, "runAsGroup": 9999, "fsGroup": 3000},  # wrong group
        )
        result = validate_pod([self.ANNOTATIONS], spec)
        assert result.allowed is False
        assert "runAsGroup" in result.message

    def test_multiple_failures_all_reported(self):
        spec = _pod(
            pod_sc={"runAsUser": 999, "runAsGroup": 9999},  # both wrong
        )
        result = validate_pod([self.ANNOTATIONS], spec)
        assert result.allowed is False
        assert "runAsUser" in result.message
        assert "runAsGroup" in result.message


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_malformed_annotation_rejects(self):
        annotations = {"tritonai-admission-webhook/policy.runAsUser": "foo,bar"}
        spec = _pod(pod_sc={"runAsUser": 1000})
        result = validate_pod([annotations], spec)
        assert result.allowed is False
        assert "malformed" in result.message.lower()

    def test_unknown_annotation_key_ignored(self):
        """Unknown annotation keys (not in CONSTRAINT_REGISTRY) are silently ignored."""
        annotations = {
            "tritonai-admission-webhook/policy.runAsUser": "1000",
            "tritonai-admission-webhook/policy.unknownFutureFiled": "xyz",
        }
        spec = _pod(pod_sc={"runAsNonRoot": True}, containers=[_container(sc={"runAsUser": 1000, "allowPrivilegeEscalation": False})])
        # Should pass based on the known constraint; the unknown key is ignored
        assert validate_pod([annotations], spec).allowed is True

    def test_multiple_containers_all_must_pass(self):
        annotations = {"tritonai-admission-webhook/policy.runAsUser": "1000"}
        spec = _pod(
            containers=[
                _container("c1", sc={"runAsUser": 1000}),
                _container("c2", sc={"runAsUser": 999}),  # bad
            ]
        )
        result = validate_pod([annotations], spec)
        assert result.allowed is False
        assert "c2" in result.message

    def test_ephemeral_container_must_also_pass(self):
        annotations = {"tritonai-admission-webhook/policy.runAsUser": "1000"}
        spec = _pod(
            containers=[_container("c1", sc={"runAsUser": 1000})],
            ephemeral_containers=[_container("e1", sc={"runAsUser": 999})],  # bad
        )
        result = validate_pod([annotations], spec)
        assert result.allowed is False
        assert "e1" in result.message


# ---------------------------------------------------------------------------
# nodeSelectors — NODE_SELECTOR
# ---------------------------------------------------------------------------


class TestNodeSelectors:
    ANNOTATIONS = {"tritonai-admission-webhook/policy.nodeSelectors": "partition=a"}
    MULTI_ANNOTATIONS = {"tritonai-admission-webhook/policy.nodeSelectors": "rack=b,rack=c"}

    def test_matching_nodeselector_allowed(self):
        spec = _pod(pod_sc={"runAsNonRoot": True}, containers=[_container(sc={"allowPrivilegeEscalation": False})])
        spec["nodeSelector"] = {"partition": "a"}
        assert validate_pod([self.ANNOTATIONS], spec).allowed is True

    def test_extra_nodeselector_entries_allowed(self):
        spec = _pod(pod_sc={"runAsNonRoot": True}, containers=[_container(sc={"allowPrivilegeEscalation": False})])
        spec["nodeSelector"] = {"partition": "a", "zone": "us-west-2"}
        assert validate_pod([self.ANNOTATIONS], spec).allowed is True

    def test_wrong_nodeselector_value_rejected(self):
        spec = _pod()
        spec["nodeSelector"] = {"partition": "b"}
        result = validate_pod([self.ANNOTATIONS], spec)
        assert result.allowed is False
        assert "nodeSelector" in result.message

    def test_missing_nodeselector_rejected(self):
        spec = _pod()
        result = validate_pod([self.ANNOTATIONS], spec)
        assert result.allowed is False
        assert "nodeSelector" in result.message

    def test_empty_nodeselector_rejected(self):
        spec = _pod()
        spec["nodeSelector"] = {}
        result = validate_pod([self.ANNOTATIONS], spec)
        assert result.allowed is False

    def test_multi_token_first_value_matches(self):
        spec = _pod(pod_sc={"runAsNonRoot": True}, containers=[_container(sc={"allowPrivilegeEscalation": False})])
        spec["nodeSelector"] = {"rack": "b"}
        assert validate_pod([self.MULTI_ANNOTATIONS], spec).allowed is True

    def test_multi_token_second_value_matches(self):
        spec = _pod(pod_sc={"runAsNonRoot": True}, containers=[_container(sc={"allowPrivilegeEscalation": False})])
        spec["nodeSelector"] = {"rack": "c"}
        assert validate_pod([self.MULTI_ANNOTATIONS], spec).allowed is True

    def test_multi_token_no_match_rejected(self):
        spec = _pod()
        spec["nodeSelector"] = {"rack": "a"}
        result = validate_pod([self.MULTI_ANNOTATIONS], spec)
        assert result.allowed is False

    def test_nodename_rejected_when_nodeselectors_enforced(self):
        spec = _pod()
        spec["nodeName"] = "node-42"
        spec["nodeSelector"] = {"partition": "a"}
        result = validate_pod([self.ANNOTATIONS], spec)
        assert result.allowed is False
        assert "nodeName" in result.message

    def test_nodename_absent_allowed(self):
        spec = _pod(pod_sc={"runAsNonRoot": True}, containers=[_container(sc={"allowPrivilegeEscalation": False})])
        spec["nodeSelector"] = {"partition": "a"}
        # nodeName not set at all
        assert validate_pod([self.ANNOTATIONS], spec).allowed is True

    def test_nodename_and_bad_nodeselector_both_reported(self):
        """Both nodeName violation and nodeSelector mismatch should be reported."""
        spec = _pod()
        spec["nodeName"] = "node-42"
        spec["nodeSelector"] = {"rack": "wrong"}
        result = validate_pod([self.ANNOTATIONS], spec)
        assert result.allowed is False
        assert "nodeName" in result.message
        assert "nodeSelector" in result.message

    def test_nodeselectors_combined_with_other_constraints(self):
        annotations = {
            "tritonai-admission-webhook/policy.runAsUser": "1000",
            "tritonai-admission-webhook/policy.nodeSelectors": "partition=gpu",
        }
        spec = _pod(pod_sc={"runAsNonRoot": True}, containers=[_container(sc={"runAsUser": 1000, "allowPrivilegeEscalation": False})])
        spec["nodeSelector"] = {"partition": "gpu"}
        assert validate_pod([annotations], spec).allowed is True

    def test_nodeselectors_malformed_annotation_rejected(self):
        annotations = {"tritonai-admission-webhook/policy.nodeSelectors": "no-equals-sign"}
        spec = _pod()
        spec["nodeSelector"] = {"partition": "a"}
        result = validate_pod([annotations], spec)
        assert result.allowed is False
        assert "malformed" in result.message.lower()


# ---------------------------------------------------------------------------
# Hardcoded security constraints (always enforced)
# ---------------------------------------------------------------------------

# Minimal valid annotations so annotation-based checks pass; we focus on the
# hardcoded constraints in this class.
_ALWAYS_ANNOTATIONS = {"tritonai-admission-webhook/policy.runAsUser": "1000"}
_ALWAYS_SPEC_OK = _pod(pod_sc={"runAsNonRoot": True}, containers=[_container(sc={"runAsUser": 1000, "allowPrivilegeEscalation": False})])


class TestHardcodedConstraints:

    # ------------------------------------------------------------------ #
    # Baseline: a clean pod passes
    # ------------------------------------------------------------------ #

    def test_clean_pod_allowed(self):
        assert validate_pod([_ALWAYS_ANNOTATIONS], _ALWAYS_SPEC_OK).allowed is True

    # ------------------------------------------------------------------ #
    # allowPrivilegeEscalation
    # ------------------------------------------------------------------ #

    def test_allow_privilege_escalation_false_ok(self):
        spec = _pod(pod_sc={"runAsNonRoot": True}, containers=[_container(sc={"runAsUser": 1000, "allowPrivilegeEscalation": False})])
        assert validate_pod([_ALWAYS_ANNOTATIONS], spec).allowed is True

    def test_allow_privilege_escalation_absent_rejected(self):
        spec = _pod(pod_sc={"runAsNonRoot": True}, containers=[_container(sc={"runAsUser": 1000})])
        assert validate_pod(_ALWAYS_ANNOTATIONS, spec).allowed is False

    def test_allow_privilege_escalation_true_rejected(self):
        spec = _pod(containers=[_container(sc={"runAsUser": 1000, "allowPrivilegeEscalation": True})])
        result = validate_pod([_ALWAYS_ANNOTATIONS], spec)
        assert result.allowed is False
        assert "allowPrivilegeEscalation" in result.message

    # ------------------------------------------------------------------ #
    # privileged
    # ------------------------------------------------------------------ #

    def test_privileged_false_ok(self):
        spec = _pod(pod_sc={"runAsNonRoot": True}, containers=[_container(sc={"runAsUser": 1000, "privileged": False, "allowPrivilegeEscalation": False})])
        assert validate_pod(_ALWAYS_ANNOTATIONS, spec).allowed is True

    def test_privileged_absent_ok(self):
        spec = _pod(pod_sc={"runAsNonRoot": True}, containers=[_container(sc={"runAsUser": 1000, "allowPrivilegeEscalation": False})])
        assert validate_pod(_ALWAYS_ANNOTATIONS, spec).allowed is True

    def test_privileged_true_rejected(self):
        spec = _pod(containers=[_container(sc={"runAsUser": 1000, "privileged": True})])
        result = validate_pod([_ALWAYS_ANNOTATIONS], spec)
        assert result.allowed is False
        assert "privileged" in result.message

    # ------------------------------------------------------------------ #
    # capabilities.add
    # ------------------------------------------------------------------ #

    def test_capabilities_add_absent_ok(self):
        spec = _pod(pod_sc={"runAsNonRoot": True}, containers=[_container(sc={"runAsUser": 1000, "allowPrivilegeEscalation": False})])
        assert validate_pod(_ALWAYS_ANNOTATIONS, spec).allowed is True

    def test_capabilities_add_empty_ok(self):
        spec = _pod(pod_sc={"runAsNonRoot": True}, containers=[_container(sc={"runAsUser": 1000, "allowPrivilegeEscalation": False, "capabilities": {"add": []}})])
        assert validate_pod(_ALWAYS_ANNOTATIONS, spec).allowed is True

    def test_capabilities_add_net_bind_service_ok(self):
        spec = _pod(pod_sc={"runAsNonRoot": True}, containers=[_container(sc={"runAsUser": 1000, "allowPrivilegeEscalation": False, "capabilities": {"add": ["NET_BIND_SERVICE"]}})])
        assert validate_pod(_ALWAYS_ANNOTATIONS, spec).allowed is True

    def test_capabilities_add_disallowed_rejected(self):
        spec = _pod(containers=[_container(sc={"runAsUser": 1000, "capabilities": {"add": ["SYS_ADMIN"]}})])
        result = validate_pod([_ALWAYS_ANNOTATIONS], spec)
        assert result.allowed is False
        assert "capabilities" in result.message

    def test_capabilities_add_mixed_rejected(self):
        """NET_BIND_SERVICE alongside a disallowed capability → rejected."""
        spec = _pod(containers=[_container(sc={"runAsUser": 1000, "capabilities": {"add": ["NET_BIND_SERVICE", "SYS_PTRACE"]}})])
        result = validate_pod([_ALWAYS_ANNOTATIONS], spec)
        assert result.allowed is False

    # ------------------------------------------------------------------ #
    # procMount
    # ------------------------------------------------------------------ #

    def test_proc_mount_absent_ok(self):
        spec = _pod(pod_sc={"runAsNonRoot": True}, containers=[_container(sc={"runAsUser": 1000, "allowPrivilegeEscalation": False})])
        assert validate_pod(_ALWAYS_ANNOTATIONS, spec).allowed is True

    def test_proc_mount_default_ok(self):
        spec = _pod(pod_sc={"runAsNonRoot": True}, containers=[_container(sc={"runAsUser": 1000, "allowPrivilegeEscalation": False, "procMount": "Default"})])
        assert validate_pod(_ALWAYS_ANNOTATIONS, spec).allowed is True

    def test_proc_mount_empty_string_ok(self):
        spec = _pod(pod_sc={"runAsNonRoot": True}, containers=[_container(sc={"runAsUser": 1000, "allowPrivilegeEscalation": False, "procMount": ""})])
        assert validate_pod(_ALWAYS_ANNOTATIONS, spec).allowed is True

    def test_proc_mount_unmasked_rejected(self):
        spec = _pod(containers=[_container(sc={"runAsUser": 1000, "procMount": "Unmasked"})])
        result = validate_pod([_ALWAYS_ANNOTATIONS], spec)
        assert result.allowed is False
        assert "procMount" in result.message

    # ------------------------------------------------------------------ #
    # sysctls (pod-level)
    # ------------------------------------------------------------------ #

    def test_sysctls_absent_ok(self):
        spec = _pod(pod_sc={"runAsUser": 1000, "runAsNonRoot": True}, containers=[_container(sc={"allowPrivilegeEscalation": False})])
        assert validate_pod(_ALWAYS_ANNOTATIONS, spec).allowed is True

    def test_sysctls_empty_ok(self):
        spec = _pod(pod_sc={"runAsUser": 1000, "sysctls": [], "runAsNonRoot": True}, containers=[_container(sc={"allowPrivilegeEscalation": False})])
        assert validate_pod(_ALWAYS_ANNOTATIONS, spec).allowed is True

    def test_sysctls_nonempty_rejected(self):
        spec = _pod(pod_sc={"runAsUser": 1000, "sysctls": [{"name": "net.ipv4.tcp_syncookies", "value": "1"}]})
        result = validate_pod([_ALWAYS_ANNOTATIONS], spec)
        assert result.allowed is False
        assert "sysctls" in result.message

    # ------------------------------------------------------------------ #
    # hostNetwork / hostPID / hostIPC (pod-level)
    # ------------------------------------------------------------------ #

    def test_host_network_absent_ok(self):
        spec = _pod(pod_sc={"runAsUser": 1000, "runAsNonRoot": True}, containers=[_container(sc={"allowPrivilegeEscalation": False})])
        assert validate_pod(_ALWAYS_ANNOTATIONS, spec).allowed is True

    def test_host_network_false_ok(self):
        spec = {**_pod(pod_sc={"runAsUser": 1000, "runAsNonRoot": True}, containers=[_container(sc={"allowPrivilegeEscalation": False})]), "hostNetwork": False}
        assert validate_pod(_ALWAYS_ANNOTATIONS, spec).allowed is True

    def test_host_network_true_rejected(self):
        spec = {**_pod(pod_sc={"runAsUser": 1000}), "hostNetwork": True}
        result = validate_pod([_ALWAYS_ANNOTATIONS], spec)
        assert result.allowed is False
        assert "hostNetwork" in result.message

    def test_host_pid_absent_ok(self):
        spec = _pod(pod_sc={"runAsUser": 1000, "runAsNonRoot": True}, containers=[_container(sc={"allowPrivilegeEscalation": False})])
        assert validate_pod(_ALWAYS_ANNOTATIONS, spec).allowed is True

    def test_host_pid_false_ok(self):
        spec = {**_pod(pod_sc={"runAsUser": 1000, "runAsNonRoot": True}, containers=[_container(sc={"allowPrivilegeEscalation": False})]), "hostPID": False}
        assert validate_pod(_ALWAYS_ANNOTATIONS, spec).allowed is True

    def test_host_pid_true_rejected(self):
        spec = {**_pod(pod_sc={"runAsUser": 1000}), "hostPID": True}
        result = validate_pod([_ALWAYS_ANNOTATIONS], spec)
        assert result.allowed is False
        assert "hostPID" in result.message

    def test_host_ipc_absent_ok(self):
        spec = _pod(pod_sc={"runAsUser": 1000, "runAsNonRoot": True}, containers=[_container(sc={"allowPrivilegeEscalation": False})])
        assert validate_pod(_ALWAYS_ANNOTATIONS, spec).allowed is True

    def test_host_ipc_false_ok(self):
        spec = {**_pod(pod_sc={"runAsUser": 1000, "runAsNonRoot": True}, containers=[_container(sc={"allowPrivilegeEscalation": False})]), "hostIPC": False}
        assert validate_pod(_ALWAYS_ANNOTATIONS, spec).allowed is True

    def test_host_ipc_true_rejected(self):
        spec = {**_pod(pod_sc={"runAsUser": 1000}), "hostIPC": True}
        result = validate_pod([_ALWAYS_ANNOTATIONS], spec)
        assert result.allowed is False
        assert "hostIPC" in result.message

    def test_multiple_host_fields_all_errors_reported(self):
        """All three violations should be reported in a single rejection."""
        spec = {**_pod(pod_sc={"runAsUser": 1000}), "hostNetwork": True, "hostPID": True, "hostIPC": True}
        result = validate_pod([_ALWAYS_ANNOTATIONS], spec)
        assert result.allowed is False
        assert "hostNetwork" in result.message
        assert "hostPID" in result.message
        assert "hostIPC" in result.message

    # ------------------------------------------------------------------ #
    # Applies to initContainers and ephemeralContainers too
    # ------------------------------------------------------------------ #

    def test_init_container_privileged_rejected(self):
        spec = _pod(
            containers=[_container(sc={"runAsUser": 1000, "allowPrivilegeEscalation": False})],
            init_containers=[_container("init", sc={"runAsUser": 1000, "privileged": True, "allowPrivilegeEscalation": False})],
        )
        result = validate_pod([_ALWAYS_ANNOTATIONS], spec)
        assert result.allowed is False
        assert "init" in result.message

    def test_ephemeral_container_allow_privilege_escalation_rejected(self):
        spec = _pod(
            containers=[_container(sc={"runAsUser": 1000, "allowPrivilegeEscalation": False})],
            ephemeral_containers=[_container("debug", sc={"runAsUser": 1000, "allowPrivilegeEscalation": True})],
        )
        result = validate_pod([_ALWAYS_ANNOTATIONS], spec)
        assert result.allowed is False
        assert "debug" in result.message

    # ------------------------------------------------------------------ #
    # hostPort
    # ------------------------------------------------------------------ #

    def test_host_port_absent_ok(self):
        c = _container(sc={"runAsUser": 1000, "allowPrivilegeEscalation": False}, ports=[{"containerPort": 8080}])
        assert validate_pod(_ALWAYS_ANNOTATIONS, _pod(pod_sc={"runAsNonRoot": True}, containers=[c])).allowed is True

    def test_host_port_zero_ok(self):
        c = _container(sc={"runAsUser": 1000, "allowPrivilegeEscalation": False}, ports=[{"containerPort": 8080, "hostPort": 0}])
        assert validate_pod(_ALWAYS_ANNOTATIONS, _pod(pod_sc={"runAsNonRoot": True}, containers=[c])).allowed is True

    def test_host_port_set_rejected(self):
        c = _container(sc={"runAsUser": 1000, "allowPrivilegeEscalation": False}, ports=[{"containerPort": 8080, "hostPort": 8080}])
        result = validate_pod(_ALWAYS_ANNOTATIONS, _pod(pod_sc={"runAsNonRoot": True}, containers=[c]))
        assert result.allowed is False
        assert "hostPort" in result.message
        assert "8080" in result.message

    def test_host_port_multiple_ports_only_offending_reported(self):
        """Only the port with hostPort set should appear in the error."""
        c = _container(sc={"runAsUser": 1000, "allowPrivilegeEscalation": False}, ports=[
            {"containerPort": 8080},
            {"containerPort": 9090, "hostPort": 9090},
        ])
        result = validate_pod([_ALWAYS_ANNOTATIONS], _pod(pod_sc={"runAsNonRoot": True}, containers=[c]))
        assert result.allowed is False
        assert "9090" in result.message

    def test_host_port_in_init_container_rejected(self):
        main = _container(sc={"runAsUser": 1000, "allowPrivilegeEscalation": False})
        init = _container("init", sc={"runAsUser": 1000, "allowPrivilegeEscalation": False}, ports=[{"containerPort": 80, "hostPort": 80}])
        result = validate_pod(_ALWAYS_ANNOTATIONS, _pod(
            pod_sc={"runAsNonRoot": True}, containers=[main], init_containers=[init]
        ))
        assert result.allowed is False
        assert "init" in result.message
        assert "hostPort" in result.message

    def test_host_port_no_ports_section_ok(self):
        assert validate_pod([_ALWAYS_ANNOTATIONS], _ALWAYS_SPEC_OK).allowed is True


# ---------------------------------------------------------------------------
# runAsUser must not be 0 (root) — hardcoded constraint
# ---------------------------------------------------------------------------


class TestRunAsUserNotRoot:
    """runAsUser=0 is always rejected at both pod and container level."""

    def test_pod_level_zero_rejected(self):
        spec = _pod(pod_sc={"runAsNonRoot": True, "runAsUser": 0}, containers=[_container(sc={"allowPrivilegeEscalation": False, "runAsUser": 1000})])
        result = validate_pod([_ALWAYS_ANNOTATIONS], spec)
        assert result.allowed is False
        assert "runAsUser must not be 0" in result.message

    def test_pod_level_nonzero_ok(self):
        spec = _pod(pod_sc={"runAsNonRoot": True, "runAsUser": 1000}, containers=[_container(sc={"allowPrivilegeEscalation": False})])
        assert validate_pod([_ALWAYS_ANNOTATIONS], spec).allowed is True

    def test_pod_level_absent_ok(self):
        spec = _pod(pod_sc={"runAsNonRoot": True}, containers=[_container(sc={"allowPrivilegeEscalation": False, "runAsUser": 1000})])
        assert validate_pod([_ALWAYS_ANNOTATIONS], spec).allowed is True

    def test_container_zero_rejected(self):
        spec = _pod(pod_sc={"runAsNonRoot": True}, containers=[_container(name="bad", sc={"allowPrivilegeEscalation": False, "runAsUser": 0})])
        result = validate_pod([_ALWAYS_ANNOTATIONS], spec)
        assert result.allowed is False
        assert "'bad'" in result.message
        assert "runAsUser must not be 0" in result.message

    def test_container_nonzero_ok(self):
        spec = _pod(pod_sc={"runAsNonRoot": True}, containers=[_container(sc={"allowPrivilegeEscalation": False, "runAsUser": 1000})])
        assert validate_pod([_ALWAYS_ANNOTATIONS], spec).allowed is True

    def test_init_container_zero_rejected(self):
        spec = _pod(
            pod_sc={"runAsNonRoot": True, "runAsUser": 1000},
            containers=[_container(sc={"allowPrivilegeEscalation": False})],
            init_containers=[_container(name="init", sc={"allowPrivilegeEscalation": False, "runAsUser": 0})],
        )
        result = validate_pod([_ALWAYS_ANNOTATIONS], spec)
        assert result.allowed is False
        assert "'init'" in result.message
        assert "runAsUser must not be 0" in result.message

    def test_ephemeral_container_zero_rejected(self):
        spec = _pod(
            pod_sc={"runAsNonRoot": True, "runAsUser": 1000},
            containers=[_container(sc={"allowPrivilegeEscalation": False})],
            ephemeral_containers=[_container(name="debug", sc={"allowPrivilegeEscalation": False, "runAsUser": 0})],
        )
        result = validate_pod([_ALWAYS_ANNOTATIONS], spec)
        assert result.allowed is False
        assert "'debug'" in result.message
        assert "runAsUser must not be 0" in result.message

    def test_multiple_containers_only_zero_rejected(self):
        spec = _pod(
            pod_sc={"runAsNonRoot": True},
            containers=[
                _container(name="good", sc={"allowPrivilegeEscalation": False, "runAsUser": 1000}),
                _container(name="bad", sc={"allowPrivilegeEscalation": False, "runAsUser": 0}),
            ],
        )
        result = validate_pod([_ALWAYS_ANNOTATIONS], spec)
        assert result.allowed is False
        assert "'bad'" in result.message
        assert "'good'" not in result.message


# ---------------------------------------------------------------------------
# runAsNonRoot hardcoded REQUIRED_SCALAR constraint
# ---------------------------------------------------------------------------


class TestRunAsNonRoot:
    """runAsNonRoot=True is always enforced, following REQUIRED_SCALAR semantics."""

    # ------------------------------------------------------------------ #
    # Pod-level value
    # ------------------------------------------------------------------ #

    def test_pod_level_true_ok(self):
        spec = _pod(pod_sc={"runAsNonRoot": True, "runAsUser": 1000}, containers=[_container(sc={"allowPrivilegeEscalation": False})])
        assert validate_pod(_ALWAYS_ANNOTATIONS, spec).allowed is True

    def test_pod_level_false_rejected(self):
        spec = _pod(pod_sc={"runAsNonRoot": False, "runAsUser": 1000})
        result = validate_pod([_ALWAYS_ANNOTATIONS], spec)
        assert result.allowed is False
        assert "runAsNonRoot" in result.message

    def test_pod_level_absent_container_not_set_rejected(self):
        """No pod-level default and container doesn't set it → rejected."""
        spec = _pod(containers=[_container(sc={"runAsUser": 1000})])
        result = validate_pod([_ALWAYS_ANNOTATIONS], spec)
        assert result.allowed is False
        assert "runAsNonRoot" in result.message

    # ------------------------------------------------------------------ #
    # Pod-level True covers containers
    # ------------------------------------------------------------------ #

    def test_pod_level_true_covers_containers(self):
        """Pod-level True is sufficient; containers don't need to set it individually."""
        spec = _pod(
            pod_sc={"runAsNonRoot": True},
            containers=[_container(sc={"runAsUser": 1000, "allowPrivilegeEscalation": False})],
        )
        assert validate_pod([_ALWAYS_ANNOTATIONS], spec).allowed is True

    def test_container_explicit_false_still_rejected_even_with_pod_true(self):
        """Container explicitly setting False overrides pod default and must be rejected."""
        spec = _pod(
            pod_sc={"runAsNonRoot": True},
            containers=[_container(sc={"runAsUser": 1000, "runAsNonRoot": False})],
        )
        result = validate_pod([_ALWAYS_ANNOTATIONS], spec)
        assert result.allowed is False
        assert "runAsNonRoot" in result.message

    # ------------------------------------------------------------------ #
    # Container-level value (no pod-level default)
    # ------------------------------------------------------------------ #

    def test_all_containers_set_true_ok(self):
        """All containers set True, no pod-level default → allowed."""
        spec = _pod(
            containers=[_container(sc={"runAsUser": 1000, "runAsNonRoot": True, "allowPrivilegeEscalation": False})],
        )
        assert validate_pod([_ALWAYS_ANNOTATIONS], spec).allowed is True

    def test_container_sets_false_rejected(self):
        spec = _pod(
            containers=[_container(sc={"runAsUser": 1000, "runAsNonRoot": False})],
        )
        result = validate_pod([_ALWAYS_ANNOTATIONS], spec)
        assert result.allowed is False
        assert "runAsNonRoot" in result.message

    def test_one_container_missing_rejected(self):
        """Two containers, one missing runAsNonRoot and no pod default → rejected."""
        spec = _pod(
            containers=[
                _container("c1", sc={"runAsUser": 1000, "runAsNonRoot": True}),
                _container("c2", sc={"runAsUser": 1000}),
            ],
        )
        result = validate_pod([_ALWAYS_ANNOTATIONS], spec)
        assert result.allowed is False
        assert "c2" in result.message
        assert "runAsNonRoot" in result.message

    # ------------------------------------------------------------------ #
    # initContainers and ephemeralContainers
    # ------------------------------------------------------------------ #

    def test_init_container_false_rejected(self):
        spec = _pod(
            pod_sc={"runAsNonRoot": True},
            containers=[_container(sc={"runAsUser": 1000})],
            init_containers=[_container("init", sc={"runAsUser": 1000, "runAsNonRoot": False})],
        )
        result = validate_pod([_ALWAYS_ANNOTATIONS], spec)
        assert result.allowed is False
        assert "init" in result.message

    def test_ephemeral_container_missing_rejected_without_pod_default(self):
        """Ephemeral container without runAsNonRoot, no pod default → rejected."""
        spec = _pod(
            containers=[_container(sc={"runAsUser": 1000, "runAsNonRoot": True})],
            ephemeral_containers=[_container("debug", sc={"runAsUser": 1000})],
        )
        result = validate_pod([_ALWAYS_ANNOTATIONS], spec)
        assert result.allowed is False
        assert "debug" in result.message

    def test_ephemeral_container_covered_by_pod_level(self):
        """Pod-level True covers ephemeral containers too."""
        spec = _pod(
            pod_sc={"runAsNonRoot": True},
            containers=[_container(sc={"runAsUser": 1000, "allowPrivilegeEscalation": False})],
            ephemeral_containers=[_container("debug", sc={"runAsUser": 1000, "allowPrivilegeEscalation": False})],
        )
        assert validate_pod([_ALWAYS_ANNOTATIONS], spec).allowed is True

    # ------------------------------------------------------------------ #
    # No securityContext at all on container
    # ------------------------------------------------------------------ #

    def test_no_container_sc_no_pod_default_rejected(self):
        spec = _pod(containers=[_container(sc=None)])
        result = validate_pod([_ALWAYS_ANNOTATIONS], spec)
        assert result.allowed is False
        assert "runAsNonRoot" in result.message


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
            pod_sc={"runAsNonRoot": True},
            containers=[_container(sc={"runAsUser": 1000, "allowPrivilegeEscalation": False})],
            volumes=list(volumes),
        )

    def test_no_volumes_ok(self):
        assert validate_pod(_ALWAYS_ANNOTATIONS, _pod(pod_sc={"runAsNonRoot": True}, containers=[_container(sc={"runAsUser": 1000, "allowPrivilegeEscalation": False})])).allowed is True

    def test_each_allowed_non_nfs_type_ok(self):
        for vol_type in _ALLOWED_VOLUME_TYPES:
            if vol_type == "nfs":
                continue  # tested separately; needs allowedNfsVolumes annotation too
            spec = self._spec({"name": "v", vol_type: {}})
            result = validate_pod([_ALWAYS_ANNOTATIONS], spec)
            assert result.allowed is True, f"Expected {vol_type!r} to be allowed; got: {result.message}"

    def test_nfs_type_ok_when_annotation_permits(self):
        anns = {**_ALWAYS_ANNOTATIONS, "tritonai-admission-webhook/policy.allowedNfsVolumes": "nfsserver:/path"}
        spec = self._spec({"name": "v", "nfs": {"server": "nfsserver", "path": "/path"}})
        assert validate_pod([anns], spec).allowed is True

    def test_disallowed_type_rejected(self):
        spec = self._spec({"name": "v", "hostPath": {"path": "/host"}})
        result = validate_pod([_ALWAYS_ANNOTATIONS], spec)
        assert result.allowed is False
        assert "hostPath" in result.message

    def test_multiple_volumes_all_allowed_ok(self):
        spec = self._spec(
            {"name": "cfg", "configMap": {"name": "my-cm"}},
            {"name": "tmp", "emptyDir": {}},
        )
        assert validate_pod([_ALWAYS_ANNOTATIONS], spec).allowed is True

    def test_one_disallowed_among_many_rejected(self):
        spec = self._spec(
            {"name": "cfg", "configMap": {}},
            {"name": "bad", "hostPath": {"path": "/etc"}},
            {"name": "tmp", "emptyDir": {}},
        )
        result = validate_pod([_ALWAYS_ANNOTATIONS], spec)
        assert result.allowed is False
        assert "bad" in result.message
        assert "hostPath" in result.message

    def test_error_names_disallowed_type(self):
        spec = self._spec({"name": "mysecret", "hostIPC": {}})
        result = validate_pod([_ALWAYS_ANNOTATIONS], spec)
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
        pod_sc={"runAsNonRoot": True},
        containers=[_container(sc={"runAsUser": 1000, "allowPrivilegeEscalation": False})],
        volumes=list(nfs_volumes),
    )


# ---------------------------------------------------------------------------
# prohibitedVolumeTypes annotation constraint
# ---------------------------------------------------------------------------

_PVT_ANN = "tritonai-admission-webhook/policy.prohibitedVolumeTypes"


class TestProhibitedVolumeTypes:

    def _spec(self, *volumes: dict) -> dict:
        return _pod(pod_sc={"runAsNonRoot": True}, containers=[_container(sc={"runAsUser": 1000, "allowPrivilegeEscalation": False})], volumes=list(volumes))

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
            result = validate_pod([_ALWAYS_ANNOTATIONS], spec)
            assert result.allowed is True, f"Expected {vol_type!r} allowed without annotation; got: {result.message}"

    # ------------------------------------------------------------------ #
    # Single-type prohibition
    # ------------------------------------------------------------------ #

    def test_prohibited_type_rejected(self):
        spec = self._spec({"name": "tmp", "emptyDir": {}})
        result = validate_pod([self._anns("emptyDir")], spec)
        assert result.allowed is False
        assert "tmp" in result.message
        assert "emptyDir" in result.message

    def test_prohibited_type_absent_from_pod_ok(self):
        spec = self._spec({"name": "cfg", "configMap": {"name": "cm"}})
        assert validate_pod([self._anns("emptyDir")], spec).allowed is True

    def test_prohibit_secret(self):
        spec = self._spec({"name": "s", "secret": {"secretName": "x"}})
        result = validate_pod([self._anns("secret")], spec)
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
        result = validate_pod([self._anns("emptyDir,secret")], spec)
        assert result.allowed is False
        assert "tmp" in result.message
        assert "s" in result.message

    def test_prohibit_multiple_only_matching_reported(self):
        # configMap is not prohibited; emptyDir is
        spec = self._spec(
            {"name": "cfg", "configMap": {}},
            {"name": "tmp", "emptyDir": {}},
        )
        result = validate_pod([self._anns("emptyDir,secret")], spec)
        assert result.allowed is False
        assert "tmp" in result.message
        assert "cfg" not in result.message

    # ------------------------------------------------------------------ #
    # Empty / whitespace annotation — no additional restriction
    # ------------------------------------------------------------------ #

    def test_empty_annotation_no_restriction(self):
        spec = self._spec({"name": "tmp", "emptyDir": {}})
        assert validate_pod([self._anns("")], spec).allowed is True

    def test_whitespace_annotation_no_restriction(self):
        spec = self._spec({"name": "tmp", "emptyDir": {}})
        assert validate_pod([self._anns("   ")], spec).allowed is True

    # ------------------------------------------------------------------ #
    # Unknown type names in annotation (not in base set)
    # ------------------------------------------------------------------ #

    def test_unknown_type_name_ignored(self):
        # "notARealType" not in base set; emptyDir still prohibited
        spec = self._spec({"name": "tmp", "emptyDir": {}})
        result = validate_pod([self._anns("notARealType,emptyDir")], spec)
        assert result.allowed is False
        assert "emptyDir" in result.message

    def test_only_unknown_type_no_restriction(self):
        spec = self._spec({"name": "tmp", "emptyDir": {}})
        assert validate_pod([self._anns("notARealType")], spec).allowed is True

    # ------------------------------------------------------------------ #
    # No volumes — always passes
    # ------------------------------------------------------------------ #

    def test_no_volumes_always_ok(self):
        spec = _pod(pod_sc={"runAsNonRoot": True}, containers=[_container(sc={"runAsUser": 1000, "allowPrivilegeEscalation": False})])
        assert validate_pod(self._anns("emptyDir,secret"), spec).allowed is True

    # ------------------------------------------------------------------ #
    # Types outside the base set remain rejected regardless
    # ------------------------------------------------------------------ #

    def test_base_disallowed_type_always_rejected(self):
        spec = self._spec({"name": "bad", "hostPath": {"path": "/host"}})
        assert validate_pod([_ALWAYS_ANNOTATIONS], spec).allowed is False

    # ------------------------------------------------------------------ #
    # configMap prohibition — env / envFrom
    # ------------------------------------------------------------------ #

    def test_configmap_prohibited_blocks_configmapkeyref_in_env(self):
        c = _container(
            sc={"runAsUser": 1000},
            env=[{"name": "X", "valueFrom": {"configMapKeyRef": {"name": "cm", "key": "k"}}}],
        )
        result = validate_pod([self._anns("configMap")], _pod(containers=[c]))
        assert result.allowed is False
        assert "configMapKeyRef" in result.message
        assert "X" in result.message

    def test_configmap_prohibited_blocks_configmapref_in_envfrom(self):
        c = _container(
            sc={"runAsUser": 1000},
            env_from=[{"configMapRef": {"name": "my-cm"}}],
        )
        result = validate_pod([self._anns("configMap")], _pod(containers=[c]))
        assert result.allowed is False
        assert "configMapRef" in result.message
        assert "my-cm" in result.message

    def test_configmap_not_prohibited_allows_configmapkeyref(self):
        c = _container(
            sc={"runAsUser": 1000, "allowPrivilegeEscalation": False},
            env=[{"name": "X", "valueFrom": {"configMapKeyRef": {"name": "cm", "key": "k"}}}],
        )
        assert validate_pod([_ALWAYS_ANNOTATIONS], _pod(pod_sc={"runAsNonRoot": True}, containers=[c])).allowed is True

    # ------------------------------------------------------------------ #
    # secret prohibition — env / envFrom
    # ------------------------------------------------------------------ #

    def test_secret_prohibited_blocks_secretkeyref_in_env(self):
        c = _container(
            sc={"runAsUser": 1000},
            env=[{"name": "PWD", "valueFrom": {"secretKeyRef": {"name": "my-sec", "key": "pw"}}}],
        )
        result = validate_pod([self._anns("secret")], _pod(containers=[c]))
        assert result.allowed is False
        assert "secretKeyRef" in result.message
        assert "PWD" in result.message

    def test_secret_prohibited_blocks_secretref_in_envfrom(self):
        c = _container(
            sc={"runAsUser": 1000},
            env_from=[{"secretRef": {"name": "my-sec"}}],
        )
        result = validate_pod([self._anns("secret")], _pod(containers=[c]))
        assert result.allowed is False
        assert "secretRef" in result.message
        assert "my-sec" in result.message

    def test_secret_not_prohibited_allows_secretkeyref(self):
        c = _container(
            sc={"runAsUser": 1000, "allowPrivilegeEscalation": False},
            env=[{"name": "PWD", "valueFrom": {"secretKeyRef": {"name": "s", "key": "p"}}}],
        )
        assert validate_pod([_ALWAYS_ANNOTATIONS], _pod(pod_sc={"runAsNonRoot": True}, containers=[c])).allowed is True

    # ------------------------------------------------------------------ #
    # downwardAPI prohibition — env
    # ------------------------------------------------------------------ #

    def test_downwardapi_prohibited_blocks_fieldref_in_env(self):
        c = _container(
            sc={"runAsUser": 1000},
            env=[{"name": "NS", "valueFrom": {"fieldRef": {"fieldPath": "metadata.namespace"}}}],
        )
        result = validate_pod([self._anns("downwardAPI")], _pod(containers=[c]))
        assert result.allowed is False
        assert "fieldRef" in result.message
        assert "NS" in result.message

    def test_downwardapi_prohibited_blocks_resourcefieldref_in_env(self):
        c = _container(
            sc={"runAsUser": 1000},
            env=[{"name": "CPU", "valueFrom": {"resourceFieldRef": {"resource": "limits.cpu"}}}],
        )
        result = validate_pod([self._anns("downwardAPI")], _pod(containers=[c]))
        assert result.allowed is False
        assert "resourceFieldRef" in result.message
        assert "CPU" in result.message

    def test_downwardapi_not_prohibited_allows_fieldref(self):
        c = _container(
            sc={"runAsUser": 1000, "allowPrivilegeEscalation": False},
            env=[{"name": "NS", "valueFrom": {"fieldRef": {"fieldPath": "metadata.namespace"}}}],
        )
        assert validate_pod([_ALWAYS_ANNOTATIONS], _pod(pod_sc={"runAsNonRoot": True}, containers=[c])).allowed is True

    # ------------------------------------------------------------------ #
    # Prohibiting one type does not block another type's env sources
    # ------------------------------------------------------------------ #

    def test_secret_prohibition_does_not_block_configmap_env(self):
        c = _container(
            sc={"runAsUser": 1000, "allowPrivilegeEscalation": False},
            env=[{"name": "X", "valueFrom": {"configMapKeyRef": {"name": "cm", "key": "k"}}}],
        )
        assert validate_pod([self._anns("secret")], _pod(pod_sc={"runAsNonRoot": True}, containers=[c])).allowed is True

    def test_configmap_prohibition_does_not_block_secret_env(self):
        c = _container(
            sc={"runAsUser": 1000, "allowPrivilegeEscalation": False},
            env=[{"name": "P", "valueFrom": {"secretKeyRef": {"name": "s", "key": "k"}}}],
        )
        assert validate_pod([self._anns("configMap")], _pod(pod_sc={"runAsNonRoot": True}, containers=[c])).allowed is True

    # ------------------------------------------------------------------ #
    # Env checks apply to initContainers and ephemeralContainers too
    # ------------------------------------------------------------------ #

    def test_configmap_prohibition_applies_to_init_container_env(self):
        main = _container(sc={"runAsUser": 1000})
        init = _container(
            "init",
            sc={"runAsUser": 1000},
            env=[{"name": "X", "valueFrom": {"configMapKeyRef": {"name": "cm", "key": "k"}}}],
        )
        result = validate_pod([self._anns("configMap")], _pod(containers=[main], init_containers=[init]))
        assert result.allowed is False
        assert "init" in result.message

    def test_secret_prohibition_applies_to_ephemeral_container_envfrom(self):
        main = _container(sc={"runAsUser": 1000})
        eph = _container(
            "debug",
            sc={"runAsUser": 1000},
            env_from=[{"secretRef": {"name": "s"}}],
        )
        result = validate_pod([self._anns("secret")], _pod(containers=[main], ephemeral_containers=[eph]))
        assert result.allowed is False
        assert "debug" in result.message


class TestAllowedNfsVolumes:

    # ------------------------------------------------------------------ #
    # No NFS volumes — always passes regardless of annotation
    # ------------------------------------------------------------------ #

    def test_no_nfs_volumes_annotation_absent_ok(self):
        spec = _nfs_spec()
        assert validate_pod([_NFS_ANNOTATIONS_BASE], spec).allowed is True

    def test_no_nfs_volumes_annotation_empty_ok(self):
        anns = {**_NFS_ANNOTATIONS_BASE, "tritonai-admission-webhook/policy.allowedNfsVolumes": ""}
        assert validate_pod([anns], _nfs_spec()).allowed is True

    def test_no_nfs_volumes_annotation_with_patterns_ok(self):
        anns = {**_NFS_ANNOTATIONS_BASE, "tritonai-admission-webhook/policy.allowedNfsVolumes": "10.20.5.3:/export/data"}
        assert validate_pod([anns], _nfs_spec()).allowed is True

    # ------------------------------------------------------------------ #
    # NFS volume present — annotation absent/empty → denied
    # ------------------------------------------------------------------ #

    def test_nfs_volume_annotation_absent_rejected(self):
        result = validate_pod([_NFS_ANNOTATIONS_BASE], _nfs_spec(_NFS_VOL))
        assert result.allowed is False
        assert "nfs-vol" in result.message
        assert "allowedNfsVolumes" in result.message

    def test_nfs_volume_annotation_empty_string_rejected(self):
        anns = {**_NFS_ANNOTATIONS_BASE, "tritonai-admission-webhook/policy.allowedNfsVolumes": ""}
        result = validate_pod([anns], _nfs_spec(_NFS_VOL))
        assert result.allowed is False

    def test_nfs_volume_annotation_whitespace_only_rejected(self):
        anns = {**_NFS_ANNOTATIONS_BASE, "tritonai-admission-webhook/policy.allowedNfsVolumes": "   "}
        result = validate_pod([anns], _nfs_spec(_NFS_VOL))
        assert result.allowed is False

    # ------------------------------------------------------------------ #
    # Exact matches
    # ------------------------------------------------------------------ #

    def test_exact_match_allowed(self):
        anns = {**_NFS_ANNOTATIONS_BASE, "tritonai-admission-webhook/policy.allowedNfsVolumes": "10.20.5.3:/export/data"}
        assert validate_pod([anns], _nfs_spec(_NFS_VOL)).allowed is True

    def test_exact_match_server_mismatch_rejected(self):
        anns = {**_NFS_ANNOTATIONS_BASE, "tritonai-admission-webhook/policy.allowedNfsVolumes": "10.20.5.4:/export/data"}
        result = validate_pod([anns], _nfs_spec(_NFS_VOL))
        assert result.allowed is False

    def test_exact_match_path_mismatch_rejected(self):
        anns = {**_NFS_ANNOTATIONS_BASE, "tritonai-admission-webhook/policy.allowedNfsVolumes": "10.20.5.3:/export/other"}
        result = validate_pod([anns], _nfs_spec(_NFS_VOL))
        assert result.allowed is False

    def test_multiple_exact_patterns_or_semantics(self):
        anns = {**_NFS_ANNOTATIONS_BASE, "tritonai-admission-webhook/policy.allowedNfsVolumes": "itsnfs:/scratch,10.20.5.3:/export/data"}
        assert validate_pod([anns], _nfs_spec(_NFS_VOL)).allowed is True

    # ------------------------------------------------------------------ #
    # Glob matches
    # ------------------------------------------------------------------ #

    def test_glob_server_wildcard_allowed(self):
        vol = {"name": "v", "nfs": {"server": "its-dsmlp-fs03", "path": "/export/workspaces/PROJ_TEST"}}
        anns = {**_NFS_ANNOTATIONS_BASE, "tritonai-admission-webhook/policy.allowedNfsVolumes": "its-dsmlp-fs0[1-9]:/export/workspaces/*"}
        assert validate_pod([anns], _nfs_spec(vol)).allowed is True

    def test_glob_path_wildcard_allowed(self):
        vol = {"name": "v", "nfs": {"server": "itsnfs", "path": "/scratch/proj"}}
        anns = {**_NFS_ANNOTATIONS_BASE, "tritonai-admission-webhook/policy.allowedNfsVolumes": "itsnfs:/scratch/*"}
        assert validate_pod([anns], _nfs_spec(vol)).allowed is True

    def test_glob_outside_range_rejected(self):
        # its-dsmlp-fs0[1-9] does not match its-dsmlp-fs10
        vol = {"name": "v", "nfs": {"server": "its-dsmlp-fs10", "path": "/export/workspaces/PROJ"}}
        anns = {**_NFS_ANNOTATIONS_BASE, "tritonai-admission-webhook/policy.allowedNfsVolumes": "its-dsmlp-fs0[1-9]:/export/workspaces/*"}
        result = validate_pod([anns], _nfs_spec(vol))
        assert result.allowed is False

    def test_glob_full_example_from_spec(self):
        """Reproduce the example from the requirements."""
        anns = {
            **_NFS_ANNOTATIONS_BASE,
            "tritonai-admission-webhook/policy.allowedNfsVolumes": (
                "10.20.5.3:/export/data,"
                "itsnfs:/scratch,"
                "its-dsmlp-fs03:/export/workspaces/PROJ_TEST"
            ),
        }
        vol = {"name": "v", "nfs": {"server": "its-dsmlp-fs03", "path": "/export/workspaces/PROJ_TEST"}}
        assert validate_pod([anns], _nfs_spec(vol)).allowed is True

    # ------------------------------------------------------------------ #
    # Multiple NFS volumes
    # ------------------------------------------------------------------ #

    def test_multiple_nfs_all_allowed(self):
        anns = {**_NFS_ANNOTATIONS_BASE, "tritonai-admission-webhook/policy.allowedNfsVolumes": "nfs1:/data,nfs2:/data"}
        vol1 = {"name": "v1", "nfs": {"server": "nfs1", "path": "/data"}}
        vol2 = {"name": "v2", "nfs": {"server": "nfs2", "path": "/data"}}
        assert validate_pod([anns], _nfs_spec(vol1, vol2)).allowed is True

    def test_multiple_nfs_one_disallowed_rejected(self):
        anns = {**_NFS_ANNOTATIONS_BASE, "tritonai-admission-webhook/policy.allowedNfsVolumes": "nfs1:/data"}
        vol1 = {"name": "v1", "nfs": {"server": "nfs1", "path": "/data"}}
        vol2 = {"name": "v2", "nfs": {"server": "nfs2", "path": "/data"}}
        result = validate_pod([anns], _nfs_spec(vol1, vol2))
        assert result.allowed is False
        assert "v2" in result.message

    # ------------------------------------------------------------------ #
    # NFS volumes alongside other volume types
    # ------------------------------------------------------------------ #

    def test_nfs_alongside_allowed_types_ok(self):
        anns = {**_NFS_ANNOTATIONS_BASE, "tritonai-admission-webhook/policy.allowedNfsVolumes": "10.20.5.3:/export/data"}
        spec = _pod(
            pod_sc={"runAsNonRoot": True},
            containers=[_container(sc={"runAsUser": 1000, "allowPrivilegeEscalation": False})],
            volumes=[
                {"name": "cfg", "configMap": {"name": "my-cm"}},
                _NFS_VOL,
            ],
        )
        assert validate_pod([anns], spec).allowed is True


# ---------------------------------------------------------------------------
# Toleration allowlist constraint
# ---------------------------------------------------------------------------

_TOL_ANNOTATIONS_BASE = {"tritonai-admission-webhook/policy.runAsUser": "1000"}
_TOL_KEY = "tritonai-admission-webhook/policy.tolerations"


def _tol_spec(*tolerations: dict) -> dict:
    spec = _pod(
        pod_sc={"runAsNonRoot": True},
        containers=[_container(sc={"runAsUser": 1000, "allowPrivilegeEscalation": False})],
    )
    spec["tolerations"] = list(tolerations)
    return spec


class TestValidateTolerations:

    # annotation absent → no restriction
    def test_no_annotation_permits_any_toleration(self):
        tol = {"key": "node-type", "operator": "Equal", "value": "its-ai", "effect": "NoSchedule"}
        result = validate_pod([_TOL_ANNOTATIONS_BASE], _tol_spec(tol))
        assert result.allowed is True

    def test_no_annotation_permits_no_tolerations(self):
        result = validate_pod(_TOL_ANNOTATIONS_BASE, _pod(pod_sc={"runAsNonRoot": True},
                                                          containers=[_container(sc={"runAsUser": 1000, "allowPrivilegeEscalation": False})]))
        assert result.allowed is True

    # exact match
    def test_exact_equal_toleration_allowed(self):
        anns = {**_TOL_ANNOTATIONS_BASE, _TOL_KEY: "node-type=its-ai:NoSchedule"}
        tol = {"key": "node-type", "operator": "Equal", "value": "its-ai", "effect": "NoSchedule"}
        assert validate_pod([anns], _tol_spec(tol)).allowed is True

    def test_exact_exists_toleration_rejected_by_non_wildcard_value(self):
        """Exists toleration does not match a non-'*' value pattern."""
        anns = {**_TOL_ANNOTATIONS_BASE, _TOL_KEY: "node-type=its-ai:NoSchedule"}
        tol = {"key": "node-type", "operator": "Exists", "effect": "NoSchedule"}
        result = validate_pod([anns], _tol_spec(tol))
        assert result.allowed is False
        assert "toleration" in result.message.lower()

    # wildcard value "*" matches both Equal and Exists
    def test_wildcard_value_permits_equal_toleration(self):
        anns = {**_TOL_ANNOTATIONS_BASE, _TOL_KEY: "node-type=*:NoSchedule"}
        tol = {"key": "node-type", "operator": "Equal", "value": "its-ai-dev", "effect": "NoSchedule"}
        assert validate_pod([anns], _tol_spec(tol)).allowed is True

    def test_wildcard_value_permits_exists_toleration(self):
        anns = {**_TOL_ANNOTATIONS_BASE, _TOL_KEY: "node-type=*:NoSchedule"}
        tol = {"key": "node-type", "operator": "Exists", "effect": "NoSchedule"}
        assert validate_pod([anns], _tol_spec(tol)).allowed is True

    # fnmatch glob in value (non-"*" pattern)
    def test_glob_value_pattern_matches(self):
        anns = {**_TOL_ANNOTATIONS_BASE, _TOL_KEY: "node-type=its-ai*:NoSchedule"}
        tol = {"key": "node-type", "operator": "Equal", "value": "its-ai-dev", "effect": "NoSchedule"}
        assert validate_pod([anns], _tol_spec(tol)).allowed is True

    def test_glob_value_pattern_no_match(self):
        anns = {**_TOL_ANNOTATIONS_BASE, _TOL_KEY: "node-type=its-ai*:NoSchedule"}
        tol = {"key": "node-type", "operator": "Equal", "value": "glean-node", "effect": "NoSchedule"}
        result = validate_pod([anns], _tol_spec(tol))
        assert result.allowed is False

    # fnmatch glob in key
    def test_glob_key_pattern_matches(self):
        anns = {**_TOL_ANNOTATIONS_BASE, _TOL_KEY: "node-*=its-ai:NoSchedule"}
        tol = {"key": "node-type", "operator": "Equal", "value": "its-ai", "effect": "NoSchedule"}
        assert validate_pod([anns], _tol_spec(tol)).allowed is True

    # fnmatch glob in effect
    def test_glob_effect_pattern_matches(self):
        anns = {**_TOL_ANNOTATIONS_BASE, _TOL_KEY: "node-type=its-ai:No*"}
        tol = {"key": "node-type", "operator": "Equal", "value": "its-ai", "effect": "NoSchedule"}
        assert validate_pod([anns], _tol_spec(tol)).allowed is True

    def test_effect_mismatch_rejected(self):
        anns = {**_TOL_ANNOTATIONS_BASE, _TOL_KEY: "node-type=its-ai:NoSchedule"}
        tol = {"key": "node-type", "operator": "Equal", "value": "its-ai", "effect": "NoExecute"}
        result = validate_pod([anns], _tol_spec(tol))
        assert result.allowed is False

    # multiple permitted entries (OR semantics)
    def test_multiple_permitted_entries_covers_different_tolerations(self):
        anns = {**_TOL_ANNOTATIONS_BASE, _TOL_KEY: "node-type=its-ai:NoSchedule,glean-node=*:NoExecute"}
        tol1 = {"key": "node-type", "operator": "Equal", "value": "its-ai", "effect": "NoSchedule"}
        tol2 = {"key": "glean-node", "operator": "Exists", "effect": "NoExecute"}
        assert validate_pod([anns], _tol_spec(tol1, tol2)).allowed is True

    def test_one_of_two_tolerations_rejected(self):
        anns = {**_TOL_ANNOTATIONS_BASE, _TOL_KEY: "node-type=its-ai:NoSchedule"}
        tol1 = {"key": "node-type", "operator": "Equal", "value": "its-ai", "effect": "NoSchedule"}
        tol2 = {"key": "other", "operator": "Equal", "value": "x", "effect": "NoSchedule"}
        result = validate_pod([anns], _tol_spec(tol1, tol2))
        assert result.allowed is False
        assert "other" in result.message

    # empty / absent tolerations always pass
    def test_empty_tolerations_list_always_ok(self):
        anns = {**_TOL_ANNOTATIONS_BASE, _TOL_KEY: "node-type=its-ai:NoSchedule"}
        spec = _pod(pod_sc={"runAsNonRoot": True}, containers=[_container(sc={"runAsUser": 1000, "allowPrivilegeEscalation": False})])
        spec["tolerations"] = []
        assert validate_pod([anns], spec).allowed is True

    def test_absent_tolerations_always_ok(self):
        anns = {**_TOL_ANNOTATIONS_BASE, _TOL_KEY: "node-type=its-ai:NoSchedule"}
        spec = _pod(pod_sc={"runAsNonRoot": True}, containers=[_container(sc={"runAsUser": 1000, "allowPrivilegeEscalation": False})])
        assert validate_pod(anns, spec).allowed is True

    # malformed annotation
    def test_malformed_annotation_rejects_pod(self):
        anns = {**_TOL_ANNOTATIONS_BASE, _TOL_KEY: "no-colon-here"}
        tol = {"key": "x", "operator": "Equal", "value": "y", "effect": "NoSchedule"}
        result = validate_pod([anns], _tol_spec(tol))
        assert result.allowed is False
        assert "malformed" in result.message.lower()

    # node.kubernetes.io/* implicit allowlist
    def test_node_kubernetes_toleration_always_permitted_without_annotation(self):
        """node.kubernetes.io/* tolerations pass even when no tolerations annotation exists."""
        tol = {"key": "node.kubernetes.io/not-ready", "operator": "Exists", "effect": "NoExecute"}
        result = validate_pod([_TOL_ANNOTATIONS_BASE], _tol_spec(tol))
        assert result.allowed is True

    def test_node_kubernetes_toleration_always_permitted_with_annotation(self):
        """node.kubernetes.io/* tolerations pass even when the annotation doesn't cover them."""
        anns = {**_TOL_ANNOTATIONS_BASE, _TOL_KEY: "node-type=its-ai:NoSchedule"}
        tol = {"key": "node.kubernetes.io/unreachable", "operator": "Exists", "effect": "NoExecute"}
        result = validate_pod([anns], _tol_spec(tol))
        assert result.allowed is True

    def test_node_kubernetes_toleration_exempt_while_custom_is_still_checked(self):
        """node.kubernetes.io/* toleration is exempt; any other toleration is still validated."""
        anns = {**_TOL_ANNOTATIONS_BASE, _TOL_KEY: "node-type=its-ai:NoSchedule"}
        sys_tol = {"key": "node.kubernetes.io/not-ready", "operator": "Exists", "effect": "NoExecute"}
        bad_tol = {"key": "other", "operator": "Equal", "value": "x", "effect": "NoSchedule"}
        result = validate_pod([anns], _tol_spec(sys_tol, bad_tol))
        assert result.allowed is False
        assert "other" in result.message

    def test_node_kubernetes_toleration_exempt_alongside_permitted_custom(self):
        """Mix of node.kubernetes.io/* and an explicitly-permitted toleration is allowed."""
        anns = {**_TOL_ANNOTATIONS_BASE, _TOL_KEY: "node-type=its-ai:NoSchedule"}
        sys_tol = {"key": "node.kubernetes.io/not-ready", "operator": "Exists", "effect": "NoExecute"}
        ok_tol = {"key": "node-type", "operator": "Equal", "value": "its-ai", "effect": "NoSchedule"}
        result = validate_pod([anns], _tol_spec(sys_tol, ok_tol))
        assert result.allowed is True


# ---------------------------------------------------------------------------
# Negation operator integration tests
# ---------------------------------------------------------------------------

_P = "tritonai-admission-webhook/policy."


class TestNegationIntegration:
    """End-to-end validation tests for the ! negation operator."""

    def test_required_scalar_negated_value_rejected(self):
        """runAsUser=!1000 → uid 1000 is denied."""
        anns = {f"{_P}runAsUser": "!1000"}
        spec = _pod(
            pod_sc={"runAsNonRoot": True, "runAsUser": 1000},
            containers=[_container(sc={"allowPrivilegeEscalation": False})],
        )
        result = validate_pod([anns], spec)
        assert result.allowed is False
        assert "runAsUser" in result.message

    def test_required_scalar_negated_value_allowed(self):
        """runAsUser=!1000 → uid 2000 is allowed."""
        anns = {f"{_P}runAsUser": "!1000"}
        spec = _pod(
            pod_sc={"runAsNonRoot": True, "runAsUser": 2000},
            containers=[_container(sc={"allowPrivilegeEscalation": False})],
        )
        result = validate_pod([anns], spec)
        assert result.allowed is True

    def test_required_scalar_mixed_positive_and_negated(self):
        """runAsUser=1000,2000,!3000 → 1000 ok, 3000 denied, 999 denied."""
        anns = {f"{_P}runAsUser": "1000,2000,!3000"}
        base_sc = {"runAsNonRoot": True}
        containers = [_container(sc={"allowPrivilegeEscalation": False})]

        # 1000 → allowed (positive match, not negated)
        spec = _pod(pod_sc={**base_sc, "runAsUser": 1000}, containers=containers)
        assert validate_pod([anns], spec).allowed is True

        # 3000 → denied (negated)
        spec = _pod(pod_sc={**base_sc, "runAsUser": 3000}, containers=containers)
        assert validate_pod([anns], spec).allowed is False

        # 999 → denied (no positive match)
        spec = _pod(pod_sc={**base_sc, "runAsUser": 999}, containers=containers)
        assert validate_pod([anns], spec).allowed is False

    def test_optional_list_negated_blocks_entry(self):
        """supplementalGroups=!5000 → a group list containing 5000 is denied."""
        anns = {
            f"{_P}runAsUser": "1000",
            f"{_P}supplementalGroups": "!5000",
        }
        spec = _pod(
            pod_sc={"runAsNonRoot": True, "runAsUser": 1000, "supplementalGroups": [5000]},
            containers=[_container(sc={"allowPrivilegeEscalation": False})],
        )
        result = validate_pod([anns], spec)
        assert result.allowed is False
        assert "supplementalGroups" in result.message

    def test_optional_list_negated_allows_other(self):
        """supplementalGroups=!5000 → a group list without 5000 is allowed."""
        anns = {
            f"{_P}runAsUser": "1000",
            f"{_P}supplementalGroups": "!5000",
        }
        spec = _pod(
            pod_sc={"runAsNonRoot": True, "runAsUser": 1000, "supplementalGroups": [6000, 7000]},
            containers=[_container(sc={"allowPrivilegeEscalation": False})],
        )
        result = validate_pod([anns], spec)
        assert result.allowed is True

    def test_node_selectors_negated_blocks_label(self):
        """nodeSelectors=!partition=gpu → nodeSelector with partition=gpu is denied."""
        anns = {
            f"{_P}runAsUser": "1000",
            f"{_P}nodeSelectors": "!partition=gpu",
        }
        spec = _pod(
            pod_sc={"runAsNonRoot": True, "runAsUser": 1000},
            containers=[_container(sc={"allowPrivilegeEscalation": False})],
        )
        spec["nodeSelector"] = {"partition": "gpu"}
        result = validate_pod([anns], spec)
        assert result.allowed is False
        assert "nodeSelectors" in result.message.lower() or "nodeSelector" in result.message

    def test_node_selectors_negated_allows_other(self):
        """nodeSelectors=partition=cpu,!partition=gpu → partition=cpu is allowed."""
        anns = {
            f"{_P}runAsUser": "1000",
            f"{_P}nodeSelectors": "partition=cpu,!partition=gpu",
        }
        spec = _pod(
            pod_sc={"runAsNonRoot": True, "runAsUser": 1000},
            containers=[_container(sc={"allowPrivilegeEscalation": False})],
        )
        spec["nodeSelector"] = {"partition": "cpu"}
        result = validate_pod([anns], spec)
        assert result.allowed is True


# ---------------------------------------------------------------------------
# nodeSelectors — nodeAffinity prohibition for negated tokens
# ---------------------------------------------------------------------------

_NA_ANNS = {f"{_P}nodeSelectors": "!rack=gpu"}
_NA_ANNS_MULTI = {f"{_P}nodeSelectors": "rack=cpu,!rack=gpu"}


def _affinity_spec(key: str, op: str = "In", values: list | None = None) -> dict:
    """Build a minimal pod spec with a nodeAffinity matchExpression."""
    spec = _pod(
        pod_sc={"runAsNonRoot": True},
        containers=[_container(sc={"allowPrivilegeEscalation": False})],
    )
    spec["affinity"] = {
        "nodeAffinity": {
            "requiredDuringSchedulingIgnoredDuringExecution": {
                "nodeSelectorTerms": [
                    {"matchExpressions": [{"key": key, "operator": op, "values": values or []}]}
                ]
            }
        }
    }
    return spec


class TestNodeSelectorsNodeAffinityProhibition:

    def test_prohibited_key_in_node_affinity_rejected(self):
        """!rack=gpu → nodeAffinity using key 'rack' is denied."""
        spec = _affinity_spec("rack")
        result = validate_pod([_NA_ANNS], spec)
        assert result.allowed is False
        assert "rack" in result.message

    def test_different_key_in_node_affinity_allowed(self):
        """!rack=gpu → nodeAffinity using an unrelated key is allowed."""
        spec = _affinity_spec("zone")
        result = validate_pod([_NA_ANNS], spec)
        assert result.allowed is True

    def test_positive_only_constraint_does_not_block_affinity(self):
        """rack=cpu (no negation) → nodeAffinity with key 'rack' is not blocked."""
        anns = {f"{_P}nodeSelectors": "rack=cpu"}
        spec = _affinity_spec("rack")
        spec["nodeSelector"] = {"rack": "cpu"}
        result = validate_pod([anns], spec)
        assert result.allowed is True

    def test_prohibited_key_in_second_term_rejected(self):
        """Prohibited key in a later nodeSelectorTerm is caught."""
        spec = _pod(
            pod_sc={"runAsNonRoot": True},
            containers=[_container(sc={"allowPrivilegeEscalation": False})],
        )
        spec["affinity"] = {
            "nodeAffinity": {
                "requiredDuringSchedulingIgnoredDuringExecution": {
                    "nodeSelectorTerms": [
                        {"matchExpressions": [{"key": "zone", "operator": "In", "values": []}]},
                        {"matchExpressions": [{"key": "rack", "operator": "In", "values": []}]},
                    ]
                }
            }
        }
        result = validate_pod([_NA_ANNS], spec)
        assert result.allowed is False
        assert "rack" in result.message

    def test_no_affinity_block_allowed(self):
        """!rack=gpu but pod has no affinity at all → allowed (nodeSelector check applies)."""
        spec = _pod(
            pod_sc={"runAsNonRoot": True},
            containers=[_container(sc={"allowPrivilegeEscalation": False})],
        )
        result = validate_pod([_NA_ANNS], spec)
        assert result.allowed is True

    def test_mixed_negation_prohibited_key_rejected(self):
        """rack=cpu,!rack=gpu → nodeAffinity using 'rack' is still denied."""
        spec = _affinity_spec("rack")
        spec["nodeSelector"] = {"rack": "cpu"}
        result = validate_pod([_NA_ANNS_MULTI], spec)
        assert result.allowed is False
        assert "rack" in result.message


# ---------------------------------------------------------------------------
# NFS volume negation tests
# ---------------------------------------------------------------------------

_NFS_KEY = "tritonai-admission-webhook/policy.allowedNfsVolumes"
_NFS_VOL_A = {"name": "nfs-a", "nfs": {"server": "10.0.0.1", "path": "/data"}}
_NFS_VOL_B = {"name": "nfs-b", "nfs": {"server": "10.0.0.2", "path": "/scratch"}}


def _nfs_neg_spec(*vols: dict) -> dict:
    return _pod(
        pod_sc={"runAsNonRoot": True},
        containers=[_container(sc={"runAsUser": 1000, "allowPrivilegeEscalation": False})],
        volumes=list(vols),
    )


class TestNfsNegation:
    """Tests for negated patterns in allowedNfsVolumes."""

    def test_negated_pattern_blocks_matching_volume(self):
        anns = {**_ALWAYS_ANNOTATIONS, _NFS_KEY: "!10.0.0.1:/data"}
        result = validate_pod([anns], _nfs_neg_spec(_NFS_VOL_A))
        assert result.allowed is False
        assert "nfs-a" in result.message
        assert "negated" in result.message.lower()

    def test_negated_pattern_allows_non_matching_volume(self):
        anns = {**_ALWAYS_ANNOTATIONS, _NFS_KEY: "!10.0.0.1:/data"}
        result = validate_pod([anns], _nfs_neg_spec(_NFS_VOL_B))
        assert result.allowed is True

    def test_negated_glob_blocks_matching_volume(self):
        anns = {**_ALWAYS_ANNOTATIONS, _NFS_KEY: "!10.0.0.1:*"}
        result = validate_pod([anns], _nfs_neg_spec(_NFS_VOL_A))
        assert result.allowed is False

    def test_negated_glob_allows_non_matching(self):
        anns = {**_ALWAYS_ANNOTATIONS, _NFS_KEY: "!10.0.0.1:*"}
        result = validate_pod([anns], _nfs_neg_spec(_NFS_VOL_B))
        assert result.allowed is True

    def test_mixed_positive_and_negated(self):
        """Positive pattern allows 10.0.0.2:/scratch, negated blocks 10.0.0.1:/data."""
        anns = {**_ALWAYS_ANNOTATIONS, _NFS_KEY: "10.0.0.2:/scratch,!10.0.0.1:/data"}
        # VOL_B matches positive, not blocked by negation
        assert validate_pod([anns], _nfs_neg_spec(_NFS_VOL_B)).allowed is True
        # VOL_A blocked by negation
        assert validate_pod([anns], _nfs_neg_spec(_NFS_VOL_A)).allowed is False

    def test_mixed_positive_and_negated_no_positive_match(self):
        """Volume not matching positive set and not blocked by negation → rejected."""
        anns = {**_ALWAYS_ANNOTATIONS, _NFS_KEY: "10.0.0.9:/other,!10.0.0.1:/data"}
        result = validate_pod([anns], _nfs_neg_spec(_NFS_VOL_B))
        assert result.allowed is False
        assert "does not match" in result.message

    def test_multiple_negated_patterns(self):
        anns = {**_ALWAYS_ANNOTATIONS, _NFS_KEY: "!10.0.0.1:/data,!10.0.0.2:/scratch"}
        assert validate_pod([anns], _nfs_neg_spec(_NFS_VOL_A)).allowed is False
        assert validate_pod([anns], _nfs_neg_spec(_NFS_VOL_B)).allowed is False
        # A volume matching neither negation is allowed
        vol_c = {"name": "nfs-c", "nfs": {"server": "10.0.0.3", "path": "/safe"}}
        assert validate_pod([anns], _nfs_neg_spec(vol_c)).allowed is True

    def test_multiple_volumes_one_blocked_by_negation(self):
        """Two volumes; one matches negation → pod denied."""
        anns = {**_ALWAYS_ANNOTATIONS, _NFS_KEY: "10.0.0.*:*,!10.0.0.1:/data"}
        result = validate_pod([anns], _nfs_neg_spec(_NFS_VOL_A, _NFS_VOL_B))
        assert result.allowed is False
        assert "nfs-a" in result.message

    def test_no_nfs_volumes_with_negation_ok(self):
        """No NFS volumes → always ok, even with negated patterns."""
        anns = {**_ALWAYS_ANNOTATIONS, _NFS_KEY: "!10.0.0.1:/data"}
        spec = _pod(
            pod_sc={"runAsNonRoot": True},
            containers=[_container(sc={"runAsUser": 1000, "allowPrivilegeEscalation": False})],
        )
        assert validate_pod([anns], spec).allowed is True


# ---------------------------------------------------------------------------
# Toleration negation tests
# ---------------------------------------------------------------------------


class TestTolerationNegation:
    """Tests for negated entries in toleration allowlist."""

    def test_negated_toleration_blocks_matching(self):
        anns = {**_TOL_ANNOTATIONS_BASE, _TOL_KEY: "!node-type=gpu:NoSchedule"}
        tol = {"key": "node-type", "operator": "Equal", "value": "gpu", "effect": "NoSchedule"}
        result = validate_pod([anns], _tol_spec(tol))
        assert result.allowed is False
        assert "negated" in result.message.lower()

    def test_negated_toleration_allows_non_matching(self):
        anns = {**_TOL_ANNOTATIONS_BASE, _TOL_KEY: "!node-type=gpu:NoSchedule"}
        tol = {"key": "node-type", "operator": "Equal", "value": "cpu", "effect": "NoSchedule"}
        result = validate_pod([anns], _tol_spec(tol))
        assert result.allowed is True

    def test_mixed_positive_and_negated_toleration(self):
        """Positive allows node-type=cpu, negated blocks node-type=gpu."""
        anns = {
            **_TOL_ANNOTATIONS_BASE,
            _TOL_KEY: "node-type=cpu:NoSchedule,!node-type=gpu:NoSchedule",
        }
        cpu_tol = {"key": "node-type", "operator": "Equal", "value": "cpu", "effect": "NoSchedule"}
        gpu_tol = {"key": "node-type", "operator": "Equal", "value": "gpu", "effect": "NoSchedule"}
        assert validate_pod([anns], _tol_spec(cpu_tol)).allowed is True
        assert validate_pod([anns], _tol_spec(gpu_tol)).allowed is False

    def test_negated_with_wildcard_value_blocks_exists_operator(self):
        """!key=*:effect blocks Exists-operator tolerations too."""
        anns = {**_TOL_ANNOTATIONS_BASE, _TOL_KEY: "!node-type=*:NoSchedule"}
        tol = {"key": "node-type", "operator": "Exists", "effect": "NoSchedule"}
        result = validate_pod([anns], _tol_spec(tol))
        assert result.allowed is False

    def test_negated_with_glob_key(self):
        anns = {**_TOL_ANNOTATIONS_BASE, _TOL_KEY: "!gpu-*=*:*"}
        tol = {"key": "gpu-partition", "operator": "Equal", "value": "a100", "effect": "NoSchedule"}
        result = validate_pod([anns], _tol_spec(tol))
        assert result.allowed is False

    def test_negated_does_not_block_node_kubernetes_tolerations(self):
        """node.kubernetes.io/* tolerations are always exempt, even from negation."""
        anns = {**_TOL_ANNOTATIONS_BASE, _TOL_KEY: "!node.kubernetes.io/*=*:*"}
        sys_tol = {"key": "node.kubernetes.io/not-ready", "operator": "Exists", "effect": "NoExecute"}
        result = validate_pod([anns], _tol_spec(sys_tol))
        assert result.allowed is True

    def test_multiple_negated_entries(self):
        anns = {
            **_TOL_ANNOTATIONS_BASE,
            _TOL_KEY: "!node-type=gpu:NoSchedule,!node-type=tpu:NoSchedule",
        }
        gpu = {"key": "node-type", "operator": "Equal", "value": "gpu", "effect": "NoSchedule"}
        tpu = {"key": "node-type", "operator": "Equal", "value": "tpu", "effect": "NoSchedule"}
        cpu = {"key": "node-type", "operator": "Equal", "value": "cpu", "effect": "NoSchedule"}
        assert validate_pod([anns], _tol_spec(gpu)).allowed is False
        assert validate_pod([anns], _tol_spec(tpu)).allowed is False
        assert validate_pod([anns], _tol_spec(cpu)).allowed is True

    def test_no_tolerations_with_negation_ok(self):
        """No tolerations on pod → always ok, even with negated patterns."""
        anns = {**_TOL_ANNOTATIONS_BASE, _TOL_KEY: "!node-type=gpu:NoSchedule"}
        spec = _pod(
            pod_sc={"runAsNonRoot": True},
            containers=[_container(sc={"runAsUser": 1000, "allowPrivilegeEscalation": False})],
        )
        assert validate_pod([anns], spec).allowed is True

    def test_positive_no_match_negation_no_match_still_rejected(self):
        """Toleration not matching positive set and not blocked by negation → rejected."""
        anns = {
            **_TOL_ANNOTATIONS_BASE,
            _TOL_KEY: "node-type=cpu:NoSchedule,!node-type=gpu:NoSchedule",
        }
        other = {"key": "zone", "operator": "Equal", "value": "us-east", "effect": "NoSchedule"}
        result = validate_pod([anns], _tol_spec(other))
        assert result.allowed is False
        assert "not permitted" in result.message.lower()


# ---------------------------------------------------------------------------
# AND semantics across multiple policy layers
# ---------------------------------------------------------------------------

_RUN_AS_USER_KEY = "tritonai-admission-webhook/policy.runAsUser"
_NODE_SELECTORS_KEY = "tritonai-admission-webhook/policy.nodeSelectors"
_NFS_KEY = "tritonai-admission-webhook/policy.allowedNfsVolumes"
_TOL_KEY_AND = "tritonai-admission-webhook/policy.tolerations"
_PROHIBITED_KEY = "tritonai-admission-webhook/policy.prohibitedVolumeTypes"


class TestAndSemanticsAcrossLayers:
    """All policy layers must be satisfied; each annotation retains OR semantics internally."""

    # ------------------------------------------------------------------ #
    # ConstraintSet-based fields (runAsUser)
    # ------------------------------------------------------------------ #

    def test_two_layers_non_overlapping_runasuser_rejected(self):
        """Layer 1: runAsUser=1000, layer 2: runAsUser=2000 → no single value satisfies both."""
        layer1 = {_RUN_AS_USER_KEY: "1000"}
        layer2 = {_RUN_AS_USER_KEY: "2000"}
        spec = _pod(pod_sc={"runAsNonRoot": True, "runAsUser": 1000})
        result = validate_pod([layer1, layer2], spec)
        assert result.allowed is False
        assert "runAsUser" in result.message

    def test_two_layers_overlapping_runasuser_accepted(self):
        """Layer 1: runAsUser=1000-2000, layer 2: runAsUser=1500-3000 → 1500-2000 satisfies both."""
        layer1 = {_RUN_AS_USER_KEY: "1000-2000"}
        layer2 = {_RUN_AS_USER_KEY: "1500-3000"}
        spec = _pod(pod_sc={"runAsNonRoot": True, "runAsUser": 1800})
        assert validate_pod([layer1, layer2], spec).allowed is True

    def test_two_layers_value_only_in_one_range_rejected(self):
        """Value satisfies layer 1 but not layer 2 → rejected."""
        layer1 = {_RUN_AS_USER_KEY: "1000-2000"}
        layer2 = {_RUN_AS_USER_KEY: "1500-3000"}
        spec = _pod(pod_sc={"runAsNonRoot": True, "runAsUser": 1200})
        result = validate_pod([layer1, layer2], spec)
        assert result.allowed is False
        assert "runAsUser" in result.message

    def test_single_layer_list_behaves_as_before(self):
        """One-layer list preserves existing single-source semantics."""
        layer = {_RUN_AS_USER_KEY: "1000"}
        spec = _pod(pod_sc={"runAsNonRoot": True, "runAsUser": 1000})
        assert validate_pod([layer], spec).allowed is True

    def test_namespace_layer_cannot_loosen_configmap_layer(self):
        """ConfigMap restricts to 1000; namespace tries to allow 2000 → 2000 still rejected."""
        cm_layer = {_RUN_AS_USER_KEY: "1000"}
        ns_layer = {_RUN_AS_USER_KEY: "2000"}
        spec_2000 = _pod(pod_sc={"runAsNonRoot": True, "runAsUser": 2000})
        spec_1000 = _pod(pod_sc={"runAsNonRoot": True, "runAsUser": 1000})
        assert validate_pod([cm_layer, ns_layer], spec_2000).allowed is False
        assert validate_pod([cm_layer, ns_layer], spec_1000).allowed is False  # 1000 fails ns_layer

    def test_three_layers_all_must_match(self):
        """Three layers; only their intersection (2000) passes all three."""
        l1 = {_RUN_AS_USER_KEY: "1000,2000"}
        l2 = {_RUN_AS_USER_KEY: "2000,3000"}
        l3 = {_RUN_AS_USER_KEY: "1000,2000,3000"}
        spec_2000 = _pod(pod_sc={"runAsNonRoot": True, "runAsUser": 2000})
        spec_1000 = _pod(pod_sc={"runAsNonRoot": True, "runAsUser": 1000})
        assert validate_pod([l1, l2, l3], spec_2000).allowed is True
        assert validate_pod([l1, l2, l3], spec_1000).allowed is False  # fails l2

    # ------------------------------------------------------------------ #
    # NFS volumes
    # ------------------------------------------------------------------ #

    def _nfs_pod(self, server: str, path: str = "/data") -> dict:
        return _pod(
            pod_sc={"runAsNonRoot": True},
            containers=[_container(sc={"runAsUser": 1000})],
            volumes=[{"name": "nfs-vol", "nfs": {"server": server, "path": path}}],
        )

    def test_nfs_allowed_by_all_layers_accepted(self):
        """Volume allowed by both layers → accepted."""
        l1 = {_RUN_AS_USER_KEY: "1000", _NFS_KEY: "nfs1.example.com:/data"}
        l2 = {_RUN_AS_USER_KEY: "1000", _NFS_KEY: "*.example.com:/data"}
        assert validate_pod([l1, l2], self._nfs_pod("nfs1.example.com")).allowed is True

    def test_nfs_denied_by_one_layer_rejected(self):
        """Volume allowed by layer 1 but not layer 2 → rejected."""
        l1 = {_RUN_AS_USER_KEY: "1000", _NFS_KEY: "nfs1.example.com:/data"}
        l2 = {_RUN_AS_USER_KEY: "1000", _NFS_KEY: "nfs2.example.com:/data"}
        result = validate_pod([l1, l2], self._nfs_pod("nfs1.example.com"))
        assert result.allowed is False

    # ------------------------------------------------------------------ #
    # Tolerations
    # ------------------------------------------------------------------ #

    def _tol_pod(self, key: str, value: str, effect: str) -> dict:
        tol = {"key": key, "operator": "Equal", "value": value, "effect": effect}
        return _tol_spec(tol)

    def test_toleration_permitted_by_all_layers_accepted(self):
        """Toleration covered by every layer → accepted."""
        l1 = {_RUN_AS_USER_KEY: "1000", _TOL_KEY_AND: "gpu=true:NoSchedule"}
        l2 = {_RUN_AS_USER_KEY: "1000", _TOL_KEY_AND: "*=*:*"}
        assert validate_pod([l1, l2], self._tol_pod("gpu", "true", "NoSchedule")).allowed is True

    def test_toleration_denied_by_second_layer_rejected(self):
        """Toleration allowed by layer 1 but blocked (negated) in layer 2 → rejected."""
        l1 = {_RUN_AS_USER_KEY: "1000", _TOL_KEY_AND: "*=*:*"}
        l2 = {_RUN_AS_USER_KEY: "1000", _TOL_KEY_AND: "!gpu=true:NoSchedule"}
        result = validate_pod([l1, l2], self._tol_pod("gpu", "true", "NoSchedule"))
        assert result.allowed is False

    def test_layer_without_toleration_annotation_no_restriction(self):
        """A layer with no toleration annotation imposes no restriction for that layer."""
        l1 = {_RUN_AS_USER_KEY: "1000"}  # no toleration key
        l2 = {_RUN_AS_USER_KEY: "1000", _TOL_KEY_AND: "gpu=true:NoSchedule"}
        assert validate_pod([l1, l2], self._tol_pod("gpu", "true", "NoSchedule")).allowed is True

    # ------------------------------------------------------------------ #
    # prohibitedVolumeTypes
    # ------------------------------------------------------------------ #

    def _secret_vol_pod(self) -> dict:
        return _pod(
            pod_sc={"runAsNonRoot": True},
            containers=[_container(sc={"runAsUser": 1000})],
            volumes=[{"name": "s", "secret": {"secretName": "my-secret"}}],
        )

    def test_prohibited_type_in_any_layer_rejected(self):
        """Layer 2 prohibits 'secret'; the volume type is therefore rejected."""
        l1 = {_RUN_AS_USER_KEY: "1000"}                  # no prohibition
        l2 = {_RUN_AS_USER_KEY: "1000", _PROHIBITED_KEY: "secret"}
        result = validate_pod([l1, l2], self._secret_vol_pod())
        assert result.allowed is False
        assert "secret" in result.message

    def test_no_layer_prohibits_type_accepted(self):
        """Neither layer prohibits 'secret'; pod with a secret volume is accepted."""
        l1 = {_RUN_AS_USER_KEY: "1000"}
        l2 = {_RUN_AS_USER_KEY: "1000", _PROHIBITED_KEY: "emptyDir"}
        assert validate_pod([l1, l2], self._secret_vol_pod()).allowed is True
