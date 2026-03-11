"""Tests for ConfigMap-based policy lookup in namespace_client.py."""
import time
from unittest.mock import MagicMock, patch

import pytest
from kubernetes.client.exceptions import ApiException

import app.namespace_client as nc


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_cm(data: dict[str, str]) -> MagicMock:
    """Build a mock ConfigMap object with the given .data dict."""
    cm = MagicMock()
    cm.data = data
    return cm


def _make_ns(labels: dict[str, str], annotations: dict[str, str] | None = None) -> MagicMock:
    ns = MagicMock()
    ns.metadata.labels = labels
    ns.metadata.annotations = annotations or {}
    return ns


def _api_404() -> ApiException:
    exc = ApiException(status=404)
    exc.reason = "Not Found"
    return exc


def _api_500() -> ApiException:
    exc = ApiException(status=500)
    exc.reason = "Internal Server Error"
    return exc


def _reset_caches():
    """Reset module-level cache state between tests."""
    nc._index_data = None
    nc._index_expires = 0.0
    nc._policy_cache.clear()


# ---------------------------------------------------------------------------
# _get_index — fetching and caching
# ---------------------------------------------------------------------------


class TestGetIndex:
    def setup_method(self):
        _reset_caches()

    def test_fetches_index_on_first_call(self):
        api = MagicMock()
        api.read_namespaced_config_map.return_value = _make_cm({"team=gpu": "gpu-policy"})
        with patch.object(nc, "_get_core_v1_api", return_value=api):
            result = nc._get_index()
        assert result == {"team=gpu": "gpu-policy"}
        api.read_namespaced_config_map.assert_called_once()

    def test_returns_cached_value_within_ttl(self):
        api = MagicMock()
        api.read_namespaced_config_map.return_value = _make_cm({"k=v": "cm1"})
        with patch.object(nc, "_get_core_v1_api", return_value=api):
            nc._get_index()
            nc._get_index()
        # Should only have fetched once despite two calls.
        api.read_namespaced_config_map.assert_called_once()

    def test_refetches_after_ttl_expires(self):
        api = MagicMock()
        api.read_namespaced_config_map.return_value = _make_cm({"k=v": "cm1"})
        with patch.object(nc, "_get_core_v1_api", return_value=api):
            nc._get_index()
            # Force expiry.
            nc._index_expires = time.monotonic() - 1
            nc._get_index()
        assert api.read_namespaced_config_map.call_count == 2

    def test_404_treated_as_empty_index(self):
        api = MagicMock()
        api.read_namespaced_config_map.side_effect = _api_404()
        with patch.object(nc, "_get_core_v1_api", return_value=api):
            result = nc._get_index()
        assert result == {}

    def test_api_error_returns_stale_data(self):
        nc._index_data = {"team=gpu": "gpu-policy"}
        nc._index_expires = time.monotonic() - 1  # expired
        api = MagicMock()
        api.read_namespaced_config_map.side_effect = _api_500()
        with patch.object(nc, "_get_core_v1_api", return_value=api):
            result = nc._get_index()
        assert result == {"team=gpu": "gpu-policy"}

    def test_api_error_returns_empty_when_no_prior_data(self):
        api = MagicMock()
        api.read_namespaced_config_map.side_effect = _api_500()
        with patch.object(nc, "_get_core_v1_api", return_value=api):
            result = nc._get_index()
        assert result == {}

    def test_none_data_treated_as_empty(self):
        api = MagicMock()
        api.read_namespaced_config_map.return_value = _make_cm(None)
        with patch.object(nc, "_get_core_v1_api", return_value=api):
            result = nc._get_index()
        assert result == {}


# ---------------------------------------------------------------------------
# _get_policy_cm — fetching and caching
# ---------------------------------------------------------------------------


class TestGetPolicyCm:
    def setup_method(self):
        _reset_caches()

    def test_fetches_on_first_call(self):
        api = MagicMock()
        api.read_namespaced_config_map.return_value = _make_cm(
            {"tritonai-admission-webhook/policy.runAsUser": "1000"}
        )
        with patch.object(nc, "_get_core_v1_api", return_value=api):
            result = nc._get_policy_cm("gpu-policy")
        assert result == {"tritonai-admission-webhook/policy.runAsUser": "1000"}

    def test_returns_cached_value_within_ttl(self):
        api = MagicMock()
        api.read_namespaced_config_map.return_value = _make_cm({"k": "v"})
        with patch.object(nc, "_get_core_v1_api", return_value=api):
            nc._get_policy_cm("my-policy")
            nc._get_policy_cm("my-policy")
        api.read_namespaced_config_map.assert_called_once()

    def test_refetches_different_configmaps_independently(self):
        api = MagicMock()
        api.read_namespaced_config_map.return_value = _make_cm({"k": "v"})
        with patch.object(nc, "_get_core_v1_api", return_value=api):
            nc._get_policy_cm("policy-a")
            nc._get_policy_cm("policy-b")
        assert api.read_namespaced_config_map.call_count == 2

    def test_api_error_returns_stale_data(self):
        nc._policy_cache["my-policy"] = (
            {"tritonai-admission-webhook/policy.runAsUser": "999"},
            time.monotonic() - 1,  # expired
        )
        api = MagicMock()
        api.read_namespaced_config_map.side_effect = _api_500()
        with patch.object(nc, "_get_core_v1_api", return_value=api):
            result = nc._get_policy_cm("my-policy")
        assert result == {"tritonai-admission-webhook/policy.runAsUser": "999"}

    def test_api_error_returns_empty_when_no_prior_data(self):
        api = MagicMock()
        api.read_namespaced_config_map.side_effect = _api_500()
        with patch.object(nc, "_get_core_v1_api", return_value=api):
            result = nc._get_policy_cm("missing-policy")
        assert result == {}


# ---------------------------------------------------------------------------
# _resolve_configmap_policy
# ---------------------------------------------------------------------------


class TestResolveConfigmapPolicy:
    def setup_method(self):
        _reset_caches()

    def test_returns_none_when_index_empty(self):
        with patch.object(nc, "_get_index", return_value={}):
            result = nc._resolve_configmap_policy({"team": "gpu"})
        assert result is None

    def test_returns_none_when_no_label_matches(self):
        with patch.object(nc, "_get_index", return_value={"team=research": "research-policy"}):
            result = nc._resolve_configmap_policy({"team": "gpu"})
        assert result is None

    def test_single_match_returns_policy_cm_data(self):
        policy_data = {"tritonai-admission-webhook/policy.runAsUser": "1000"}
        with (
            patch.object(nc, "_get_index", return_value={"team=gpu": "gpu-policy"}),
            patch.object(nc, "_get_policy_cm", return_value=policy_data),
        ):
            result = nc._resolve_configmap_policy({"team": "gpu", "env": "prod"})
        assert result == policy_data

    def test_multiple_matches_merged_in_lexical_order(self):
        """Later label=value (lexically) should win on key conflicts."""
        index = {
            "team=research": "research-policy",
            "tier=gpu": "gpu-policy",
        }
        research_data = {
            "tritonai-admission-webhook/policy.runAsUser": "1000",
            "tritonai-admission-webhook/policy.runAsGroup": "1000",
        }
        gpu_data = {
            "tritonai-admission-webhook/policy.runAsUser": "2000",  # overrides research
            "tritonai-admission-webhook/policy.nodeLabel": "partition=gpu",
        }

        def _get_policy(name: str) -> dict:
            return {"research-policy": research_data, "gpu-policy": gpu_data}[name]

        with (
            patch.object(nc, "_get_index", return_value=index),
            patch.object(nc, "_get_policy_cm", side_effect=_get_policy),
        ):
            # "team=research" < "tier=gpu" lexically, so gpu_data applied last and wins.
            result = nc._resolve_configmap_policy({"team": "research", "tier": "gpu"})

        assert result["tritonai-admission-webhook/policy.runAsUser"] == "2000"
        assert result["tritonai-admission-webhook/policy.runAsGroup"] == "1000"
        assert result["tritonai-admission-webhook/policy.nodeLabel"] == "partition=gpu"

    def test_lexical_order_is_on_label_value_string_not_cm_name(self):
        """Merge order is determined by the label=value key, not the ConfigMap name."""
        index = {
            "zzz=last": "first-policy",   # lexically last label → applied last → wins
            "aaa=first": "second-policy",  # lexically first label → applied first → overridden
        }
        first_policy_data = {"tritonai-admission-webhook/policy.runAsUser": "999"}
        second_policy_data = {"tritonai-admission-webhook/policy.runAsUser": "1"}

        def _get_policy(name: str) -> dict:
            return {
                "first-policy": first_policy_data,
                "second-policy": second_policy_data,
            }[name]

        with (
            patch.object(nc, "_get_index", return_value=index),
            patch.object(nc, "_get_policy_cm", side_effect=_get_policy),
        ):
            result = nc._resolve_configmap_policy({"aaa": "first", "zzz": "last"})

        assert result["tritonai-admission-webhook/policy.runAsUser"] == "999"

    def test_returns_none_when_all_matching_cms_empty(self):
        with (
            patch.object(nc, "_get_index", return_value={"team=gpu": "gpu-policy"}),
            patch.object(nc, "_get_policy_cm", return_value={}),
        ):
            result = nc._resolve_configmap_policy({"team": "gpu"})
        # Empty dict returned from all matching CMs → still not None (match was found).
        assert result == {}


# ---------------------------------------------------------------------------
# get_namespace_security_annotations — integration with lookup path
# ---------------------------------------------------------------------------


class TestGetNamespaceSecurityAnnotations:
    def setup_method(self):
        _reset_caches()

    def test_uses_configmap_policy_when_index_matches(self):
        policy_data = {"tritonai-admission-webhook/policy.runAsUser": "1000"}
        ns = _make_ns(labels={"team": "gpu"}, annotations={})
        api = MagicMock()
        api.read_namespace.return_value = ns
        with (
            patch.object(nc, "_get_core_v1_api", return_value=api),
            patch.object(nc, "_resolve_configmap_policy", return_value=policy_data),
        ):
            result = nc.get_namespace_security_annotations("my-ns")
        assert result == policy_data

    def test_falls_back_to_ns_annotations_when_no_index_match(self):
        ns_annotations = {
            "tritonai-admission-webhook/policy.runAsUser": "500",
            "unrelated-annotation": "ignored",
        }
        ns = _make_ns(labels={"team": "unknown"}, annotations=ns_annotations)
        api = MagicMock()
        api.read_namespace.return_value = ns
        with (
            patch.object(nc, "_get_core_v1_api", return_value=api),
            patch.object(nc, "_resolve_configmap_policy", return_value=None),
        ):
            result = nc.get_namespace_security_annotations("my-ns")
        assert result == {"tritonai-admission-webhook/policy.runAsUser": "500"}
        assert "unrelated-annotation" not in result

    def test_returns_empty_on_namespace_fetch_error(self):
        api = MagicMock()
        api.read_namespace.side_effect = _api_500()
        with patch.object(nc, "_get_core_v1_api", return_value=api):
            result = nc.get_namespace_security_annotations("bad-ns")
        assert result == {}

    def test_labels_passed_to_resolve(self):
        ns = _make_ns(labels={"env": "prod", "team": "research"})
        api = MagicMock()
        api.read_namespace.return_value = ns
        with (
            patch.object(nc, "_get_core_v1_api", return_value=api),
            patch.object(nc, "_resolve_configmap_policy", return_value=None) as mock_resolve,
        ):
            nc.get_namespace_security_annotations("my-ns")
        mock_resolve.assert_called_once_with({"env": "prod", "team": "research"})

    def test_ns_annotations_override_configmap_on_conflict(self):
        """Namespace annotations with the right prefix override ConfigMap values."""
        cm_policy = {
            "tritonai-admission-webhook/policy.runAsUser": "1000",
            "tritonai-admission-webhook/policy.runAsGroup": "2000",
        }
        ns_annotations = {
            "tritonai-admission-webhook/policy.runAsUser": "9999",  # overrides CM
            "unrelated/annotation": "ignored",
        }
        ns = _make_ns(labels={"team": "gpu"}, annotations=ns_annotations)
        api = MagicMock()
        api.read_namespace.return_value = ns
        with (
            patch.object(nc, "_get_core_v1_api", return_value=api),
            patch.object(nc, "_resolve_configmap_policy", return_value=cm_policy),
        ):
            result = nc.get_namespace_security_annotations("my-ns")
        assert result["tritonai-admission-webhook/policy.runAsUser"] == "9999"
        assert result["tritonai-admission-webhook/policy.runAsGroup"] == "2000"
        assert "unrelated/annotation" not in result

    def test_ns_annotations_extend_configmap(self):
        """Namespace annotations not present in the ConfigMap are added to the result."""
        cm_policy = {"tritonai-admission-webhook/policy.runAsUser": "1000"}
        ns_annotations = {"tritonai-admission-webhook/policy.nodeLabel": "partition=gpu"}
        ns = _make_ns(labels={"team": "gpu"}, annotations=ns_annotations)
        api = MagicMock()
        api.read_namespace.return_value = ns
        with (
            patch.object(nc, "_get_core_v1_api", return_value=api),
            patch.object(nc, "_resolve_configmap_policy", return_value=cm_policy),
        ):
            result = nc.get_namespace_security_annotations("my-ns")
        assert result == {
            "tritonai-admission-webhook/policy.runAsUser": "1000",
            "tritonai-admission-webhook/policy.nodeLabel": "partition=gpu",
        }

    def test_non_prefixed_ns_annotations_excluded_in_configmap_path(self):
        """Annotations without ANNOTATION_NS prefix are excluded even on the CM path."""
        cm_policy = {"tritonai-admission-webhook/policy.runAsUser": "1000"}
        ns_annotations = {
            "other-tool/some-annotation": "value",
            "bare-annotation": "value",
        }
        ns = _make_ns(labels={"team": "gpu"}, annotations=ns_annotations)
        api = MagicMock()
        api.read_namespace.return_value = ns
        with (
            patch.object(nc, "_get_core_v1_api", return_value=api),
            patch.object(nc, "_resolve_configmap_policy", return_value=cm_policy),
        ):
            result = nc.get_namespace_security_annotations("my-ns")
        assert result == {"tritonai-admission-webhook/policy.runAsUser": "1000"}


# ---------------------------------------------------------------------------
# _normalise_cm_key
# ---------------------------------------------------------------------------


class TestNormaliseCmKey:
    """Unit tests for the ConfigMap key normalisation helper."""

    NS = "tritonai-admission-webhook/"

    def test_full_key_unchanged(self):
        key = "tritonai-admission-webhook/policy.runAsUser"
        assert nc._normalise_cm_key(key) == key

    def test_bare_policy_key_prefixed(self):
        assert nc._normalise_cm_key("policy.runAsUser") == (
            "tritonai-admission-webhook/policy.runAsUser"
        )

    def test_bare_default_key_prefixed(self):
        assert nc._normalise_cm_key("default.runAsUser") == (
            "tritonai-admission-webhook/default.runAsUser"
        )

    def test_arbitrary_prefix_replaced(self):
        assert nc._normalise_cm_key("other-ns/policy.runAsUser") == (
            "tritonai-admission-webhook/policy.runAsUser"
        )

    def test_get_policy_cm_normalises_keys(self):
        """_get_policy_cm should normalise all key forms to canonical keys."""
        _reset_caches()
        raw_data = {
            "policy.runAsUser": "1000",                              # bare
            "other/policy.runAsGroup": "2000",                      # arbitrary prefix
            "tritonai-admission-webhook/default.runAsUser": "500",  # already canonical
        }
        api = MagicMock()
        api.read_namespaced_config_map.return_value = _make_cm(raw_data)
        with patch.object(nc, "_get_core_v1_api", return_value=api):
            result = nc._get_policy_cm("test-policy")
        assert result == {
            "tritonai-admission-webhook/policy.runAsUser": "1000",
            "tritonai-admission-webhook/policy.runAsGroup": "2000",
            "tritonai-admission-webhook/default.runAsUser": "500",
        }

    def test_collision_last_value_wins(self):
        """When two raw keys normalise to the same canonical key, the last one wins."""
        _reset_caches()
        # dict preserves insertion order in Python 3.7+
        raw_data = {
            "policy.runAsUser": "first",
            "other/policy.runAsUser": "last",
        }
        api = MagicMock()
        api.read_namespaced_config_map.return_value = _make_cm(raw_data)
        with patch.object(nc, "_get_core_v1_api", return_value=api):
            result = nc._get_policy_cm("test-policy")
        assert result == {"tritonai-admission-webhook/policy.runAsUser": "last"}
