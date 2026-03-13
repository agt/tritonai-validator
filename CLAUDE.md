# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Install dependencies
pip install -r requirements.txt

# Run all tests
pytest tests/ -v

# Run a single test file
pytest tests/test_validator.py -v

# Run a single test by name
pytest tests/test_validator.py::TestRunAsNonRoot::test_pod_true_covers_containers -v

# Start the server (HTTP, for local testing)
uvicorn app.main:app --host 0.0.0.0 --port 8080

# Start with TLS (required for real webhook use)
uvicorn app.main:app --host 0.0.0.0 --port 8443 --ssl-keyfile tls.key --ssl-certfile tls.crt
```

There is no build step — this is a pure Python project.

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `ANNOTATION_PREFIX` | `tritonai-admission-webhook` | Prefix for namespace annotations; derived constants in `app/config.py` |
| `LOG_LEVEL` | `INFO` | Controls logging level (stdlib + uvicorn) |
| `PORT` | `8443` | Server port when using `python -m app.main` dev entrypoint |
| `TLS_KEY_FILE` | — | Path to TLS private key (passed to uvicorn) |
| `TLS_CERT_FILE` | — | Path to TLS certificate (passed to uvicorn) |

## Architecture

Two FastAPI endpoints in `app/main.py`:
- `POST /mutate` — MutatingAdmissionWebhook; only patches `kind=Pod`, passes all other kinds through unmodified.
- `POST /validate` — ValidatingAdmissionWebhook; handles Pod directly and also workload kinds (Deployment, ReplicaSet, StatefulSet, DaemonSet, Job, CronJob) by extracting their pod template spec.

For workload validation, the validator internally calls `mutate_pod_spec()` to pre-apply defaults before checking constraints, so the validator sees the same post-mutation spec the API server would produce.

### Data flow

```
API Server → /mutate → fetch ns annotations → mutate_pod() → JSON Patch response
API Server → /validate → fetch ns annotations → [workloads: mutate_pod_spec()] → validate_pod() → allow/deny
```

Namespace security annotations are fetched from the Kubernetes API via `app/namespace_client.py` (`get_namespace_security_annotations()`), which returns only annotations with the `ANNOTATION_PREFIX/` prefix (default: `tritonai-admission-webhook/`). The K8s client is synchronous but wrapped in `asyncio.to_thread()` so it does not block the event loop. Auth tries in-cluster config first, then falls back to kubeconfig. Errors return an empty dict so the webhook continues (validator will deny rather than 500).

### Shared helpers (`app/pod_helpers.py`)

Reusable functions shared by mutator and validator: `_pod_sc()`, `_all_containers()`, `_container_sc()`, `_container_name()`, `_is_node_kubernetes_toleration()`. When adding code that reads pod/container securityContext fields, use these helpers rather than inlining `pod.get("securityContext") or {}`.

### Constraint system (`app/constraints/`)

Extensible constraint abstraction:
- `base.py`: `Constraint` (single token, `matches(value) -> bool`), `NegatedConstraint` (inverts a constraint's match), `ConstraintSet` (positive tokens OR-ed, negated tokens AND-ed), `ConstraintParser` (parses annotation string → `ConstraintSet`).
- `numeric.py`: Handles `1000`, `2000-3000`, `>5000000`, `<500`, `>=1000`, `<=1000`. All support `!` prefix.
- `boolean.py`: Handles `true`/`false`/`!true`/`!false`.
- `nodelabel.py`: Handles `key=value` and `!key=value` pairs.
- `registry.py`: `CONSTRAINT_REGISTRY` dict mapping annotation keys to parser instances.

**Negation (`!` prefix)**: Any constraint token can be prefixed with `!`. Within a `ConstraintSet`, positive constraints use OR semantics (at least one must match) and negated constraints use AND semantics (all must be satisfied). When both are present, both conditions must hold. Example: `"1000,2000,!3000"` → `(value == 1000 OR value == 2000) AND value != 3000`.

To add a new ConstraintSet-based annotation: implement a `ConstraintParser`, register it in `registry.py`, and add a `FieldSpec` in `app/validator.py`'s `_FIELD_SPECS`. When implementing the parser's token handler, check for a leading `!`, strip it, parse the remainder normally, and wrap in `NegatedConstraint(inner)` if negated.

For non-ConstraintSet constraints (NFS volumes, tolerations), negation is handled directly in the validation functions: split tokens into positive and negated lists, check negated patterns first (none may match), then check positive patterns (at least one must match if any exist).

### Validator (`app/validator.py`)

`validate_pod(ns_annotations, pod_spec) -> ValidationResult`

Two layers of checks:

1. **Annotation-driven constraints** (`_FIELD_SPECS` dict): maps annotation suffix → `FieldSpec(behavior, sc_field)`. `FieldBehavior` enum:
   - `REQUIRED_SCALAR`: pod-level value covers all containers; if absent at pod level, every container/initContainer/ephemeralContainer must individually set it.
   - `OPTIONAL_SCALAR`: only pod-level checked; absent = satisfied.
   - `OPTIONAL_LIST`: only pod-level checked; absent/empty = satisfied.
   - `NODE_SELECTOR`: `nodeLabel` annotation — enforces `nodeName` absent, `nodeSelector` matches one of the `key=value` tokens.

2. **Hardcoded constraints** (always enforced, not configurable):
   - Pod: `hostNetwork`/`hostPID`/`hostIPC` absent or false; `securityContext.sysctls` absent or empty; `securityContext.runAsUser` must not be 0 (root); `securityContext.runAsNonRoot` true (REQUIRED_SCALAR semantics); volume types restricted to allowed set; NFS volumes checked against `allowedNfsVolumes` annotation; `prohibitedVolumeTypes` annotation narrows the allowed set and also blocks env/envFrom sources.
   - Containers/initContainers/ephemeralContainers: `securityContext.runAsUser` must not be 0 (root); `allowPrivilegeEscalation` absent or false; `privileged` absent or false; `capabilities.add` absent/empty or `["NET_BIND_SERVICE"]` only; `procMount` absent/`""`/`"Default"`.

3. **Toleration allowlist** (`<POLICY_PREFIX>tolerations`): annotation-driven, handled outside `_FIELD_SPECS` like NFS volumes. Each pod toleration must match at least one positive `key=value:effect` entry (fnmatch globs supported in any field; `*` value also matches `Exists` operator) and must not match any negated (`!key=value:effect`) entry. Annotation absent = no restriction. `node.kubernetes.io/*` tolerations are always exempt from both positive and negated checks.

   **NFS volumes** (`<POLICY_PREFIX>allowedNfsVolumes`): supports `!pattern` negation — none of the pod's NFS volumes may match a negated `server:/path` glob.

### Mutator (`app/mutator.py`)

`mutate_pod(ns_annotations, pod_spec) -> list[RFC6902 patches]`
`mutate_pod_spec(ns_annotations, pod_spec) -> mutated_spec_dict`

Only injects missing values; never overwrites existing ones (the validator rejects wrong values):
- **REQUIRED_SCALAR** fields (`runAsUser`, `runAsGroup`): injects default into pod-level `securityContext` when any container is missing the field.
- **OPTIONAL_SCALAR/OPTIONAL_LIST** fields: no mutation (absent is always valid).
- **NODE_SELECTOR**: always removes `nodeName`; injects default `nodeSelector` only when none is present.
- **runAsNonRoot** (unconditional): always sets `securityContext.runAsNonRoot = True` when absent.
- **tolerations** (`<DEFAULT_PREFIX>tolerations`): injects a list of `key=value:effect` tolerations into `spec.tolerations` only when that field is absent or empty. Value `*` produces `operator: Exists`; any other value produces `operator: Equal`.

Default values come from `<DEFAULT_PREFIX><field>` namespace annotations. Missing or unparseable defaults are logged as warnings; other fields continue to be processed.

### Pydantic models (`app/models.py`)

All models use `extra="allow"` to tolerate extra fields from the K8s API server. `AdmissionReviewResponse.model_dump_json()` defaults to `exclude_none=True`.

### Key annotation prefix

The annotation prefix is configured via the `ANNOTATION_PREFIX` env var (default: `tritonai-admission-webhook`). Three derived constants in `app/config.py`:
- `ANNOTATION_NS = f"{ANNOTATION_PREFIX}/"` — used to filter namespace annotations
- `POLICY_PREFIX = f"{ANNOTATION_NS}policy."` — constraint annotations (e.g. `tritonai-admission-webhook/policy.runAsUser`)
- `DEFAULT_PREFIX = f"{ANNOTATION_NS}default."` — mutator default annotations (e.g. `tritonai-admission-webhook/default.runAsUser`)

## Deployment

- **Docker**: Python 3.11-slim, runs as non-root (uid 1000), expects TLS at `/tls/tls.key` and `/tls/tls.crt`.
- **Helm**: `helm install pod-security-webhook ./deploy/helm -n <namespace> --create-namespace`. Key values: `annotationPrefix`, `replicaCount` (default 2), `logLevel`.
- **CI**: GitHub Actions (`.github/workflows/build-push-container-on-tag.yml`) builds on tag push, pushes to `ghcr.io`.

## Testing conventions

Tests live in `tests/`. Helper factories `_pod()` and `_container()` build minimal pod specs. Tests are grouped by feature into `Test*` classes (e.g. `TestRunAsNonRoot`, `TestValidateTolerations`).

## Known technical debt

- **Toleration parsing duplication**: `_parse_default_tolerations()` (mutator) and `_parse_permitted_tolerations()` (validator) share near-identical parsing logic with different return types. Could be unified into a shared parser returning raw `(key, value, effect)` tuples.
- **Underscore-prefixed cross-module helpers**: Functions in `pod_helpers.py` use `_` prefix (convention: module-private) but are imported across modules. Same for `_FIELD_SPECS` in validator.py imported by mutator.py. Consider dropping the prefix or moving `_FIELD_SPECS`/`FieldBehavior` to a shared module.
- **`FieldSpec.display_name` redundancy**: Always matches its dict key in `_FIELD_SPECS`; could be derived at point of use.
