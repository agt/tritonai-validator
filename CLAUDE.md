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

Namespace security annotations are fetched from the Kubernetes API via `app/namespace_client.py` (`get_namespace_security_annotations()`), which returns only annotations with the `sc.dsmlp.ucsd.edu/` prefix.

### Constraint system (`app/constraints/`)

Extensible constraint abstraction:
- `base.py`: `Constraint` (single token, `matches(value) -> bool`), `ConstraintSet` (OR-semantics over tokens), `ConstraintParser` (parses annotation string → `ConstraintSet`).
- `numeric.py`: Handles `1000`, `2000-3000`, `>5000000`, `<500`, `>=1000`, `<=1000`.
- `boolean.py`: Handles `true`/`false`.
- `nodelabel.py`: Handles `key=value` pairs.
- `registry.py`: `CONSTRAINT_REGISTRY` dict mapping annotation keys to parser instances.

To add a new ConstraintSet-based annotation: implement a `ConstraintParser`, register it in `registry.py`, and add a `FieldSpec` in `app/validator.py`'s `_FIELD_SPECS`.

### Validator (`app/validator.py`)

`validate_pod(ns_annotations, pod_spec) -> ValidationResult`

Two layers of checks:

1. **Annotation-driven constraints** (`_FIELD_SPECS` dict): maps annotation suffix → `FieldSpec(behavior, sc_field)`. `FieldBehavior` enum:
   - `REQUIRED_SCALAR`: pod-level value covers all containers; if absent at pod level, every container/initContainer/ephemeralContainer must individually set it.
   - `OPTIONAL_SCALAR`: only pod-level checked; absent = satisfied.
   - `OPTIONAL_LIST`: only pod-level checked; absent/empty = satisfied.
   - `NODE_SELECTOR`: `nodeLabel` annotation — enforces `nodeName` absent, `nodeSelector` matches one of the `key=value` tokens.

2. **Hardcoded constraints** (always enforced, not configurable):
   - Pod: `hostNetwork`/`hostPID`/`hostIPC` absent or false; `securityContext.sysctls` absent or empty; `securityContext.runAsNonRoot` true (REQUIRED_SCALAR semantics); volume types restricted to allowed set; NFS volumes checked against `allowedNfsVolumes` annotation; `prohibitedVolumeTypes` annotation narrows the allowed set and also blocks env/envFrom sources.
   - Containers/initContainers/ephemeralContainers: `allowPrivilegeEscalation` absent or false; `privileged` absent or false; `capabilities.add` absent/empty or `["NET_BIND_SERVICE"]` only; `procMount` absent/`""`/`"Default"`.

3. **Toleration allowlist** (`sc.dsmlp.ucsd.edu/tolerations`): annotation-driven, handled outside `_FIELD_SPECS` like NFS volumes. Each pod toleration must match at least one `key=value:effect` entry (fnmatch globs supported in any field; `*` value also matches `Exists` operator). Annotation absent = no restriction.

### Mutator (`app/mutator.py`)

`mutate_pod(ns_annotations, pod_spec) -> list[RFC6902 patches]`
`mutate_pod_spec(ns_annotations, pod_spec) -> mutated_spec_dict`

Only injects missing values; never overwrites existing ones (the validator rejects wrong values):
- **REQUIRED_SCALAR** fields (`runAsUser`, `runAsGroup`): injects default into pod-level `securityContext` when any container is missing the field.
- **OPTIONAL_SCALAR/OPTIONAL_LIST** fields: no mutation (absent is always valid).
- **NODE_SELECTOR**: always removes `nodeName`; injects default `nodeSelector` only when none is present.
- **runAsNonRoot** (unconditional): always sets `securityContext.runAsNonRoot = True` when absent.
- **tolerations** (`sc.dsmlp.ucsd.edu/default.tolerations`): injects a list of `key=value:effect` tolerations into `spec.tolerations` only when that field is absent or empty. Value `*` produces `operator: Exists`; any other value produces `operator: Equal`.

Default values come from `sc.dsmlp.ucsd.edu/default.<field>` namespace annotations. Missing or unparseable defaults are logged as warnings; other fields continue to be processed.

### Key annotation prefix

All annotations use the `sc.dsmlp.ucsd.edu/` prefix. Constraint annotations are the bare suffix (e.g. `sc.dsmlp.ucsd.edu/runAsUser`); default annotations used by the mutator append `default.` (e.g. `sc.dsmlp.ucsd.edu/default.runAsUser`).
