# TritonAI Pod Security Admission Webhook

A FastAPI-based Kubernetes admission webhook with two components:

- **Mutating webhook** (`/mutate`) — fills in missing security-context defaults before a pod is admitted.
- **Validating webhook** (`/validate`) — rejects pods whose security context violates namespace policy.

---

## How It Works

### Mutating webhook (`/mutate`)

Called first by the API server.  For each active constraint annotation on the pod's namespace:

1. Looks up the corresponding `sc.dsmlp.ucsd.edu/default.<field>` annotation.
2. For **REQUIRED_SCALAR** fields (`runAsUser`, `runAsGroup`, `allowPrivilegeEscalation`):
   injects a pod-level `securityContext` default for any container that does not already
   set the field.  Fields that are already set are **not modified**.
3. For **OPTIONAL_SCALAR** (`fsGroup`) and **OPTIONAL_LIST** (`supplementalGroups`) fields:
   no mutation is applied — absent is always acceptable; wrong values are left for the
   validator to reject.
4. For **NODE_SELECTOR** (`nodeLabel`): removes `spec.nodeName` unconditionally, and
   injects the default `key=value` label as a new `spec.nodeSelector` only when the
   pod specifies no `nodeSelector` at all.  Any existing `nodeSelector` is left untouched.

### Validating webhook (`/validate`)

Called after mutation.  The webhook:

1. Fetches `sc.dsmlp.ucsd.edu/*` annotations from the Pod's **namespace**.
2. If **no** annotations are present → **reject** (policy must be explicit).
3. Parses each annotation into a constraint set and validates the Pod spec.
4. Applies **hardcoded security constraints** that are always enforced, regardless of annotations.
5. If **any** constraint fails → **reject** with a descriptive message listing all failures.

---

## Namespace Annotations

Set security policy on a namespace by adding annotations prefixed `sc.dsmlp.ucsd.edu/`.
Pair each constraint annotation with a `sc.dsmlp.ucsd.edu/default.<field>` annotation to
enable the mutating webhook to fill in missing values automatically.

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: my-app
  annotations:
    # Constraint annotations (enforced by the validator)
    sc.dsmlp.ucsd.edu/runAsUser: "1000,2000-3000,>5000000"
    sc.dsmlp.ucsd.edu/runAsGroup: "1000"
    sc.dsmlp.ucsd.edu/fsGroup: "1000"
    sc.dsmlp.ucsd.edu/supplementalGroups: "1000,2000-3000"
    sc.dsmlp.ucsd.edu/nodeLabel: "partition=gpu,partition=cpu"
    # Default annotations (used by the mutator to fill in absent fields)
    sc.dsmlp.ucsd.edu/default.runAsUser: "1000"
    sc.dsmlp.ucsd.edu/default.runAsGroup: "1000"
    sc.dsmlp.ucsd.edu/default.nodeLabel: "partition=gpu"
    # NFS volume allowlist (see below)
    sc.dsmlp.ucsd.edu/allowedNfsVolumes: "10.20.5.3:/export/data,itsnfs:/scratch,its-dsmlp-fs0[1-9]:/export/workspaces/*"
    # Optionally remove types from the hardcoded permitted volume type set (see below)
    sc.dsmlp.ucsd.edu/prohibitedVolumeTypes: "emptyDir,secret"
```

Default annotations are only consulted by the mutator and must satisfy the corresponding
constraint.  If a default annotation is absent or unparseable, the mutator logs a warning
and skips that field; the validator still enforces the constraint.

### Constraint Value Syntax

#### Numeric and boolean annotations

Comma-separated tokens, matched with **OR** semantics (any one token matching is sufficient):

| Token format | Example        | Meaning               |
|-------------|----------------|-----------------------|
| Exact        | `1000`         | value == 1000         |
| Closed range | `2000-3000`    | 2000 ≤ value ≤ 3000   |
| Greater than | `>5000000`     | value > 5,000,000     |
| Less than    | `<500`         | value < 500           |
| ≥            | `>=1000`       | value ≥ 1000          |
| ≤            | `<=1000`       | value ≤ 1000          |
| Boolean      | `true`/`false` | exact boolean match   |

#### `sc.dsmlp.ucsd.edu/nodeLabel`

Comma-separated `key=value` pairs, matched with **OR** semantics:

| Token format | Example         | Meaning                                   |
|-------------|-----------------|-------------------------------------------|
| Key=value   | `partition=gpu` | nodeSelector must contain `partition: gpu` |

Multiple tokens mean the pod may land on a node matching **any** of them:

```
sc.dsmlp.ucsd.edu/nodeLabel: "rack=b,rack=c"
```

---

## Validation Behavior per Annotation

### `sc.dsmlp.ucsd.edu/runAsUser`, `sc.dsmlp.ucsd.edu/runAsGroup`

**Required field** — enforcement is strict:

- If the **Pod-level** `securityContext` sets the field → it must match.
- All **container/initContainer** `securityContext`s that set the field → must match.
- If the Pod-level `securityContext` is **absent** (or does not set the field), **every**
  container and initContainer must supply the field and it must match.

> **Note:** `allowPrivilegeEscalation` is enforced as a [hardcoded constraint](#hardcoded-security-constraints) (always `false`) rather than a configurable namespace annotation.

### `sc.dsmlp.ucsd.edu/fsGroup`

**Optional field** — only pod-level:

- Absent from pod `securityContext` → constraint satisfied (no requirement to set it).
- Present → must match the annotation constraint.

### `sc.dsmlp.ucsd.edu/supplementalGroups`

**Optional list** — only pod-level:

- Absent or empty → constraint satisfied.
- Present → **every element** must satisfy at least one constraint token.

### `sc.dsmlp.ucsd.edu/nodeLabel`

**Node placement** — two rules are enforced simultaneously:

- `pod.spec.nodeName` must be **absent**.  Setting `nodeName` bypasses the scheduler and
  the `nodeSelector` check entirely, so it is never permitted when this annotation is present.
- `pod.spec.nodeSelector` must contain at least one entry matching **any** of the
  annotation's `key=value` tokens.  Additional `nodeSelector` entries beyond the matched
  one are permitted.

Example — namespace annotation `"rack=b,rack=c"` would:

| Pod nodeSelector              | Result  | Reason                             |
|-------------------------------|---------|------------------------------------|
| `{rack: b}`                   | Allowed | matches `rack=b`                   |
| `{rack: c, zone: us-west-2}`  | Allowed | matches `rack=c`; extra key is OK  |
| `{rack: a}`                   | Rejected | no token matches                  |
| `{}` or absent                | Rejected | no token matches                  |
| any spec with `nodeName` set  | Rejected | `nodeName` bypass is forbidden     |

### `sc.dsmlp.ucsd.edu/allowedNfsVolumes`

**NFS volume allowlist** — controls which NFS mounts a pod may use:

- If the annotation is **absent or empty**, no NFS volumes are permitted.
- If NFS volumes are present, **each** must match at least one entry in the comma-separated
  allowlist.
- A match is either an exact `server:/path` string or a **shell glob** (fnmatch) pattern,
  e.g. `its-dsmlp-fs0[1-9]:/export/workspaces/*FA25`.

```
sc.dsmlp.ucsd.edu/allowedNfsVolumes: "10.20.5.3:/export/data,itsnfs:/scratch,its-dsmlp-fs0[1-9]:/export/workspaces/*"
```

A pod with no NFS volumes is always accepted regardless of this annotation.

### `sc.dsmlp.ucsd.edu/prohibitedVolumeTypes`

**Volume type restriction** — removes one or more types from the hardcoded permitted set:

- Value is a comma-separated list of volume type names (e.g. `"emptyDir,secret"`).
- Each named type is removed from the base permitted set for pods in this namespace.
- A missing or empty annotation means no additional restrictions.
- Type names not present in the base permitted set are ignored (logged as a warning).

```
sc.dsmlp.ucsd.edu/prohibitedVolumeTypes: "emptyDir,hostPath"
```

---

## Hardcoded Security Constraints

The following constraints are **always enforced** on every pod that passes through the
webhook.  They are not configurable via namespace annotations.

### Pod-level

| Field | Allowed values |
|---|---|
| `securityContext.sysctls` | absent or `[]` |
| `volumes[*]` type | `configMap`, `downwardAPI`, `emptyDir`, `image`, `nfs`, `persistentVolumeClaim`, `projected`, `secret`, `serviceAccountToken`, `clusterTrustBundle`, `podCertificate` (base set; further restricted by `sc.dsmlp.ucsd.edu/prohibitedVolumeTypes`) |

### Container-level (applies to `containers`, `initContainers`, and `ephemeralContainers`)

| Field | Allowed values |
|---|---|
| `securityContext.allowPrivilegeEscalation` | absent or `false` |
| `securityContext.privileged` | absent or `false` |
| `securityContext.capabilities.add` | absent, empty, or `["NET_BIND_SERVICE"]` only |
| `securityContext.procMount` | absent, `""`, or `"Default"` |

Any violation is reported as a validation error and the pod is rejected.

---

## Running Locally

```bash
# Install dependencies
pip install -r requirements.txt

# Run tests
pytest tests/ -v

# Start the server (HTTP, for local testing only)
uvicorn app.main:app --host 0.0.0.0 --port 8080

# Start with TLS (required for use as a real webhook)
uvicorn app.main:app \
  --host 0.0.0.0 --port 8443 \
  --ssl-keyfile tls.key --ssl-certfile tls.crt
```

---

## Deploying to Kubernetes

### 1. Build and push the image

```bash
docker build -t your-registry/pod-security-webhook:latest .
docker push your-registry/pod-security-webhook:latest
```

### 2. Generate TLS credentials

The webhook must be served over HTTPS.  The simplest production approach is
[cert-manager](https://cert-manager.io/):

```bash
# Or generate a self-signed cert for testing:
openssl req -x509 -newkey rsa:4096 -keyout tls.key -out tls.crt -days 365 \
  -subj "/CN=pod-security-webhook.tritonai-system.svc" \
  -addext "subjectAltName=DNS:pod-security-webhook.tritonai-system.svc,DNS:pod-security-webhook.tritonai-system.svc.cluster.local" \
  -nodes
```

### 3. Populate the manifests

```bash
# Encode the cert/key for the Secret
TLS_CRT=$(base64 -w0 tls.crt)
TLS_KEY=$(base64 -w0 tls.key)
CA_BUNDLE=$(base64 -w0 tls.crt)   # self-signed: CA == leaf cert

# Substitute placeholders
sed -i "s|<BASE64_ENCODED_TLS_CRT>|$TLS_CRT|g; \
        s|<BASE64_ENCODED_TLS_KEY>|$TLS_KEY|g; \
        s|<BASE64_ENCODED_CA_CRT>|$CA_BUNDLE|g" deploy/webhook.yaml
```

### 4. Apply

```bash
kubectl apply -f deploy/rbac.yaml
kubectl apply -f deploy/webhook.yaml
```

---

## Extending with New Constraints

1. **New numeric operator** (e.g. `!=`) — add a `Constraint` subclass in
   `app/constraints/numeric.py` and handle the token pattern in `_parse_numeric_token`.

2. **New string constraint type** (e.g. glob matching) — create
   `app/constraints/glob.py` with a `GlobConstraintParser` and register it.

3. **New ConstraintSet-based annotation key** — add entries to both:
   - `app/constraints/registry.py` → `CONSTRAINT_REGISTRY`
   - `app/validator.py` → `_FIELD_SPECS`

4. **New annotation-driven constraint that doesn't fit the ConstraintSet model** (e.g. glob
   patterns, structured values) — implement a dedicated validation function in `app/validator.py`
   and call it from `validate_pod()`, following the pattern of `_validate_nfs_volumes()`.

---

## Environment Variables

| Variable        | Default | Description                         |
|----------------|---------|-------------------------------------|
| `LOG_LEVEL`    | `INFO`  | Python logging level                |
| `PORT`         | `8443`  | Listening port (dev entrypoint only)|
| `TLS_KEY_FILE` | —       | Path to TLS private key             |
| `TLS_CERT_FILE`| —       | Path to TLS certificate             |
