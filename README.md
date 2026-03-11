
# TritonAI Pod Security Admission Webhook

A FastAPI-based Kubernetes Pod admission webhook which offers fine-grained control over workloads' security configuration while minimizing modifications to published YAML or Helm files and no dependencies on external systems: defaults and constraints are established through namespace Annotations.

- **Mutating webhook** (`/mutate`) — called first by the API server to inject optional defaults for fields later inspected by the Validator.

- **Validating webhook** (`/validate`) — rejects pods which violate either namespace-specific policies or a list of hardcoded rules aligned to [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/).  For workload resources (Deployment, ReplicaSet, StatefulSet, DaemonSet, Job, and CronJob objects), namespace defaults are applied to the pod template spec via the mutator before validation so the validator sees the same (post-mutation) spec the API server would ultimately use.  The intent is to reject nonconforming workloads as early as possbile.

Beyond controlling Pod `securityContext` fields (`runAsUser`, etc.), defaults/constraints on `nodeSelectors` and `tolerations` enable Pods to be directed to specific node groups or excluded from them, and data security is enhanced through restrictions on permitted Volume types and allowable NFS servers/paths.

These protections provide enhanced isolation for TritonAI/TritonGPT workloads executing within a mixed-tenant cluster.

### Example Namespace Annotations:
```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: my-app
  annotations:
    # Constraint annotations (enforced by the validator)
    tritonai-admission-webhook/policy.runAsUser: "1000,2000-3000,>5000000"
    tritonai-admission-webhook/policy.runAsGroup: "1000"
    tritonai-admission-webhook/policy.fsGroup: "1000"
    tritonai-admission-webhook/policy.supplementalGroups: "1000,2000-3000"
    tritonai-admission-webhook/policy.nodeLabel: "partition=gpu,partition=cpu"
    tritonai-admission-webhook/policy.tolerations: "node-type=its-ai*:NoSchedule,glean-node=*:NoExecute"
    tritonai-admission-webhook/policy.allowedNfsVolumes: "10.20.5.3:/export/data,itsnfs:/scratch,its-dsmlp-fs0[1-9]:/export/workspaces/*"
    tritonai-admission-webhook/policy.prohibitedVolumeTypes: "emptyDir,secret"
    # Default annotations (used by the mutator to fill in absent fields)
    tritonai-admission-webhook/default.runAsUser: "1000"
    tritonai-admission-webhook/default.runAsGroup: "1000"
    tritonai-admission-webhook/default.nodeLabel: "partition=gpu"
    tritonai-admission-webhook/default.tolerations: "node-type=its-ai:NoSchedule"
```

---

## Hardcoded Security Constraints

The following constraints are **always enforced** on every pod that passes through the
Validation webhook.  They are not configurable via namespace annotations.

The Mutation webhook will also preemptively set `securityContext.runAsNonRoot: true` for each Pod missing that attribute.  (A pod explicitly configured with `securityContext.runAsNonRoot: false` will pass through to the Validator where it will be rejected.)

### Pod-level

| Field | Allowed values | Semantics |
|---|---|---|
| `hostNetwork` | absent or `false` | hardcoded |
| `hostPID` | absent or `false` | hardcoded |
| `hostIPC` | absent or `false` | hardcoded |
| `securityContext.runAsNonRoot` | `true` | hardcoded |
| `securityContext.sysctls` | absent or `[]` | hardcoded |
| `volumes[*]` type | `configMap`, `downwardAPI`, `emptyDir`, `image`, `nfs`, `persistentVolumeClaim`, `projected`, `secret`, `serviceAccountToken`, `clusterTrustBundle`, `podCertificate` (base set; further restricted by `tritonai-admission-webhook/policy.prohibitedVolumeTypes`) | hardcoded |

### Container-level (applies to `containers`, `initContainers`, and `ephemeralContainers`)

| Field | Allowed values |
|---|---|
| `securityContext.allowPrivilegeEscalation` | absent or `false` |
| `securityContext.privileged` | absent or `false` |
| `securityContext.capabilities.add` | absent, empty, or `["NET_BIND_SERVICE"]` only |
| `securityContext.procMount` | absent, `""`, or `"Default"` |
| `ports[*].hostPort` | absent or `0` |

Any violation is reported as a validation error and the pod is rejected.


---

## Optional Defaults and Constraints

### `tritonai-admission-webhook/policy.runAsUser` and `tritonai-admission-webhook/default.runAsUser`; `tritonai-admission-webhook/policy.runAsGroup` and `tritonai-admission-webhook/default.runAsGroup`

_Mutator_:  If any Container-level `securityContext` is missing runAsUser/runAsGroup, and the Pod-level `securityContext` also lacks the value (or securityContext is absent), insert the default value at the Pod level.

_Validator_: If the **Pod-level** `securityContext` sets the field, it must match.  All **container** `securityContext`s that set the field must match.  If the Pod-level `securityContext` is **absent** (or does not set the field), **every** container must supply the field and it must match.

Validator accepts a comma-separated list of tokens forming a `ConstraintSet` with OR semantics. The supported token forms for `runAsUser` and `runAsGroup` are:

| Token | Example | Matches |
|---|---|---|
| Exact | `1000` | only 1000 |
| Range | `2000-3000` | 2000 ≤ x ≤ 3000 |
| Greater-than | `>5000000` | x > 5000000 |
| Less-than | `<500` | x < 500 |
| Greater-or-equal | `>=1000` | x ≥ 1000 |
| Less-or-equal | `<=1000` | x ≤ 1000 |


``` tritonai-admission-webhook/policy.runAsUser: "1000,2000-3000,>5000000" ```produces four constraints joined by OR — a user ID satisfies the annotation if it matches **any** of them. The same parser is shared by `runAsUser`, `runAsGroup`, `fsGroup`, and `supplementalGroups`.


### `tritonai-admission-webhook/policy.fsGroup`

_Mutator_: If default provided, and Pod security context does not specify fsGroup, inject default value into Pod.

_Validator_: If present, must match the annotation constraint value.  Validator accepts a `ConstraintSet` as with `runAsUser` using the same token logic.

### `tritonai-admission-webhook/policy.supplementalGroups` and `tritonai-admission-webhook/default.supplementalGroups`

_Mutator_: If comma-separated default list is provided, and Pod security context does not specify `supplementalGroups`, inject defaults.

_Validator_: If present,  **every element** in Pod's `supplementalGroups` list must be explicitly permitted. Validator accepts a `ConstraintSet` comma-separated list as with `runAsUser` using the same token logic.


### `tritonai-admission-webhook/policy.nodeLabel`

_Mutator_: If default provided, and Pod does not specify nodeSelector(s), inject default list.

_Validator_:   `pod.spec.nodeSelector` must contain at least one entry matching **any** of the
  annotation's `key=value` tokens.  **Additionally**, ensures `pod.spec.nodeName` is **absent**.  _(Setting `nodeName` bypasses the scheduler and the `nodeSelector` check entirely, so it is never permitted when this annotation is present.)_


Example — namespace annotation `"rack=b,rack=c"` would:

| Pod nodeSelector              | Result  | Reason                             |
|-------------------------------|---------|------------------------------------|
| `{rack: b}`                   | Allowed | matches `rack=b`                   |
| `{rack: c, zone: us-west-2}`  | Allowed | matches `rack=c`; extra key is OK  |
| `{rack: a}`                   | Rejected | no token matches                  |
| `{}` or absent                | Rejected | no token matches                  |
| any spec with `nodeName` set  | Rejected | `nodeName` bypass is forbidden     |



### `tritonai-admission-webhook/policy.allowedNfsVolumes`

_Validator_: If the annotation is **absent or empty**, no NFS volumes are permitted. If NFS volumes are present, **each** must match at least one entry in the comma-separated allowlist.

A match is either an exact `server:/path` string or a **shell glob** (fnmatch) pattern,
  e.g. `its-dsmlp-fs0[1-9]:/export/workspaces/*FA25`.

```
tritonai-admission-webhook/policy.allowedNfsVolumes: "10.20.5.3:/export/data,itsnfs:/scratch,its-dsmlp-fs0[1-9]:/export/workspaces/*"
```

A pod with no NFS volumes is always accepted regardless of this annotation.

### `tritonai-admission-webhook/policy.prohibitedVolumeTypes`

_Validator_: By default, the Validator allows use of the following Volume types:     "configMap",
    "downwardAPI",
    "emptyDir",
    "image",
    "nfs",
    "persistentVolumeClaim",
    "secret",
    "serviceAccountToken",
    "clusterTrustBundle",
    "podCertificate",
    "projected"

If present, `prohibitedVolumeTypes` removes one or more types from this list.

The following container env/envFrom sources are also blocked
across all `containers`, `initContainers`, and `ephemeralContainers` when their corresponding Volume type is disabled:

| Prohibited type | Blocked env source | Blocked envFrom source |
|---|---|---|
| `configMap` | `env[].valueFrom.configMapKeyRef` | `envFrom[].configMapRef` |
| `secret` | `env[].valueFrom.secretKeyRef` | `envFrom[].secretRef` |
| `downwardAPI` | `env[].valueFrom.fieldRef`, `env[].valueFrom.resourceFieldRef` | — |

```
tritonai-admission-webhook/policy.prohibitedVolumeTypes: "emptyDir,secret"
```

### `tritonai-admission-webhook/policy.tolerations` and `tritonai-admission-webhook/default.tolerations`

_Mutator_: Injects a list of `key=value:effect` defaults into `spec.tolerations` only when the pod's toleration list is **absent or empty**. (Kubernetes-internal tolerations ignored when deciding whether to inject.) If an entry's `value` is `*`, the injected toleration uses `operator: Exists` (no `value` field); otherwise the injected toleration uses `operator: Equal` and the supplied value.

_Validator_: Ensures every pod spec Toleration falls within the list of comma-separated `key=value:effect` tokens.  

Globs (`fnmatch` style) may appear in **any** field (key, value, or effect).  The special value `*` additionally covers tolerations that use `operator: Exists` (which carry no `value` field).

| Token format | Example | Meaning |
|---|---|---|
| `key=value:effect` | `node-type=its-ai:NoSchedule` | Equal operator, exact value match |
| `key=*:effect` | `node-type=*:NoSchedule` | Wildcard value — matches Equal (any value) **and** Exists (no value) |
| `key=glob*:effect` | `node-type=its-ai*:NoSchedule` | fnmatch glob in value field |





---


## Pod Security Standards Compliance Analysis

This section maps the webhook's hardcoded constraints and configurable namespace annotations against the Kubernetes [`baseline`](https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline) and [`restricted`](https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted) Pod Security Standards.

Note: the Windows-only `hostProcess` control has been excluded from the following table. 

### Legend

| Symbol | Meaning |
|--------|---------|
| ✅ Enforced | Hardcoded; always applied regardless of namespace annotations |
| ✅ Stricter | Webhook enforces a tighter rule than the standard requires (hardcoded) |
| ⚙️ Configurable | Compliance depends on how the namespace annotation is set; not guaranteed by default |
| ⚠️ Partial | Standard is partially addressed but a gap remains that no current configuration can close |
| ❌ Not enforced | Webhook does not check this control at all |

---


### Baseline Policy

| Control | Restricted fields | Standard allows | Webhook status | Notes |
|---------|------------------|-----------------|----------------|-------|
| Host Namespaces | `spec.hostNetwork`, `spec.hostPID`, `spec.hostIPC` | `undefined/nil`, `false` | ✅ Enforced | Hardcoded: each must be absent or `false`. |
| Privileged Containers | `spec.containers[*].securityContext.privileged`, init/ephemeral containers | `undefined/nil`, `false` | ✅ Enforced | Hardcoded: `privileged` must be absent or `false`. |
| Capabilities (`add`) | `spec.containers[*].securityContext.capabilities.add`, init/ephemeral containers | `undefined/nil`, or one of 14 named capabilities | ✅ Stricter | Only `NET_BIND_SERVICE` may appear in `capabilities.add`. Baseline permits 13 additional capabilities (e.g. `CHOWN`, `KILL`, `SETUID`); the webhook rejects them all. `capabilities.drop` is not checked (required only by Restricted). |
| HostPath Volumes | `spec.volumes[*].hostPath` | `undefined/nil` | ✅ Enforced | `hostPath` is absent from the hardcoded allowed volume-type set; hostPath volumes are always rejected. |
| Host Ports | `spec.containers[*].ports[*].hostPort`, init/ephemeral containers | `undefined/nil`, `0` | ✅ Enforced | Hardcoded: `hostPort` must be absent or `0` across all container types. |
| Host Probes / Lifecycle Hooks (v1.34+) | `httpGet.host` and `tcpSocket.host` on liveness/readiness/startup probes and lifecycle hooks | `undefined/nil`, `""` | ❌ Not enforced | Probe and lifecycle hook `host` fields are not inspected. |
| `/proc` Mount Type | `spec.containers[*].securityContext.procMount`, init/ephemeral containers | `undefined/nil`, `Default` | ✅ Enforced | Hardcoded: `procMount` must be absent, `""`, or `"Default"`. |
| Sysctls | `spec.securityContext.sysctls[*].name` | `undefined/nil`, or a specific set of "safe" sysctls (`kernel.shm_rmid_forced`, several `net.ipv4.*`) | ✅ Stricter | All sysctls are forbidden (hardcoded: `sysctls` must be absent or `[]`). This is more restrictive than Baseline, which permits the safe sysctl subset. |
| AppArmor | `spec.securityContext.appArmorProfile.type`, `spec.containers[*].securityContext.appArmorProfile.type`, init/ephemeral containers; `metadata.annotations["container.apparmor.security.beta.kubernetes.io/*"]` | `undefined/nil`, `RuntimeDefault`, `Localhost` | ❌ Not enforced | AppArmor profile type is not checked; `Unconfined` or arbitrary custom profiles are not blocked. |
| SELinux | `seLinuxOptions.type` (pod & all containers); `seLinuxOptions.user`, `seLinuxOptions.role` (pod & all containers) | type: `undefined/""`, `container_t`, `container_init_t`, `container_kvm_t`, `container_engine_t`; user/role: `undefined/""` | ❌ Not enforced | SELinux type, user, and role fields are not inspected. |

| Seccomp | `spec.securityContext.seccompProfile.type`, `spec.containers[*].securityContext.seccompProfile.type`, init/ephemeral containers | `undefined/nil`, `RuntimeDefault`, `Localhost` (i.e. `Unconfined` is disallowed) | ❌ Not enforced | Seccomp profile type is not inspected; `Unconfined` is not blocked. |


---

### Restricted Policy

Restricted is cumulative — it includes all Baseline controls above, plus the following.

| Control | Restricted fields | Standard requires | Webhook status | Notes |
|---------|------------------|-------------------|----------------|-------|
| *(all Baseline controls)* | — | *(see table above)* | *(as above)* | — |
| Volume Types | `spec.volumes[*]` | Only `configMap`, `csi`, `downwardAPI`, `emptyDir`, `ephemeral`, `persistentVolumeClaim`, `projected`, `secret` | ⚙️ Configurable  | The hardcoded allowed set includes extra types not permitted by Restricted: `nfs`, `image`, `serviceAccountToken`, `clusterTrustBundle`, `podCertificate`. These can be excluded using `tritonai-admission-webhook/policy.prohibitedVolumeTypes`, reducing the effective set to `configMap`, `downwardAPI`, `emptyDir`, `persistentVolumeClaim`, `projected`, `secret`. However, `csi` and `ephemeral` — which Restricted allows — are not in the webhook's base set and cannot be added via annotation, so pods requiring those types will always be rejected. |
| Privilege Escalation | `spec.containers[*].securityContext.allowPrivilegeEscalation`, init/ephemeral containers | Must be explicitly `false` | ⚠️ Partial | The webhook rejects any value other than `false` (hardcoded), but it also accepts the field being absent (treated as `false` by k8s API) |
| Running as Non-root (`runAsNonRoot`) | `spec.securityContext.runAsNonRoot`, `spec.containers[*].securityContext.runAsNonRoot`, init/ephemeral containers | `true` at pod or container level | ✅ Enforced | Hardcoded: `runAsNonRoot` must be `true` at pod level or on every container individually. The mutator unconditionally injects `true` when the field is absent. |
| Running as Non-root user (`runAsUser != 0`) | `spec.securityContext.runAsUser`, `spec.containers[*].securityContext.runAsUser`, init/ephemeral containers | Any non-zero value, or `undefined/null` | ⚙️ Configurable | The webhook enforces `runAsUser` through `tritonai-admission-webhook/policy.runAsUser`. Setting that annotation to `">0"` (or any constraint that excludes `0`) satisfies this control. There is no hardcoded default preventing UID 0; compliance depends entirely on the namespace annotation. |
| Seccomp (Restricted) | `spec.securityContext.seccompProfile.type`, `spec.containers[*].securityContext.seccompProfile.type`, init/ephemeral containers | Must be `RuntimeDefault` or `Localhost` (absence is not permitted) | ❌ Not enforced | Seccomp profile type is not inspected. Under Restricted, omitting the field is a violation; the webhook cannot enforce this without new logic. |
| Capabilities (`drop ALL`) | `spec.containers[*].securityContext.capabilities.drop`, init/ephemeral containers | Must include `ALL` |  ✅ Equivalent | `capabilities.drop` is not checked. The webhook instead validates `capabilities.add` (only `NET_BIND_SERVICE` permitted). |

---

# Development Notes

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

## ConfigMap-Based Policy Lookup

As an alternative to annotating each namespace directly, policies can be stored in ConfigMaps within the webhook's own namespace and mapped to subject namespaces via their labels.

### How it works

1. Create a **policy index** ConfigMap (default name: `pod-security-policy-index`) in the webhook's namespace.  Each key is a `label=value` string; each value is the name of a policy ConfigMap in the same namespace.

2. Create one or more **policy ConfigMaps** whose `data` entries use the same key/value format as namespace annotations. Keys may be written in bare form (prefix optional) or with the full annotation prefix — both are accepted:

```yaml
# Policy index
apiVersion: v1
kind: ConfigMap
metadata:
  name: pod-security-policy-index
  namespace: tgptinf-system
data:
  "team=research": research-policy
  "tier=gpu":      gpu-policy

---
# A policy ConfigMap — bare keys (prefix omitted) are the recommended form
apiVersion: v1
kind: ConfigMap
metadata:
  name: gpu-policy
  namespace: tgptinf-system
data:
  policy.runAsUser: "1000,>5000000"   # bare key — annotation prefix optional
  policy.nodeLabel: "partition=gpu"
  default.runAsUser: "1000"
  default.nodeLabel: "partition=gpu"
  # full-prefix form is equally valid:
  # tritonai-admission-webhook/policy.runAsUser: "1000,>5000000"
```

3. Label the subject namespaces — no annotations needed:

```yaml
metadata:
  labels:
    tier: gpu
```

### Lookup behaviour

- All `label=value` pairs on the subject namespace are checked against the index.
- If **one or more** entries match, their policy ConfigMaps are fetched and merged in **lexical order of the `label=value` key** (so conflicts resolve deterministically: the lexically-last matching label wins). The namespace's own `tritonai-admission-webhook/` annotations are then merged on top, so namespace annotations override ConfigMap entries on conflict. This allows per-namespace overrides without a separate ConfigMap.
- If **no** index entry matches, the webhook falls back to the namespace's own annotations (existing behaviour).

### Caching

Both the index ConfigMap and each policy ConfigMap are cached for `POLICY_CACHE_TTL` seconds (default 10 minutes). On fetch errors the last cached value is reused; if there is no prior cached value an empty dict is used so the webhook degrades gracefully rather than 500-ing.

---

## Environment Variables

| Variable                | Default                        | Description                                                                        |
|------------------------|--------------------------------|------------------------------------------------------------------------------------|
| `LOG_LEVEL`            | `INFO`                         | Python logging level                                                               |
| `ANNOTATION_PREFIX`    | `tritonai-admission-webhook`   | Prefix for all webhook namespace annotations (`policy.*`, `default.*`)             |
| `POLICY_INDEX_CONFIGMAP` | `pod-security-policy-index`  | Name of the index ConfigMap that maps `label=value` → policy ConfigMap name       |
| `POLICY_CACHE_TTL`     | `600`                          | Seconds to cache the index and policy ConfigMaps (0 disables caching)             |
| `PORT`                 | `8443`                         | Listening port (dev entrypoint only)                                               |
| `TLS_KEY_FILE`         | —                              | Path to TLS private key                                                            |
| `TLS_CERT_FILE`        | —                              | Path to TLS certificate                                                            |

---


## References:
- https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#what-are-admission-webhooks


