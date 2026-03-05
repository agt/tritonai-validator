# TritonAI Pod Security Admission Webhook

A FastAPI-based Kubernetes **Validating Admission Webhook** that enforces per-namespace
Pod security requirements via namespace annotations.

---

## How It Works

When a Pod is submitted to Kubernetes, the API server calls this webhook's `/validate`
endpoint.  The webhook:

1. Fetches `securityContext/*` annotations from the Pod's **namespace**.
2. If **no** annotations are present → **reject** (policy must be explicit).
3. Parses each annotation into a constraint set and validates the Pod spec.
4. If **any** constraint fails → **reject** with a descriptive message listing all failures.

---

## Namespace Annotations

Set security policy on a namespace by adding annotations prefixed `securityContext/`.

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: my-app
  annotations:
    securityContext/runAsUser: "1000,2000-3000,>5000000"
    securityContext/runAsGroup: "1000"
    securityContext/fsGroup: "1000"
    securityContext/supplementalGroups: "1000,2000-3000"
    securityContext/allowPrivilegeEscalation: "false"
```

### Constraint Value Syntax

Comma-separated tokens, matched with **OR** semantics (any one token matching is sufficient):

| Token format | Example      | Meaning                    |
|-------------|--------------|----------------------------|
| Exact        | `1000`       | value == 1000              |
| Closed range | `2000-3000`  | 2000 ≤ value ≤ 3000        |
| Greater than | `>5000000`   | value > 5,000,000          |
| Less than    | `<500`       | value < 500                |
| ≥            | `>=1000`     | value ≥ 1000               |
| ≤            | `<=1000`     | value ≤ 1000               |
| Boolean      | `true`/`false` | exact boolean match      |

---

## Validation Behavior per Annotation

### `securityContext/runAsUser`, `securityContext/runAsGroup`, `securityContext/allowPrivilegeEscalation`

**Required field** — enforcement is strict:

- If the **Pod-level** `securityContext` sets the field → it must match.
- All **container/initContainer** `securityContext`s that set the field → must match.
- If the Pod-level `securityContext` is **absent** (or does not set the field), **every**
  container and initContainer must supply the field and it must match.

### `securityContext/fsGroup`

**Optional field** — only pod-level:

- Absent from pod `securityContext` → constraint satisfied (no requirement to set it).
- Present → must match the annotation constraint.

### `securityContext/supplementalGroups`

**Optional list** — only pod-level:

- Absent or empty → constraint satisfied.
- Present → **every element** must satisfy at least one constraint token.

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

3. **New annotation key** — add entries to both:
   - `app/constraints/registry.py` → `CONSTRAINT_REGISTRY`
   - `app/validator.py` → `_FIELD_SPECS`

---

## Environment Variables

| Variable        | Default | Description                         |
|----------------|---------|-------------------------------------|
| `LOG_LEVEL`    | `INFO`  | Python logging level                |
| `PORT`         | `8443`  | Listening port (dev entrypoint only)|
| `TLS_KEY_FILE` | —       | Path to TLS private key             |
| `TLS_CERT_FILE`| —       | Path to TLS certificate             |
