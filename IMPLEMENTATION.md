# Implementation Notes

## Sync-in-Async: `get_namespace_security_annotations()`

### Problem

`get_namespace_security_annotations()` in `app/namespace_client.py` makes a
synchronous HTTP call to the Kubernetes API (`api.read_namespace(namespace)`)
inside async FastAPI handlers (`/mutate` and `/validate`). This blocks the
event loop for the duration of the network round-trip, preventing the server
from handling other requests concurrently.

Under low concurrency (single webhook invocation at a time) this is
acceptable, but under high concurrency (e.g. burst of pod creations) it
becomes a bottleneck: every request serializes on the blocking K8s API call.

### Approaches Considered

#### Approach 1: `asyncio.to_thread()` wrapper (selected)

Wrap the blocking call in `asyncio.to_thread()` so it runs in a thread pool
and does not block the event loop.

**Changes required:**
- Make `get_namespace_security_annotations()` an `async` function (or add a
  new async wrapper) that calls the existing sync logic via
  `asyncio.to_thread()`.
- Update callers in `app/main.py` to `await` the result.

**Pros:**
- Minimal code change; the sync K8s client code stays as-is.
- Uses Python's default `ThreadPoolExecutor`, which is well-suited for I/O
  bound blocking calls.
- No new dependencies.

**Cons:**
- Thread pool has a finite size (default = min(32, os.cpu_count() + 4)).
  Under extreme concurrency the pool could saturate, but this is unlikely
  for a webhook server.

#### Approach 2: Async Kubernetes client (`kubernetes_asyncio`)

Replace the synchronous `kubernetes` client with `kubernetes_asyncio`, a
community-maintained async fork.

**Pros:**
- True async I/O with no thread overhead.

**Cons:**
- New dependency (`kubernetes_asyncio`).
- Different API surface; requires rewriting client initialization and the
  API call.
- Less mature than the official sync client.

#### Approach 3: `run_in_executor()` with custom pool

Similar to Approach 1 but with an explicit `ThreadPoolExecutor` for finer
control over pool size.

**Pros:**
- Full control over thread pool sizing and naming.

**Cons:**
- More boilerplate for minimal practical benefit over `asyncio.to_thread()`.

### Decision

**Approach 1** — `asyncio.to_thread()` wrapper. It is the simplest change
that resolves the event-loop blocking issue without adding dependencies or
rewriting the K8s client code.
