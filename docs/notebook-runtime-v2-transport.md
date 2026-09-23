# Private notebook runtime transport

The notebook route uses Rabbit's existing TLS 1.3 control listener. It does not allocate a public data listener. Existing database tunnels retain their existing protocol. Notebook routing is disabled unless `RABBIT_NOTEBOOK_AUTHORITY_URL`, `NOTEBOOK_RUNTIME_SERVICE_TOKEN` and `RABBIT_NOTEBOOK_BROKER_TOKEN` are configured. The two secrets must be different credentials for different services.

The authority URL is the app's `/api/internal/notebook-runtimes-v2` endpoint. HTTPS, certificate verification and a two-second request timeout are required. Explicit local development can use literal loopback HTTP. Redirects and unbounded responses are rejected. Customer frames cannot select this endpoint, a target host, a port or a command.

## Protocol

Every control or data connection begins with one frame name and one bounded JSON line. Unknown fields are rejected. The notebook service is exactly `notebook-v2`.

- `RUNTIME-V2`: registration includes runtime, workspace, installation, credential generation, current policy revision, ledger generation, environment digest and runtime credential. A successful connection receives `READY`. The launcher sends `PING` every three seconds and receives `PONG` only after fresh authorization.
- `RUNTIME-OPEN-V2`: the coordinator supplies the exact registration scope and a separate broker token. It never supplies a local address. The server authorizes again, sends `OPEN <random-one-use-id>` to the enrolled launcher and waits for pairing.
- `RUNTIME-DATA-V2`: the launcher supplies the same registration and the one-use ID. The server reauthorizes, consumes the ID and responds `PAIRED`. After another authority check, the coordinator receives `READY` and its byte stream is bridged to the fixed helper address configured locally by the operator.

The notebook HTTP body still carries its action-scoped capability. Rabbit credentials authorize transport only, never Python execution. The node and central execution ledger must independently validate the approved code, notebook, actor, inputs and runtime binding.

Authority responses must match the exact scope and expire within ten seconds. Expired leases cannot be revived. Denial or expiry closes that runtime's control and data connections. Thus revocation is bounded by the ten-second lease plus the 100ms expiry sweep, rather than claimed to be instantaneous. Authority failure fails closed. Disabling execution can retain transport for status, cancellation and artifact recovery; the execution layer blocks new submissions.

At most eight streams may be open for one runtime, 128 pairing requests globally, and 1024 runtimes per process. Pairing has a five-second deadline. A byte stream has a three-minute lifetime; status/output consumers must reconnect using their execution cursor. Transport reconnect does not resend HTTP requests or notebook cells. Disconnecting transport is not evidence that an already accepted execution stopped.

## Local connection command

`rabbit.go runtime-connect --connection-file /absolute/path/runtime.json` loads a private regular JSON file (0600, maximum 8 KiB), verifies Rabbit TLS for both control and data, and connects only to the configured literal-loopback helper. The file contains `version: 2`, `serverAddress`, `caFile`, `serverName`, `helperAddress` and `registration`. Enrollment creates the scoped registration separately. Never pass credentials on the command line or put this file in a notebook workspace.

This command connects an already-running helper. For verified HTTPS enrollment, private credential rotation, and process supervision, use the [local runtime launcher](notebook-runtime-launcher.md). Customer runtime selection remains gated on integrated launcher, central coordinator, capability provisioning and Quantum Lab review-flow acceptance.

## Validation

Focused Go tests with the race detector cover verified control/data TLS, fixed helper routing, buffered payload preservation, transport shutdown, cross-team/policy/ledger/service denial, single-use pairing, active bridge revocation, lease expiry, malformed frames, bounded authority responses and exact authorization scope. These are transport checks, not end-to-end notebook execution evidence.

A native integration run built the actual sibling Go client and connected it through the router's TLS listener to a loopback HTTP helper. The request and response crossed the paired data connection; changing the live authority to deny access closed the existing stream at the next heartbeat. Both Go modules passed `go test -race ./...`. Additional regressions prove a blocked socket close cannot delay an unrelated lease and queued refreshes stop consulting authority after revocation. All integration listeners and child processes were closed afterward. No Docker, deployment, customer database or Jupyter execution was involved in this transport test.
