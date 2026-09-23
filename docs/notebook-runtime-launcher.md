# Local notebook runtime launcher

On Linux and macOS, the Rabbit client provisions and supervises an installed Kole local notebook helper. The helper executes approved notebook code with the launcher user's operating-system permissions. It is not a sandbox: use a dedicated account with only the filesystem and network access intended for notebooks. Private file permissions and a minimal child environment prevent accidental credential exposure; they do not isolate hostile code running as that account.

## Install and enroll

Install the Python helper and its pinned dependency closure first, following Kole's `notebook_runtime/LOCAL_RUNTIME.md`. The launcher invokes only that Python executable's isolated `notebook_runtime.local_serve` module. It verifies the helper's ledger generation and installed environment digest before enrollment and every startup. Upgrading the environment requires an explicit runtime registration change; silently substituting another environment fails closed.

Create a dedicated mode-0700 state directory and private configuration directory owned by the launcher user. Store the following enrollment request as a mode-0600 regular file. Obtain the one-time enrollment token from an authorized workspace administrator and insert it using a private file editor, never a shell argument or environment variable.

```json
{
  "version": 2,
  "appOrigin": "https://app.example.com",
  "pythonExecutable": "/opt/syne/runtime/bin/python",
  "stateDirectory": "/var/lib/syne/runtime",
  "serverAddress": "rabbit.example.com:8443",
  "serverName": "rabbit.example.com",
  "runtimeId": "runtime_id_from_app",
  "teamId": "workspace_id_from_app",
  "enrollmentToken": "ONE_TIME_TOKEN_FROM_APP"
}
```

`appCAFile` and `caFile` may specify absolute PEM trust-store paths for a private app CA and Rabbit CA respectively. HTTPS and certificate verification are mandatory for app provisioning; redirects, URL credentials, plaintext endpoints, and arbitrary endpoint paths are rejected. Rabbit independently verifies its TLS connection. The app origin must be an origin, without a path, query, or fragment.

```sh
rabbit.go runtime-enroll --request-file /var/lib/syne/config/enrollment.json --config /var/lib/syne/config/runtime.json
rabbit.go runtime-start --config /var/lib/syne/config/runtime.json
```

Enrollment creates a durable installation identity, describes the installed helper, exchanges the one-time token for a runtime credential, then bootstraps the current policy and capability key over verified HTTPS. The runtime state contains secrets and must remain private, outside the helper's `workers` directory. Do not copy it into a notebook workspace or source repository. Remove the enrollment request after successful enrollment using your normal secret-file handling process.

The CLI prints only installation and policy metadata. Startup refreshes provisioning before spawning the helper, verifies actual readiness, and connects Rabbit to the helper's fixed loopback address. The readiness record means the helper is ready; Rabbit registration and central runtime health remain separate checks. A single state lock excludes simultaneous startup, enrollment, bootstrap, or rotation for that installation. Send SIGTERM or interrupt the foreground launcher for orderly helper shutdown.

## Credential rotation and recovery

Stop the launcher before refreshing registration or rotating credentials:

```sh
rabbit.go runtime-bootstrap --config /var/lib/syne/config/runtime.json
rabbit.go runtime-rotate --config /var/lib/syne/config/runtime.json
```

Bootstrap is a credential-authenticated, repeatable recovery of current policy and capability key. Rotation revokes the old runtime credential and durably saves the replacement before bootstrapping. Credential generation and capability-key version are independent. A capability key cannot change without increasing its version; a policy cannot change without increasing its revision.

Enrollment and rotation persist a pending marker before sending their credential mutation. If the acknowledgement is lost, the CLI reports an uncertain outcome and refuses an automatic retry. Keep the existing state and ledger. Ask an administrator for a fresh enrollment token for the same installation, place it in the private enrollment request, and explicitly recover:

```sh
rabbit.go runtime-enroll --request-file /var/lib/syne/config/enrollment.json --config /var/lib/syne/config/runtime.json --recover
```

Recovery preserves runtime, workspace, installation, ledger, environment, app origin, and Rabbit configuration. A missing bootstrap response after a successfully saved credential only requires `runtime-bootstrap`; it does not require re-enrollment. Expired credentials can be replaced through the same explicit administrator-authorized recovery flow.

The launcher does not rotate credentials automatically or mutate an active helper's policy/key configuration. Arrange stopped-state maintenance before credential expiry. Central authorization independently fails closed on expiry, revocation, and stale registration. Transport loss does not prove accepted notebook work stopped: recover its status or cancel its exact execution through the coordinator instead of resubmitting it.

## Verification

Client race tests exercise verified HTTPS, untrusted certificates, redirect refusal, lost mutation acknowledgements, explicit same-installation recovery, policy and key versioning, private files, duplicate JSON rejection, and helper supervision. The opt-in native server test uses an actual built client, Rabbit TLS router, and installed Python/Jupyter helper:

```sh
RABBIT_RUNTIME_CLIENT_TEST_BINARY=/absolute/path/rabbit.go \
RABBIT_RUNTIME_HELPER_TEST_PYTHON=/absolute/path/runtime/bin/python \
go test -race -v ./internal/runtime -run TestRuntimeLauncherNativeTLSIntegration -count=1
```

Run this from the server module. The test verifies early output, cursor reconnect, duplicate suppression, exact cancellation, revocation, and omission of inherited cloud/agent secrets from the kernel environment. Its app enrollment/bootstrap endpoint is a verified HTTPS contract fixture. It does not establish live app, Prisma, KMS, deployment, or full product acceptance. All test-owned listeners and child processes are shut down afterward.
