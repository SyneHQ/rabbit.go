# Private databases through Rabbit

## Placement

Run Rabbit client on the customer's machine or VPS, beside the private database.
Run Rabbit server beside Kelvo or on its private network. The customer-side client
opens outbound connections to the server's TLS control port, normally TCP 9999.
PostgreSQL metadata and Redis must be reachable from Rabbit and its migration job.

Keep Kelvo's database connections pooled. Every new database connection creates a
Rabbit data stream, so reusing a pool avoids control dispatch and connection setup.
Rabbit itself does not pool or replay database sessions.

## Same host

Use the default `--tunnel-bind 127.0.0.1` when Rabbit and Kelvo share a network
namespace. Separate containers on the same host do not share loopback.

Configure the Kelvo source with the token's assigned ingress port. Keep database
authentication enabled. For verified database TLS, use the driver's server-name
setting or a DNS mapping that preserves the source certificate's identity.

## Separate hosts

Set `--tunnel-bind` to a private IP reachable by Kelvo workers. Bind addresses must
be literal IPs. Permit each assigned ingress port only from the authorized workers.
The ingress carries the original database protocol; the public Rabbit certificate
protects the separate client-to-server tunnel. Preserve database TLS throughout.

Set `--api-bind` only when the management service must be reachable off-host. Put a
TLS reverse proxy in front of its HTTP listener and restrict network access.

## Containers and private routing

The published image starts with public control on `0.0.0.0:9999`, database ingress
on loopback, and the management API on `127.0.0.1:3422`. The CLI's API default is
8080. Set bindings explicitly when another container must connect:

```sh
# These addresses are examples: use interfaces assigned to the Rabbit process.
rabbit.go server --bind 0.0.0.0 --port 9999 \
  --tunnel-bind 10.20.0.10 --api-bind 127.0.0.1 --api-port 3422
```

If a container needs wildcard private bindings, restrict ingress through its
platform network policy before starting it. Publish only the control port.
Configure private DNS, service ports and peer rules for database ingress separately.

Tokens receive ports from 10000–65535. There is no configurable allocation range.
Platforms that route only declared service ports must declare each assigned port;
opening 9999 alone does not make a database reachable. Do not publish the full range.

Use an immutable image digest for the server and migration job. The repository's
Compose files are development wiring: they build locally, require an existing
`dokploy-network`, and do not provision metadata or private worker routing.

## Metadata and management

Set these through the service's secret/configuration provider:

| Setting | Purpose |
| --- | --- |
| `DATABASE_URL`, `REDIS_URL` | Metadata connections; both are required by migrations too |
| `RABBIT_REDIS_KEY_PREFIX` | Optional Redis namespace. Empty preserves existing keys. See [shared Redis](shared-redis.md). |
| `RABBIT_IDENTITY_MODE` | `standalone` for new metadata, `postgoose` for the existing application adapter |
| `RABBIT_SERVICE_TOKEN` | Management credential, at least 32 characters |
| `RABBIT_TLS_CERT_FILE`, `RABBIT_TLS_KEY_FILE` | Read-only PEM files for the control listener |
| `ENVIRONMENT=production` | Disables the development-only insecure listener exception |

Use verified TLS for remote metadata: PostgreSQL `sslmode=verify-full` with the
correct CA/hostname, and authenticated Redis over `rediss://`. Keep stores private.

Back up existing metadata and review the SQL before running the migration. Inside
the published image, run:

```sh
rabbit.go database migrate /usr/local/bin/internal/database/migrations.sql
```

New standalone deployments then create their first team through the
[identity guide](standalone-identity.md). Existing application deployments retain
their `Team` and `postgoose_user_teams` tables. Each metadata database binds to one
identity mode; changing an environment variable does not migrate identities.

Management requires `X-Service-Token`, `X-Team-ID` and `X-User-ID`. PostgreSQL
membership checks authorize each request. The health endpoint needs no credential.

For an existing team and authorized administrator, using the CLI's default API port
(use 3422 for the published image):

```sh
curl --fail-with-body http://127.0.0.1:8080/api/v1/tokens/generate \
  -H 'Content-Type: application/json' \
  -H "X-Service-Token: $RABBIT_SERVICE_TOKEN" \
  -H "X-Team-ID: $TEAM_ID" -H "X-User-ID: $USER_ID" \
  --data "{\"team_id\":\"$TEAM_ID\",\"name\":\"analytics\",\"expires_in_days\":30}"
```

Treat the returned token as a secret. The application should deliver it only to the
intended customer client. Deleting a token revokes its tunnel and active streams.

## Limits and operations

| Limit | Default | Change |
| --- | --- | --- |
| Client streams | 64 | `--max-connections`, 1–4096 |
| Server accepted sockets, including database ingress | 4096 | `RABBIT_MAX_CONNECTIONS`, 1–1,000,000 |
| Untrusted connections per IP | 100 | `RABBIT_MAX_CONNECTIONS_PER_IP` or YAML |
| Idle connection | 30 minutes | `RABBIT_IDLE_TIMEOUT` or YAML |
| Extra idle-deadline slack | At most 1 second | Derived from idle timeout |

These are admission limits, not capacity guarantees. Account for control sockets,
metadata work, file descriptors, database limits and available memory. Trusted
networks still obey the global connection cap.

Use `rabbit.go server --config rabbit.yml` for [operator settings](operator-limits.md).
Environment values override YAML. Invalid settings stop startup.

Set a service restart policy and inspect exit status. Check `/api/v1/health` for
metadata availability. Monitor CPU, RSS, open sockets, connection failures, database
query latency and client pool wait time before increasing concurrency.

A TCP control-port probe establishes listener reachability only. Before routing
customer work, verify metadata health, an actual database query, cancellation and
token revocation through the deployed path.

Certificate rotation affects new TLS connections. Replace custom CA files atomically;
restart processes when rotating system trust or the server's loaded TLS certificate.
Existing database sessions are not migrated to new sockets.

## Upgrade and rollback

1. Retain the prior tested image digest, current secrets/configuration and a metadata backup.
2. Stop admission upstream, then stop Rabbit. Shutdown closes active streams; writes
   can have committed even when the caller sees a disconnect.
3. Run reviewed migrations, start the pinned replacement and verify the deployed path.
4. To roll back, stop the replacement and select the previous compatible image while
   retaining current identity/security settings. Recheck schema compatibility first.

Rabbit gives shutdown one 30-second budget across listeners, tunnels, management
requests and audit writes. Allow more than 30 seconds in the container stop grace
period. A deadline or cleanup failure produces a nonzero exit; it does not prove
that every session record or audit write reached the metadata database.

Embedded callers can use `Shutdown(ctx)` to shorten that budget. If it returns
`ErrShutdownIncomplete`, the same teardown owner still holds unfinished handlers
and pools. Use `WaitShutdown(ctx)` to join it; do not close those pools separately.
The CLI exits on that error, so the OS releases its remaining process resources.

There is no down-migration command. A metadata restore requires a separate recovery
decision: restoring old tokens can undo revocations. Do not replay interrupted writes
or assume Rabbit provides active-active tunnel ownership/failover.

## Transport choices

Rabbit keeps reliable ordered TCP/TLS streams and transparent database bytes.
TLS configurations and bounded session tickets are reused per client. The server
coalesces deadline updates while preserving explicit deadlines and timeout errors.

No universal compression is added: encrypted database traffic cannot be usefully
compressed at this layer. Enable compression in a database driver or Arrow exchange
where the endpoints understand it. QUIC is not assumed to improve bulk throughput.

Implementation references: Go's [copy fast paths](https://pkg.go.dev/io#Copy),
[TLS session cache](https://pkg.go.dev/crypto/tls#Config), and
[connection deadline contract](https://pkg.go.dev/net#Conn).
