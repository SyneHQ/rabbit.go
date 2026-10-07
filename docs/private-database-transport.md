# Private databases through Rabbit

## Placement

Run Rabbit client on the customer's machine or VPS, beside the private database.
Run Rabbit server beside Kelvo or on its private network. Only the customer-side
client needs outbound reachability to the server's TLS control port.

Keep Kelvo's database connections pooled. Every new database connection creates a
Rabbit data stream, so reusing a pool avoids control dispatch and connection setup.
Rabbit itself does not pool or replay database sessions.

## Same host

Use the default `--tunnel-bind 127.0.0.1`. Configure the Kelvo source with the token's
assigned ingress port. Keep database authentication enabled. For verified database
TLS, use the driver's server-name setting or a local DNS mapping that preserves the
source certificate's identity.

## Separate hosts

Set `--tunnel-bind` to a private IP reachable by Kelvo workers. Firewall the assigned
port range so only those workers can connect. The ingress listener carries the
original database protocol; the public Rabbit TLS certificate protects the separate
client-to-server tunnel. Preserve database TLS across the entire path.

Set `--api-bind` only when the management service must be reachable off-host. Put a
TLS reverse proxy in front of its HTTP listener and restrict network access.

## Metadata and management

Set `DATABASE_URL`, `REDIS_URL` and `RABBIT_SERVICE_TOKEN` in the server environment.
Use verified TLS for remote metadata stores. Management requires a service token
of at least 32 characters plus `X-Team-ID` and `X-User-ID`; membership is checked in
PostgreSQL before access is granted.

The current repository expects application-owned `Team` and membership records.
`server/internal/database/migrations.sql` does not create a complete standalone
identity service. Do not run it blindly against an existing application database;
review its schema contract and migration first. Tests provision disposable schemas.

For an existing team and authorized administrator:

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
| Untrusted connections per IP | 100 | Source-level `SecurityConfig` |
| Idle connection | 30 minutes | Source-level `SecurityConfig.IdleTimeout` |
| Extra idle-deadline slack | At most 1 second | Derived from idle timeout |

These are admission limits, not capacity guarantees. Account for control sockets,
metadata work, file descriptors, database limits and available memory. Trusted
networks still obey the global connection cap.

Per-IP and idle settings currently require a source change; they have no CLI or
public server-configuration option.

Set a service restart policy and inspect exit status. Check `/api/v1/health` for
metadata availability. Monitor CPU, RSS, open sockets, connection failures, database
query latency and client pool wait time before increasing concurrency.

Certificate rotation affects new TLS connections. Replace custom CA files atomically;
restart processes when rotating system trust or the server's loaded TLS certificate.
Existing database sessions are not migrated to new sockets.

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
