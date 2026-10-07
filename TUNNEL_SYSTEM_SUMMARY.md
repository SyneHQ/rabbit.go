# Rabbit transport architecture

Rabbit connects a private TCP service to an assigned server port. It does not
parse SQL, convert result formats or execute database queries.

## Connection lifecycle

1. The private-machine client opens a verified TLS 1.3 control connection.
2. The server validates its token and restores or assigns the token's ingress port.
3. Kelvo opens a native database connection to that port.
4. The server sends `CONNECT` and `CONN_ID:<id>` as two newline-terminated control lines.
5. The client opens a separate TLS connection, sends `DATA:<id>`, and dials its local service.
6. Both sides stream bytes until EOF, error, cancellation or revocation.

A clean EOF half-closes the sending side and lets the response drain. A transport
error closes both sides. Reconnection restores the tunnel, not in-flight queries.

## Boundaries

| Channel | Default exposure | Trust |
| --- | --- | --- |
| Control and data TLS | `0.0.0.0:9999` | Verified server certificate and tunnel token |
| Database ingress | `127.0.0.1:<assigned-port>` | Host/network access controls and database authentication |
| Management HTTP | `127.0.0.1:8080` | Service credential plus team/user membership |
| Metadata | Configured PostgreSQL and Redis | Operator-managed credentials and network policy |

Ingress ports are capabilities: anyone who can reach one can attempt a database
connection. Use a private interface and firewall for remote workers; preserve
verified database TLS for end-to-end database identity.

## Resource ownership

Each client control session owns its reader, cancellation context and stream workers.
Old monitors cannot close a replacement session. Control writes are serialized and
bounded; buffered bytes remain attached to their connection.

The server records each stream against its parent tunnel session. Completing a
stream does not close that parent session. Shutdown cancels pending work, closes
owned sockets and releases metadata pools.

A client-specific eight-entry TLS cache reuses authenticated sessions. Changes to
the server identity or custom CA contents replace the cache. No early application
data is replayed. The wire protocol stays TCP/TLS.

[Deployment](docs/private-database-transport.md) · [Validation](docs/transport-validation.md)
