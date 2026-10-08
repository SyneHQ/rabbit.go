# Shared private database ingress

This opt-in HTTP/1.1 CONNECT endpoint lets trusted database consumers share one
private Rabbit port. Customer clients keep the existing outbound TLS protocol.

The endpoint is an integration building block. Native-driver hooks, issuer
integration, cancellation under saturation and WAN qualification need separate
acceptance before using this path for production traffic.

## Flow

1. The application authorizes a source and fetches its Rabbit route snapshot.
2. Its issuer signs a one-use ticket for that source, worker and execution attempt.
3. The worker opens CONNECT over verified mutual TLS, using the original database
   `host:port` as the request target.
4. Rabbit verifies the ticket, live source authority, token and current client owner.
   It sends success only after the customer's DATA socket is paired.
5. The native driver uses the resulting socket and still owns database TLS,
   credentials and SQL. Rabbit never resolves or dials the request target.

Use the assigned-port path until your application implements this flow. A route
snapshot, service token or caller-supplied tenant header cannot open CONNECT.

## Configure Rabbit

Add to the operator YAML passed with `--config`:

```yaml
private_connect:
  listen: 10.0.0.4:14443
  certificate_file: /etc/rabbit/private.crt
  private_key_file: /etc/rabbit/private.key
  client_ca_file: /etc/rabbit/workers-ca.crt
  authority_url: https://authority.internal/transport-lease
  authority_ca_file: /etc/rabbit/authority-ca.crt
  authority_certificate_file: /etc/rabbit/authority-client.crt
  authority_private_key_file: /etc/rabbit/authority-client.key
  replay_capacity: 16384
  trust:
    - issuer: application
      audience: database-ingress
      cluster_tenant: shared
      service_principal: analytics
      worker_identity: spiffe://example.com/workers/worker-a
      public_key_hex: REPLACE_WITH_ED25519_PUBLIC_KEY_HEX
```

Use a literal loopback or private IP. For dynamic pod addresses, replace `listen`
with `listen: ":14443"` and add `private_interface: eth0`. Rabbit resolves that
interface once at startup. It requires exactly one private unicast address and
rejects multiple private addresses; use a literal private IP for such interfaces.
It never falls back to a wildcard or public bind.

The operator YAML and referenced files require root or server-user ownership
without group/other write access. Private keys default to owner-only access (`0600`
or `0400`). For root-owned Secret subpath mounts, set `private_key_group: 1000`
inside `private_connect` and mount keys as `0440` with GID `1000`. The daemon must
belong to that exact service GID. Group write/execute and all other access remain
forbidden; arbitrary group/world-readable keys are rejected. The configured group
applies to both server and authority private keys.

Keep parent directories under the same trusted ownership and prevent untrusted writes.
Referenced paths are absolute and reject symbolic links and inputs larger than
64 KiB. Private ingress fails closed on Windows, where ownership verification is
not implemented. TLS 1.3 and verified client certificates are mandatory.

The authority uses separate mutual TLS credentials. Its URL and trusted issuer
keys come only from operator configuration. Restart Rabbit after changes.

Keep per-token ports loopback-only. Expose the fixed private port only to trusted
workers through your network policy. No public database-port range is needed.

## Issuer contract

Fetch `GET /api/v1/teams/{teamId}/tokens/{tokenId}/route` through the existing
management authorization. It checks the service credential and live team
membership. The response contains tenant, token ID, random token epoch, tunnel
ID and current control-owner generation. It contains no database credentials or
customer registration token.

The issuer must verify that the authorized source ID and revision map to this
exact tenant/token. Rabbit does not own the application's source catalog.

The version-1 [ticket types](../server/transport/grant.go) bind:

- Issuer, audience, cluster tenant and service principal.
- Source ID/revision and the complete route snapshot.
- Exact worker certificate fingerprint and URI identity.
- Query/operation ID, grant digest, worker incarnation and execution attempt.
- Original database authority, one-use random ID and signed deadlines.

Sign with Ed25519 using JWT type `rabbit-connect+jwt`. Admission lasts at most
60 seconds. The separate session deadline is at most 24 hours. Each physical
database connection needs its own ticket, including PostgreSQL cancellation
connections. Reconnect invalidates outstanding tickets; queries are never replayed.

## Live lease

Rabbit sends the [versioned lease request](../server/transport/authority.go) to
the configured authority before admission and during each active stream. The
authority must verify the ticket signature, source mapping, source revision,
revocation state and exact live execution custody. Admission expiry does not
invalidate an existing session; its signed session expiry still applies.

Return JSON with `version`, matching `open_sha256`, and `valid_until` Unix seconds.
The returned lease must be current, at most 15 seconds ahead, and no later than
the underlying execution lease. Rabbit also caps it by the session, worker
certificate and source-token expiration.

Each pooled authority response rechecks both TLS identities. Leases cannot
outlive either identity's certificate chain; restart Rabbit to rotate its keys.

Authority errors, invalid replies, revocation and lease expiry close both stream
directions. Each renewal has a two-second budget; responses and headers are
bounded. TLS connections to the authority are reused. Token renewal reads
metadata without updating usage timestamps or creating database sessions.

## Boundaries

- Only CONNECT, Host, Proxy-Authorization and optional User-Agent are accepted.
  Request bodies, chunking, duplicate headers and proxy chaining are rejected.
- Accepted sockets share Rabbit's global admission limit and shutdown owner.
  The replay registry is bounded and never evicts an unexpired ticket.
- Control-owner replacement closes pending and active streams for the old owner.
- Temporary listener errors use bounded retries. A fatal error makes health
  return 503 and starts joined shutdown; it cannot leave a healthy dead listener.
- One process owns each live customer tunnel. A generic load balancer does not
  provide cross-instance routing or distributed replay protection.
- Source TLS must still verify the original database hostname. Do not replace it
  with localhost or disable certificate verification in the native driver.
