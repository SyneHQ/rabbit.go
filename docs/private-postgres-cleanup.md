# Private PostgreSQL cancellation

This opt-in protocol keeps cancellation authority separate from query execution.
It requires matching issuer and trusted worker-parent implementations. MySQL
cancellation is not enabled by this protocol.

## Configure

Add these fields to the existing `private_connect` block:

```yaml
accepted_key_id: rabbit-route-1
accepted_private_key_file: /run/rabbit/accepted-source.key
cleanup_authority_url: https://issuer.internal/v1/private-transport/cleanup-lease
```

Use a separate Ed25519 PKCS8 key in an operator-owned, protected file. Pin its
public key and key ID in the issuer and worker route configuration. The existing
mTLS authority credentials also authenticate cleanup lease reads. Missing or
partial configuration fails closed; existing clients remain unchanged.

## Wire contract

1. The parent adds `Rabbit-Accepted-Open: required-v1` to its DATA CONNECT.
2. Rabbit returns a signed receipt in the same header only after pairing both
   sockets, refreshing the DATA lease and registering physical custody.
3. The issuer verifies the receipt against its retained original DATA ticket.
   It issues one `rabbit-postgres-abort+jwt` ticket with a fixed cutoff of at most
   five seconds from the first cancellation time.
4. The trusted parent opens CONNECT with that ticket and
   `Rabbit-Postgres-Abort: required-v1`, preserving the original source authority.
5. Rabbit checks the same held parent, worker certificate, source, token and
   control owner. It consumes the ticket and parent cleanup slot once.

Rabbit permits at most 256 KiB in each cleanup direction. It checks the separate
cleanup lease every 250 ms and never extends its first deadline. Parent closure,
revocation, expiry, byte exhaustion or uncertain authority closes cleanup.

## Trust boundary

The trusted parent owns the fixed PostgreSQL cancellation encoder, immutable
backend identity and original verified source TLS settings. It must never pass
the cleanup connection to an untrusted child. Rabbit relays encrypted TLS bytes;
it cannot inspect or enforce the plaintext PostgreSQL message inside them.

An authorized abort permanently blocks original worker-to-source DATA. A positive
cleanup lease permits up to 256 KiB of source-to-worker completion bytes. The
trusted adapter discards results and verifies protocol completion; these bytes
must not be delivered as query results. An explicit DATA lease
403 can also enter this state, but only with a separate positive cleanup lease.
Suspension never restores query writes. Network errors, invalid authority
responses, missing receipts and writes already in progress fail closed. A closed
parent cannot be recreated from its receipt.

A successful CONNECT proves transport admission, not backend cancellation. The
parent must report `cleanup_unknown` when it cannot verify source termination.

## Validation

Public deterministic vectors match the issuer codec. Tests cover replay, expired
or changed scope, missing opt-in, closed parents, cancellation before receipt
registration, suspended DATA, byte limits and joined shutdown. Source-TLS and
queued-job cancellation still require paired worker/issuer acceptance tests.
