# Reserved private connections

Version 2 is a protocol foundation. The current listener accepts version 1 only;
no setting, source driver or deployment enables reserved connections yet.

The `transport` package provides:

- `SignReservation` for a version-2 ticket with type `rabbit-connect-reservation+jwt`.
- `VerifyReservationData` for a data ticket with no parent digest.
- `VerifyReservationAuxiliary` for a ticket bound to an exact verified data open.
- `ReplayRegistry.ConsumeReservation`, sharing version 1's issuer/audience/JTI
  namespace and capacity. A version change cannot bypass replay tracking.

An auxiliary ticket signs `parent_open_sha256`. Its source, revision, execution,
tunnel, control owner and worker certificate must match the parent. Its JTI must
be new. Its session lasts at most 15 seconds and cannot outlive the parent
session or either verified certificate chain. The parent's admission deadline
may have passed while its session remains live.

Verification proves signed scope. The caller must still check live authority,
route ownership, parent custody and admission for both transport sockets before
consuming the ticket. It does not reserve sockets or track cleanup.

The separate [dormant accounting package](private-reservation-accounting.md)
tracks four-slot parent reservations and exact socket/setup joins. No listener
uses that ledger yet.

An opaque auxiliary connection provides bounded access to the same source. It
does not prove the bytes are a PostgreSQL cancellation request. A trusted parent
must construct that request if cancellation-only bytes are required. With source
TLS in the child, a child-reported backend key is not independently verified
provenance; PostgreSQL still validates its cancellation secret.

Runtime activation needs socket/handshake reservations, issuer admission, a
parent-owned cancellation handle, verified cleanup and real saturation tests.
