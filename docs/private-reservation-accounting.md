# Reservation accounting

Operator configuration cannot enable this path. Construction-only listener tests
exercise the shared ledger; the production listener still accepts version 1 only.

One process ceiling covers ordinary sockets, a fixed anonymous handshake
partition, and four slots per parent: private ingress, DATA, and an auxiliary pair.
Ordinary traffic cannot consume an existing parent's reserve.

The trusted server owns this lifecycle:

1. `Accept` allocates an anonymous setup slot with a fixed deadline.
2. Validate live route ownership and authority before `AdmitData` or `AdmitAuxiliary`.
3. Attach the exact capability's DATA socket; call `SetupJoined` after pairing work ends.
4. Call `BeginTermination` before closing data. The grace deadline cannot move later.
5. Poll `Cleanup`; close its sockets and join its pending setup work.
6. Call each socket's `Joined` only after physical closure and its work have finished.

Timeouts fence admission. They never release unconfirmed sockets or pending
capabilities. Duplicate completion calls do not change accounting. Failed or
replayed opens leave the original parent intact; close only their new ingress.

Data EOF retains the auxiliary reserve during the bounded termination window.
Authority must remain live. Revocation closes admission immediately. Releasing
network capacity does not prove remote SQL stopped or release execution quota.

Individual admissions and joins touch only their own parent. Explicit maintenance
scans the bounded registry and must continue during drain until all joins finish.
The ledger has no background goroutines or networking. The middleware
adapter binds each allocation to its accepted socket, defers ordinary per-IP
checks until classification, and retains DATA handoff owners until they join.
Its construction-only mode rejects legacy admission and mismatched ceilings.

Control/DATA, private CONNECT and assigned ports share that admission path.
DATA transfers a separate work owner; handler return does not release its slot.
Pairing joins the DATA handler before acknowledging setup. Shutdown keeps custody
of pending closes and relay work. Notebook routing is refused in this test mode.

Activation still requires version-2 listener/authority wiring, bounded issuer
admission before dialing, and native PostgreSQL cancellation tests at saturation.
Anonymous handshake capacity cannot guarantee availability during a hostile flood.
