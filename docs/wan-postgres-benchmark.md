# PostgreSQL over a real WAN

All **26 queries passed** complete Arrow, row and value checks. Ten concurrent exports returned 30 million rows in 290.24 seconds. These measurements describe this workload; they do not establish a transport speedup or production capacity.

Route: PostgreSQL and Rabbit client on macOS → verified TLS/TCP WAN → Rabbit server and Kelvo on Linux. Native PostgreSQL TLS remains intact inside the tunnel.

## Results

| Scenario | Returned rows | Wall time | Aggregate returned rows/s |
| --- | ---: | ---: | ---: |
| Five analytical queries, serial | 470 | 30.60 s | — |
| Ten analytical queries, concurrent | 940 | 17.37 s | — |
| One raw export | 3,000,000 | 43.08 s | 69,632 |
| Ten concurrent raw exports | 30,000,000 | 290.24 s | 103,364 |

The source contains **3M synthetic trips across six PostgreSQL tables**, not public NYC Taxi data. Parallel exports read the same fixture ten times. Analytical queries return aggregates, so their returned rows/s would misrepresent the work performed.

Single/parallel raw exports produced **3.745 / 5.559 MB/s of Arrow output**, while Rabbit copied **7.275 / 10.799 MB/s of native PostgreSQL TLS payload**. Payload counters include authentication, SQL and results; they exclude outer Rabbit TLS, control messages, TCP/IP and retransmissions. All 26 campaign streams reconciled successfully.

## Measurement scope

- PostgreSQL executes five CTE/join workflows; Kelvo streams Arrow. Federation and acceleration are outside this test.
- Each query starts a fresh CLI/worker: no compression, default batch target, one requested thread, 256 MB engine budget.
- Timing includes startup, source execution, WAN transfer and output/fsync. Validation runs afterward.
- Warm source caches, one run per scenario. No direct-WAN baseline, first-row metric or repeated-trial interval.

Rabbit server RSS peaked at **27.0–28.4 MiB**; client peaks were **13.8–18.4 MiB**. Ten exports reached **1,310.5 MiB summed Kelvo RSS** and **1,697.5 MiB charged cgroup memory**. RSS can double-count shared mappings; cgroup memory includes harness/output page cache. Samples can miss peaks. No cgroup OOM kills occurred. The engine budget is not a process limit, and hard CPU/RAM limits were not captured; these results do not establish 1 GB VM capacity.

## Try the workload

Point `FIXTURE_ADMIN_DSN` at a fresh dedicated database named `rabbit_wan_<suffix>`:

```sh
psql "$FIXTURE_ADMIN_DSN" -v stage_rows=3000000 -f scripts/wan_postgres_workload.sql
```

The [SQL file](../scripts/wan_postgres_workload.sql) contains labeled queries. See [transport validation](transport-validation.md) for fixtures and [loopback measurements](transport-performance.md) for controlled comparisons.

[Evidence](evidence/rabbit-wan-20261008.json) records bytes, resource scopes and source/binary/workload hashes. Only the SQL's stale preparation comment changed before publication.

A separate [Kelvo cancellation fix](https://github.com/SyneHQ/kelvo-go/commit/d68ff4cc472682974438fe30aa591b892c4fe91d) passed Linux/race tests and delayed TLS cancellation. In the live CLI test, a 10-second timeout stopped its source by 11.69 seconds while an unrelated query completed correctly. These throughput figures use the earlier binary; the fix is qualified separately.

The fixed binary also revalidated all 3M exported rows in **60.17 s** and all five analyses in **35.21 s**, with live 3-CPU/5-GiB limits recorded. These unpaired WAN samples show timing variation; they do not establish a causal performance change.
