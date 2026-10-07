# Transport measurements

Rabbit reduced connection setup overhead in this test. Bulk throughput stayed
roughly unchanged. These are loopback measurements, not WAN capacity claims.

## Before and after

Rates include dialing, native client dispatch, metadata, transfer and SHA-256
verification. Each cell is the median of five run means; each run uses five waves.

| Payload per stream | Concurrent streams | Before MB/s | After MB/s |
| --- | ---: | ---: | ---: |
| 1 KiB | 1 | 0.400 | 0.539 |
| 1 KiB | 10 | 0.101 | 0.129 |
| 64 MiB | 1 | 702.4 | 706.8 |
| 64 MiB | 10 | 701.6 | 703.3 |

For 1 KiB, mean first-byte latency fell from **2.53 to 1.87 ms**
at one stream, and **70.9 to 38.8 ms** at ten streams (medians across runs).

Bulk results include regressions: paired changes ranged from **−0.7% to +3.3%**
at one stream and **−1.2% to +2.0%** at ten. This does not establish a bulk speedup.
Small-payload results were also variable: improvements ranged from 27.7–41.8%
and 23.9–72.6%, respectively. No p95 is inferred from five run means.

## Direct-path context

The same 64 MiB source and consumer also ran without Rabbit. These paths omit
Rabbit's dispatch, metadata and additional relays.

| Concurrent streams | Direct TCP MB/s | Direct verified TLS MB/s | Rabbit MB/s |
| --- | ---: | ---: | ---: |
| 1 | 1167.9 | 863.1 | 706.8 |
| 10 | 1939.7 | 1271.8 | 703.3 |

These are candidate-run medians. Direct-path rates also varied between runs;
the [evidence](evidence/rabbit-transport-20261008.json) retains all measurements.

## Kelvo and PostgreSQL

The native Kelvo CLI queried one million synthetic PostgreSQL rows directly and
through Rabbit, with verified source TLS on both paths. Both normal and race runs
checked every value, 58,823 NULLs, 977 Arrow batches and complete end-of-stream.
The 97-row CTE result also matched exactly.

One normal full-row sample took **3.953 s direct / 4.051 s through Rabbit** (+2.5%),
producing identical 48,888,192-byte Arrow files. This single ordered sample proves
compatibility; it is not a comparative performance benchmark.

## Reproduce and interpret

- Runtime: before `ecf8753`, after `0ec4292`; measured harness `283ccd7`.
- Linux x86-64, Xeon Platinum 8573C; test cgroup capped at 2 CPUs and 4 GiB.
- `GOMAXPROCS=2` per Go process. PostgreSQL: 0.5 CPU/512 MiB; Redis: 0.25 CPU/128 MiB. Both fixtures run outside the test cgroup.
- Five alternating AB/BA pairs, `-benchtime=5x -count=1`; warmup excluded. All ten runs passed byte/hash/EOF checks.
- Cgroup memory peaks include the harness and its 64 MiB corpus. They do not measure production Rabbit RSS.

Follow [transport validation](transport-validation.md) for commands. See
[deployment guidance](private-database-transport.md) for pooling, TLS and limits.
WAN loss/latency, production RSS and sustained tenant concurrency need separate
measurements. Source, client, harness and result hashes are in the evidence file.

For the Mac-to-Azure test with 3M source rows and ten concurrent exports, see
[PostgreSQL over a real WAN](wan-postgres-benchmark.md).
