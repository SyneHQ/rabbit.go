# Transport validation

Use Linux and Go 1.26.8. The repository has separate `client` and `server` modules.
The [validation workflow](../.github/workflows/ci.yml) builds both and runs normal,
race and vet checks with an actual sibling client process.

## Local fixture run

Start bounded, disposable PostgreSQL and Redis fixtures in one terminal:

```sh
python3 -m unittest discover -s scripts -p 'test_transport_fixtures.py' -v
python3 scripts/transport_fixtures.py serve /tmp/rabbit-fixtures --max-seconds 2700
```

The directory must be empty and owned by you. Use `--sudo-docker` if only Docker
needs sudo. The controller publishes a `fixtures.json` environment map. It uses
pinned images, Unix sockets, no container network and no persistent database volume.

In a second Bash terminal, load the fixture environment and build the client:

```bash
set -euo pipefail
while IFS='=' read -r name value; do
  export "$name=$value"
done < <(python3 - <<'PY'
import json
with open('/tmp/rabbit-fixtures/fixtures.json', encoding='utf-8') as source:
    environment = json.load(source)
for name in ('SECURITY_TEST_DATABASE_URL', 'RABBIT_TRANSPORT_DATABASE_URL', 'RABBIT_TRANSPORT_REDIS_URL'):
    print(name + '=' + environment[name])
PY
)
(cd client && go build -o /tmp/rabbit-client .)
export RABBIT_DATABASE_CLIENT_TEST_BINARY=/tmp/rabbit-client
export RABBIT_RUNTIME_CLIENT_TEST_BINARY=/tmp/rabbit-client
(cd server && go test -p 2 -json -count=1 -timeout=10m ./...) | tee /tmp/rabbit-tests.jsonl
python3 - <<'PY'
import json
with open('/tmp/rabbit-tests.jsonl', encoding='utf-8') as source:
    events = [json.loads(line) for line in source]
required = {'TestNativeDatabaseTransport', 'TestRuntimeClientTLSIntegration',
            'TestRealMetadataMembership', 'TestAtomicScopedRevocationRetainsHistory',
            'TestStreamAccountingPreservesTunnelSession'}
passed = {event.get('Test') for event in events if event.get('Action') == 'pass'}
if missing := required - passed:
    raise SystemExit('Required fixture checks did not pass: ' + ', '.join(sorted(missing)))
print('Required native fixture checks passed')
PY
(cd server && go test -p 2 -race -count=1 -timeout=10m ./...)
```

Stop the controller with SIGTERM and wait for it. Accept the run only when
`cleanup.json` says `complete: true`. Cleanup verifies ownership and removes exact
fixture container IDs. Never point these tests at production metadata.

## Throughput comparison

```sh
(cd server && go test -run='^$' -bench='^BenchmarkNativeDatabaseTransport$' \
  -benchtime=5x -count=1 -timeout=15m ./internal/server)
```

The harness compares direct TCP, verified TLS and Rabbit for 1 KiB and 64 MiB
payloads at 1 and 10 concurrent streams. It checks exact lengths, SHA-256 and
bidirectional half-close. Dial, first-byte and transfer durations are separate.
Warmup is excluded; fixed iterations are capped at 25.

Use the same harness on both revisions. Alternate baseline/candidate order, record
source and binary hashes, and run under identical CPU and memory limits. Keep
failures and regressions in the results. Deadline microbenchmarks measure runtime
calls and allocations; they are not network or SQL throughput measurements.

## Evidence limits

The native transport harness uses an opaque loopback payload source. It includes
metadata work and client dispatch but does not measure source query execution,
WAN loss, WAN latency or a deployment's long-running capacity.

External notebook authority and Python helper checks require their own fixtures.
A skipped test is not a passed release gate. To run the optional Kelvo/PostgreSQL gate, also set:

```sh
export RABBIT_KELVO_TEST_BINARY=/path/to/kelvo
export RABBIT_KELVO_TEST_PYTHON=/path/to/pyarrow-venv/bin/python
(cd server && go test -run '^TestKelvoPostgresThroughRabbit$' -count=1 -timeout=10m ./internal/server)
```

It checks one million synthetic rows and a CTE through direct and tunneled paths.
See [measured results and limits](transport-performance.md).
