# Operator limits

Start with `rabbit.go server --config rabbit.yml`. Environment settings override YAML. Missing settings retain the existing defaults. Invalid settings stop startup.

```yaml
security:
  max_connections: 4096
  max_connections_per_ip: 100
  max_connections_per_hour: 10000
  connection_window: 1h
  burst_threshold: 10000
  burst_window: 1m
  handshake_timeout: 10s
  idle_timeout: 30m
  blacklist_duration: 1h
  max_violations_per_hour: 100
  trusted_networks: []
pairing_timeout: 10s
control_write_timeout: 10s
audit_queue_capacity: 1024
audit_write_timeout: 5s
audit_shutdown_timeout: 5s
```

Each setting also accepts a `RABBIT_` environment variable, such as `RABBIT_IDLE_TIMEOUT=5m`. Use `RABBIT_MAX_CONNECTIONS` for the global limit and `TRUSTED_NETWORKS` for comma-separated CIDRs. Durations must include a unit. Admission values range from 1 to 1,000,000. Security durations range from 1ms to 24h. Pairing and control-write timeouts range from 1ms to 1m.

Trusted networks bypass per-IP limits. They cannot bypass the global limit. A capacity limit is a safety ceiling, not a throughput guarantee.

New clients negotiate `busy-v1` after registration. A saturated client rejects unpaired streams on its authenticated control connection. Established streams continue. Old peers retain the pairing timeout behavior.

The YAML parser uses `gopkg.in/yaml.v3` for strict field validation and standard YAML syntax. This dependency avoids maintaining a custom configuration parser.

Stream audit logs appear after completion. Each record contains its original start/end timestamps and byte totals. A full queue drops audit records without delaying database traffic. Authorization and token revocation stay synchronous. The worker cannot reactivate stopped sessions.

Set `audit_queue_capacity: 0` to disable optional stream logs. The maximum capacity is 65,536 records. Write/shutdown timeouts range from 1ms to 1m. The corresponding environment names are `RABBIT_AUDIT_QUEUE_CAPACITY`, `RABBIT_AUDIT_WRITE_TIMEOUT` and `RABBIT_AUDIT_SHUTDOWN_TIMEOUT`.

`GET /operator/transport-stats` reports `stream_audit`: queue depth/capacity, accepted, written, dropped and failed writes. `inflight` counts active writes. `drain_complete` is true only after the writer exits. It also reports active/pending stream counts. Shutdown emits the same audit counters. These optional logs are not a durable compliance audit.

The operator endpoint is disabled by default. Set `RABBIT_OPERATOR_TOKEN` to a distinct 32–512-byte secret and send it as `X-Operator-Token`. Application and enabled notebook service tokens cannot access this endpoint. Keep the management listener on loopback or a protected private network.
