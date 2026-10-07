# Rabbit client

Run beside the private database. `--local-port` connects to loopback on this machine.

```sh
# Supply RABBIT_TOKEN through a secret environment.
./rabbit-client tunnel --server rabbit.example.com:9999 \
  --local-port 5432 --max-connections 64 --max-retries 0
```

| Flag | Default | Purpose |
| --- | --- | --- |
| `--server` | Required explicitly | Rabbit control address; omitted port means 9999 |
| `--local-port` | `5432` | Private service's local TCP port |
| `--token` | `RABBIT_TOKEN` | Tunnel credential; prefer the environment over command-line history |
| `--ca-file` | System trust | PEM CA file for private server certificates |
| `--server-name` | Server hostname | Expected certificate identity when dialing an IP or alias |
| `--max-connections` | `64` | Simultaneous streams, 1–4096 |
| `--timeout` | `10s` | Connection and control-write timeout |
| `--max-retries` | `10` | Reconnect attempts; 0 retries indefinitely |
| `--initial-delay` / `--max-delay` | `1s` / `60s` | Exponential retry delay bounds |
| `--health-interval` | `30s` | Control heartbeat interval |

## Trust and rotation

TLS verification is always enabled for remote servers. A custom CA must be a
regular file of at most 1 MiB; symlinks, pipes and devices are rejected. Rotate it
by atomically replacing the file. The client rereads it before dialing and drops
its TLS session cache when the contents change. Restart after changing system roots.

`--insecure-local` permits plaintext only to a literal loopback IP for development.
The server must separately enable its local development exception. Do not use it
for customer database access across machines.

The separate legacy SSH helper uses `~/.ssh/known_hosts` by default, or the
`SSHKnownHostsPath` configuration field. Verify host fingerprints independently;
unknown or changed keys fail closed.

## Disconnects and overload

Ctrl+C closes active sockets and stops reconnecting. The control session expires
when incoming control traffic stops; active CONNECT traffic also proves liveness.

When the stream limit is reached, new CONNECT requests expire through the server's
pairing timeout. Established streams continue. Bound the database client's pool to
fit this limit and the source database's connection budget.

Rabbit does not retry SQL or preserve transactions across reconnects. Retry queries
at the application layer only when their semantics allow it.
