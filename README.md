# Rabbit

Private TCP tunnels for databases and local services. Built by **SYNEHQ**.

![Rabbit](assets/img/banner.png)

Run the client beside a database on a customer's laptop, private server or VPS.
It opens outbound TLS connections to your Rabbit server. Kelvo or another database
client connects to an assigned port on that server using the original database protocol.

```text
Kelvo / database client
        |
        | private database ingress (loopback by default)
        v
Rabbit server  <====== verified TLS 1.3 ======  Rabbit client --> private database
              outbound connections from the customer's machine
```

Rabbit forwards bytes. Query execution, database authentication and connection
pooling stay with the database client. Database TLS can remain enabled inside the tunnel.

## Start a tunnel

Build with Go 1.26.8 from the repository root:

```sh
(cd server && go build -o ../rabbit-server .)
(cd client && go build -o ../rabbit-client .)
```

Configure the server's metadata PostgreSQL and Redis connections, server certificate
and management credential through your secret manager or service environment:

```sh
# Required: DATABASE_URL, REDIS_URL, RABBIT_SERVICE_TOKEN (at least 32 characters)
export RABBIT_TLS_CERT_FILE=/etc/rabbit/server.crt
export RABBIT_TLS_KEY_FILE=/etc/rabbit/server.key
export ENVIRONMENT=production

./rabbit-server server --bind 0.0.0.0 --port 9999 \
  --tunnel-bind 127.0.0.1 --api-bind 127.0.0.1 --api-port 8080
```

Initialize metadata before starting the server. New deployments can use Rabbit's
standalone teams; existing application deployments can retain their current identity
adapter. Select the mode explicitly and follow the [identity guide](docs/standalone-identity.md).

Issue a team-scoped tunnel token through the authenticated management API, then
start the client on the machine that can reach the database:

```sh
# Set RABBIT_TOKEN through your service's secret environment.
./rabbit-client tunnel --server rabbit.example.com:9999 \
  --local-port 5432 --max-connections 64 --max-retries 0
```

Use `--ca-file /etc/rabbit/ca.pem` for a private CA. Point Kelvo's native database
connector at the assigned Rabbit ingress port, retaining the database credentials
and verified database TLS settings. The tunnel token is separate from those credentials.

## Operating limits

- Database ingress and management API bind to loopback by default. For separate
  workers, select a private ingress IP and restrict access to those workers.
- The client allows 64 simultaneous streams by default. New peers reject excess
  requests explicitly; older peers use the pairing timeout. Reconnects do not replay queries.
- TLS session reuse reduces repeated handshakes. Traffic stays encrypted and
  certificate verification remains enabled.
- Idle deadline updates are coalesced; explicit deadlines remain upper bounds.
- Active queries can fail during disconnection. Application retries must account
  for whether a write already committed.

## Documentation

| Topic | Guide |
| --- | --- |
| Private databases, Kelvo and secure deployment | [Transport guide](docs/private-database-transport.md) |
| Metadata setup, teams and identity compatibility | [Identity configuration](docs/standalone-identity.md) |
| Admission limits, timeouts and operator statistics | [Operator configuration](docs/operator-limits.md) |
| Client flags, trust and reconnect behavior | [Client usage](client/TUNNEL_CLIENT_USAGE.md) |
| Control channel and database stream lifecycle | [Architecture](TUNNEL_SYSTEM_SUMMARY.md) |
| Measured transport overhead | [Before and after](docs/transport-performance.md) |
| Tests, benchmarks and evidence limits | [Transport validation](docs/transport-validation.md) |
| Notebook runtime protocol | [Runtime transport](docs/notebook-runtime-v2-transport.md) |
| Notebook launcher | [Runtime launcher](docs/notebook-runtime-launcher.md) |

Performance depends on the source database, network, row encoding and concurrency.
Loopback transport results do not establish WAN throughput or production capacity.

## Contribute

Changes should preserve database bytes, tenant boundaries, cancellation and
half-close behavior. Run both Go modules' tests, race detector and vet; include
reproducible measurements for performance changes. See the validation guide.

[MIT license](LICENSE).
