# Management API TLS

Set both variables to enable TLS 1.3 on the management API port:

```sh
RABBIT_API_TLS_CERT_FILE=/etc/rabbit/api/server.pem
RABBIT_API_TLS_KEY_FILE=/etc/rabbit/api/server-key.pem
```

Use a certificate whose SAN matches the hostname used by callers. Give clients its CA certificate. Keep the key readable only by the service's user or dedicated group.

Missing or invalid TLS material stops startup. Plain HTTP and TLS 1.2 requests cannot reach management handlers when TLS is enabled. Service-token and team-membership checks still apply.

Use `https://rabbit:3422` with a certificate for `rabbit` on private service networks. Configure HTTP health probes to use HTTPS, or use a private TCP readiness probe and perform authenticated HTTPS acceptance separately.

If both variables are absent, the existing HTTP API behavior remains available for loopback access or an existing TLS reverse proxy. Keep this listener private. Management TLS does not change the control listener or private CONNECT listener.
