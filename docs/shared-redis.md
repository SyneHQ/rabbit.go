# Shared Redis

Set `RABBIT_REDIS_KEY_PREFIX=rabbit:production:` through deployment configuration.
Rabbit uses `rabbit:production:session:<uuid>` and `rabbit:production:port_lock:<port>`.
An empty value preserves existing `session:*` and `port_lock:*` keys.

Prefixes must contain 2–128 ASCII letters, digits, colons, underscores or hyphens.
Start with a letter or digit and end with a colon. Glob patterns and escapes are rejected before database connections start.

1. Create a dedicated Redis ACL user. Allow only `~rabbit:production:*` and the commands below.
2. Store `rediss://<user>:<password>@<verified-host>:6379/0` in `REDIS_URL`. Mount the CA through `SSL_CERT_FILE` when needed.
3. Give all replicas sharing Rabbit metadata the same prefix. Use separate prefixes for independent installations.
4. Verify token allocation, session creation and revocation before moving traffic. Keep the prior Redis configuration until verification passes.

Required commands: `PING`, `HELLO`, `AUTH`, `SET`, `GET`, `DEL`, `EVAL`, `EVALSHA`.
Allow `CLIENT SETINFO` for client identification. Add `CLIENT SETNAME` only when the URL sets `client_name`.
The lock-release script needs `GET` and `DEL` on the same permitted keys.

A nonzero URL database index also needs `SELECT`. Database numbers are not ACL boundaries.
Restrict every application's Redis user: a user with `~*` can still access Rabbit's keys.
Do not grant `KEYS`, `SCAN`, `FLUSHDB`, `FLUSHALL`, `CONFIG`, or ACL administration to Rabbit.

Changing the prefix does not migrate cached sessions or advisory locks. Coordinate the change across replicas.
PostgreSQL retains tokens, session history and authoritative port reservations. Old session keys expire after 24 hours; allocation locks expire after 10 minutes.
Do not delete unrelated Redis keys. Shared Redis still shares memory, eviction policy and availability.
