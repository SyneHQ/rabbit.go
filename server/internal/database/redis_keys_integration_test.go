package database

import (
	"context"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

func TestRedisKeyPrefixLegacyAndIndependentNamespaces(t *testing.T) {
	base, ctx := ownedIdentityDatabase(t)
	id := uuid.New()
	owner := uuid.New()
	const port = 64991
	nonce := strings.ReplaceAll(uuid.NewString(), "-", "")
	prefixes := []string{"", "rabbit:" + nonce + ":a:", "rabbit:" + nonce + ":b:"}
	for _, prefix := range prefixes {
		db := *base
		db.redisKeyPrefix = prefix
		cleanupTestPortLock(t, &db, port, owner)
		key := prefix + "session:" + id.String()
		t.Cleanup(func() { base.Redis.Del(context.Background(), key) })
		if err := db.SetActiveSession(id, prefix); err != nil {
			t.Fatal("write namespaced session")
		}
		if got, err := db.GetActiveSession(id); err != nil || got != `"`+prefix+`"` {
			t.Fatal("read crossed a session namespace")
		}
		if ttl, err := base.Redis.TTL(ctx, key).Result(); err != nil || ttl < 23*time.Hour || ttl > 24*time.Hour {
			t.Fatal("session key or expiry changed")
		}
		if won, err := db.TryPortLock(ctx, port, owner, time.Minute); err != nil || !won {
			t.Fatal("independent namespace could not acquire the same port")
		}
		if got, err := base.Redis.Get(ctx, prefix+portLockKey(port)).Result(); err != nil || got != owner.String() {
			t.Fatal("port lock key omitted its namespace")
		}
	}
	for _, prefix := range prefixes {
		db := *base
		db.redisKeyPrefix = prefix
		if removed, err := db.ReleasePortLock(ctx, port, uuid.New()); err != nil || removed {
			t.Fatal("another owner released a namespaced lock")
		}
		if removed, err := db.ReleasePortLock(ctx, port, owner); err != nil || !removed {
			t.Fatal("owner could not release its namespaced lock")
		}
		if err := db.DeleteActiveSession(id); err != nil {
			t.Fatal("delete namespaced session")
		}
		if _, err := db.GetActiveSession(id); !errors.Is(err, redis.Nil) {
			t.Fatal("deleted session still exists")
		}
	}
	// Generic helpers use the same namespace, including counters.
	db := *base
	db.redisKeyPrefix = prefixes[1]
	key := "helper:" + nonce
	t.Cleanup(func() { base.Redis.Del(context.Background(), db.redisKey(key)) })
	if err := db.SetCache(key, "41", time.Minute); err != nil {
		t.Fatal("set namespaced cache entry")
	}
	if n, err := db.IncrementCounter(key); err != nil || n != 42 {
		t.Fatal("counter did not use the cache namespace")
	}
	if got, err := db.GetCache(key); err != nil || got != "42" {
		t.Fatal("get namespaced cache entry")
	}
	if err := db.DeleteCache(key); err != nil {
		t.Fatal("delete namespaced cache entry")
	}
	if _, err := base.Redis.Get(ctx, db.redisKey(key)).Result(); !errors.Is(err, redis.Nil) {
		t.Fatal("cache deletion left the namespaced entry")
	}
}

func TestRedisKeyPrefixRestrictedACLAllocationAndRevocation(t *testing.T) {
	admin, ctx := allocatorFixture(t)
	nonce := strings.ReplaceAll(uuid.NewString(), "-", "")
	prefix := "rabbit:" + nonce + ":"
	user := "rabbit_" + nonce
	password := uuid.NewString() + uuid.NewString()
	// This test requires the disposable administrator fixture, never a service credential.
	rules := []string{"on", ">" + password, "resetkeys", "~" + prefix + "*", "resetchannels", "-@all", "+ping", "+hello", "+auth", "+client|setinfo", "+set", "+get", "+del", "+eval", "+evalsha"}
	if err := admin.Redis.ACLSetUser(ctx, user, rules...).Err(); err != nil {
		t.Fatal("create owned Redis ACL fixture")
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if n, err := admin.Redis.ACLDelUser(cleanup, user).Result(); err != nil || n != 1 {
			t.Error("remove owned Redis ACL fixture")
		}
	})
	redisURL, err := url.Parse(os.Getenv("RABBIT_TRANSPORT_REDIS_URL"))
	if err != nil {
		t.Fatal("parse fixture Redis URL")
	}
	redisURL.User = url.UserPassword(user, password)
	postgresURL, err := url.Parse(os.Getenv("RABBIT_TRANSPORT_DATABASE_URL"))
	if err != nil {
		t.Fatal("parse fixture PostgreSQL URL")
	}
	var databaseName string
	if err := admin.DB.QueryRowContext(ctx, "SELECT current_database()").Scan(&databaseName); err != nil {
		t.Fatal("read owned PostgreSQL database name")
	}
	postgresURL.Path, postgresURL.RawPath = "/"+databaseName, ""
	db, err := NewDatabase(Config{PostgresURL: postgresURL.String(), RedisURL: redisURL.String(), RedisKeyPrefix: prefix, IdentityMode: IdentityStandalone})
	if err != nil {
		t.Fatal("initialize Rabbit with a namespaced Redis ACL")
	}
	t.Cleanup(func() { db.Close() })
	foreign := "foreign:" + nonce
	if err := admin.Redis.Set(ctx, foreign, "retained", time.Minute).Err(); err != nil {
		t.Fatal("seed foreign Redis key")
	}
	t.Cleanup(func() { admin.Redis.Del(context.Background(), foreign) })
	for _, attempt := range []func() error{
		func() error { return db.Redis.Get(ctx, foreign).Err() },
		func() error { return db.Redis.Set(ctx, foreign, "changed", time.Minute).Err() },
		func() error { return db.Redis.Del(ctx, foreign).Err() },
		func() error { return db.Redis.Eval(ctx, `return redis.call("DEL", KEYS[1])`, []string{foreign}).Err() },
		// Even a script with an allowed declared key cannot access a foreign key through ARGV.
		func() error {
			return db.Redis.Eval(ctx, `return redis.call("GET", ARGV[1])`, []string{prefix + "allowed"}, foreign).Err()
		},
	} {
		if err := attempt(); err == nil || !strings.Contains(strings.ToLower(err.Error()), "permission") && !strings.Contains(err.Error(), "NOPERM") {
			t.Fatal("narrow Redis ACL did not deny foreign access")
		}
	}
	if got, err := admin.Redis.Get(ctx, foreign).Result(); err != nil || got != "retained" {
		t.Fatal("foreign Redis key changed")
	}
	service := NewService(db)
	token, port, err := service.GenerateTokenForTeam(ctx, "allocator", "prefix fixture", "", nil)
	if err != nil {
		t.Fatal("allocate token with narrow Redis ACL")
	}
	cleanupTestPortLock(t, db, port.Port, token.ID)
	if _, err := admin.Redis.Get(ctx, prefix+portLockKey(port.Port)).Result(); !errors.Is(err, redis.Nil) {
		t.Fatal("allocator retained its advisory lock")
	}
	// Explicit EVAL checks the fallback permission even if another test cached this script.
	if n, err := releasePortLock.Eval(ctx, db.Redis, []string{prefix + portLockKey(port.Port)}, uuid.NewString()).Int64(); err != nil || n != 0 {
		t.Fatal("execute the owner-safe Lua script with narrow ACL")
	}
	// Run uses EVALSHA after the explicit EVAL has cached the script.
	for range 2 {
		if won, err := db.TryPortLock(ctx, port.Port, token.ID, time.Minute); err != nil || !won {
			t.Fatal("acquire namespaced lock with narrow ACL")
		}
		if removed, err := db.ReleasePortLock(ctx, port.Port, uuid.New()); err != nil || removed {
			t.Fatal("stale owner changed namespaced lock")
		}
		if removed, err := db.ReleasePortLock(ctx, port.Port, token.ID); err != nil || !removed {
			t.Fatal("release namespaced lock with narrow ACL")
		}
	}
	session, err := NewRepository(db).CreateConnectionSession(ctx, "allocator", token.ID, port.ID, "127.0.0.1", port.Port, "tcp")
	if err != nil {
		t.Fatal("create session with narrow Redis ACL")
	}
	t.Cleanup(func() { admin.Redis.Del(context.Background(), prefix+"session:"+session.ID.String()) })
	if _, err := db.GetActiveSession(session.ID); err != nil {
		t.Fatal("session cache did not use the permitted namespace")
	}
	if _, err := service.DeleteTunnelForTeam(ctx, "foreign", token.ID); err == nil {
		t.Fatal("foreign team revoked token")
	}
	if _, err := service.DeleteTunnelForTeam(ctx, "allocator", token.ID); err != nil {
		t.Fatal("revoke token with narrow Redis ACL")
	}
	if _, _, err := service.AuthenticateToken(ctx, token.Token); err == nil {
		t.Fatal("revoked token still authenticates")
	}
	if err := db.DeleteActiveSession(session.ID); err != nil {
		t.Fatal("delete session with narrow Redis ACL")
	}
	if _, err := admin.Redis.Get(ctx, prefix+"session:"+session.ID.String()).Result(); !errors.Is(err, redis.Nil) {
		t.Fatal("session deletion left a namespaced key")
	}
}
