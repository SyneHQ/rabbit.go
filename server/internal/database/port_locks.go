package database

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

var releasePortLock = redis.NewScript(`
if redis.call("GET", KEYS[1]) == ARGV[1] then
    return redis.call("DEL", KEYS[1])
end
return 0
`)

func portLockKey(port int) string { return fmt.Sprintf("port_lock:%d", port) }

// TryPortLock reports contention separately from a Redis failure.
func (d *Database) TryPortLock(ctx context.Context, port int, owner uuid.UUID, expiration time.Duration) (bool, error) {
	if port < 1 || port > 65535 || owner == uuid.Nil || expiration <= 0 {
		return false, fmt.Errorf("invalid port lock")
	}
	return d.Redis.SetNX(ctx, portLockKey(port), owner.String(), expiration).Result()
}

// ReleasePortLock cannot remove a replacement lease after expiry or contention.
func (d *Database) ReleasePortLock(ctx context.Context, port int, owner uuid.UUID) (bool, error) {
	if port < 1 || port > 65535 || owner == uuid.Nil {
		return false, fmt.Errorf("invalid port lock")
	}
	removed, err := releasePortLock.Run(ctx, d.Redis, []string{portLockKey(port)}, owner.String()).Int64()
	return removed == 1, err
}
