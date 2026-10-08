package database

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

func allocatorFixture(t *testing.T) (*Database, context.Context) {
	t.Helper()
	db, ctx := ownedIdentityDatabase(t)
	// The disposable PostgreSQL fixture has 32 slots. Leave room for its
	// administrator and the competing writer used by the conflict test.
	db.DB.SetMaxOpenConns(16)
	db.DB.SetMaxIdleConns(16)
	if err := db.RunMigrations("migrations.sql"); err != nil {
		t.Fatal(err)
	}
	if err := db.BootstrapTeam(ctx, "allocator", "Allocator fixture", "owner"); err != nil {
		t.Fatal(err)
	}
	return db, ctx
}

func cleanupTestPortLock(t *testing.T, db *Database, port int, owner uuid.UUID) {
	t.Helper()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if _, err := db.ReleasePortLock(ctx, port, owner); err != nil {
			t.Errorf("remove owned fixture port lock: %v", err)
		}
	})
}

func TestPortLockHasOneOwnerAndRejectsStaleCleanup(t *testing.T) {
	db, ctx := ownedIdentityDatabase(t)
	const port = 64001
	const contenders = 32
	type result struct {
		owner uuid.UUID
		won   bool
		err   error
	}
	start := make(chan struct{})
	results := make(chan result, contenders)
	owners := make([]uuid.UUID, contenders)
	for i := range owners {
		owners[i] = uuid.New()
		cleanupTestPortLock(t, db, port, owners[i])
		go func(owner uuid.UUID) {
			<-start
			won, err := db.TryPortLock(ctx, port, owner, time.Minute)
			results <- result{owner, won, err}
		}(owners[i])
	}
	close(start)
	var winner uuid.UUID
	successes := 0
	for range contenders {
		got := <-results
		if got.err != nil {
			t.Errorf("acquire port lock: %v", got.err)
		}
		if got.won {
			winner = got.owner
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("expected one lock owner, got %d", successes)
	}
	for _, owner := range owners {
		if owner == winner {
			continue
		}
		if removed, err := db.ReleasePortLock(ctx, port, owner); err != nil || removed {
			t.Fatalf("losing contender released winning lease: removed=%v err=%v", removed, err)
		}
	}
	if got, err := db.Redis.Get(ctx, portLockKey(port)).Result(); err != nil || got != winner.String() {
		t.Fatal("winning lease changed after losing cleanup")
	}
	if removed, err := db.ReleasePortLock(ctx, port, winner); err != nil || !removed {
		t.Fatalf("owner could not release lease: %v %v", removed, err)
	}
	replacement := uuid.New()
	cleanupTestPortLock(t, db, port, replacement)
	if won, err := db.TryPortLock(ctx, port, replacement, time.Minute); err != nil || !won {
		t.Fatalf("replacement could not acquire lease: %v %v", won, err)
	}
	if removed, err := db.ReleasePortLock(ctx, port, winner); err != nil || removed {
		t.Fatalf("stale owner released replacement lease: %v %v", removed, err)
	}
	if got, err := db.Redis.Get(ctx, portLockKey(port)).Result(); err != nil || got != replacement.String() {
		t.Fatal("replacement lease was lost")
	}
}

func TestPortAllocationConcurrentTokensRemainUnique(t *testing.T) {
	db, ctx := allocatorFixture(t)
	const contenders = 32
	type result struct {
		token *TeamToken
		port  *PortAssignment
		err   error
	}
	start := make(chan struct{})
	results := make(chan result, contenders)
	service := NewService(db)
	for i := range contenders {
		go func(i int) {
			<-start
			token, port, err := service.GenerateTokenForTeam(ctx, "allocator", fmt.Sprintf("token-%d", i), "", nil)
			results <- result{token, port, err}
		}(i)
	}
	close(start)
	ports := make(map[int]bool)
	tokens := make(map[uuid.UUID]bool)
	for range contenders {
		got := <-results
		if got.err != nil {
			t.Errorf("concurrent token allocation: %v", got.err)
			continue
		}
		cleanupTestPortLock(t, db, got.port.Port, got.token.ID)
		if ports[got.port.Port] || tokens[got.token.ID] || got.port.TokenID != got.token.ID || !got.port.IsReserved {
			t.Error("allocation returned duplicate or unbound token/port")
		}
		ports[got.port.Port], tokens[got.token.ID] = true, true
	}
	if len(ports) != contenders || len(tokens) != contenders {
		t.Fatalf("expected %d distinct allocations, got %d ports/%d tokens", contenders, len(ports), len(tokens))
	}
	var count int
	if err := db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM port_assignments p JOIN team_tokens t ON p.token_id=t.id WHERE p.is_reserved AND t.is_active`).Scan(&count); err != nil || count != contenders {
		t.Fatalf("committed reservations do not match results: %d %v", count, err)
	}
	for port := range ports {
		if exists, err := db.Redis.Exists(ctx, portLockKey(port)).Result(); err != nil || exists != 0 {
			t.Fatalf("successful allocation retained advisory lock: port=%d err=%v", port, err)
		}
	}
}

// Observe real SET NX replies; fault injection never replaces Redis semantics.
type allocatorRedisHook struct {
	attempts atomic.Int32
	after    func(context.Context, int, uuid.UUID) error
}

func (*allocatorRedisHook) DialHook(next redis.DialHook) redis.DialHook { return next }
func (*allocatorRedisHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}
func (h *allocatorRedisHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		args := cmd.Args()
		value, isBool := cmd.(*redis.BoolCmd)
		isLock := isBool && cmd.Name() == "set" && len(args) >= 3 && strings.HasPrefix(fmt.Sprint(args[1]), "port_lock:")
		if isLock {
			h.attempts.Add(1)
		}
		if err := next(ctx, cmd); err != nil {
			return err
		}
		if !isLock || !value.Val() || h.after == nil {
			return nil
		}
		port, err := strconv.Atoi(strings.TrimPrefix(fmt.Sprint(args[1]), "port_lock:"))
		if err != nil {
			return err
		}
		owner, err := uuid.Parse(fmt.Sprint(args[2]))
		if err != nil {
			return err
		}
		return h.after(ctx, port, owner)
	}
}

func TestPortAllocationRetriesPostgresReservationConflict(t *testing.T) {
	db, ctx := allocatorFixture(t)
	competitor := uuid.New()
	if _, err := db.DB.ExecContext(ctx, `INSERT INTO team_tokens(id,team_id,token,name) VALUES($1,'allocator',$2,'competitor')`, competitor, uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	var conflicted int
	hook := &allocatorRedisHook{after: func(ctx context.Context, port int, _ uuid.UUID) error {
		if conflicted != 0 {
			return nil
		}
		conflicted = port
		// Another writer can reserve a port after the allocator's SELECT, for
		// example after Redis loses a lease. PostgreSQL must decide the winner.
		_, err := db.DB.ExecContext(ctx, `INSERT INTO port_assignments(team_id,token_id,port,protocol,is_reserved) VALUES('allocator',$1,$2,'tcp',true)`, competitor, port)
		return err
	}}
	db.Redis.AddHook(hook)
	token, port, err := NewService(db).GenerateTokenForTeam(ctx, "allocator", "retried", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	cleanupTestPortLock(t, db, port.Port, token.ID)
	if conflicted == 0 || port.Port == conflicted || hook.attempts.Load() != 2 {
		t.Fatalf("reservation conflict was not retried once: port=%d conflicted=%d attempts=%d", port.Port, conflicted, hook.attempts.Load())
	}
	var count int
	if err := db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM team_tokens`).Scan(&count); err != nil || count != 2 {
		t.Fatal("retry left an extra or missing token")
	}
	if err := db.DB.QueryRowContext(ctx, `SELECT COUNT(DISTINCT port) FROM port_assignments WHERE is_reserved`).Scan(&count); err != nil || count != 2 {
		t.Fatal("PostgreSQL reservation uniqueness was not preserved")
	}
	for _, p := range []int{port.Port, conflicted} {
		if exists, err := db.Redis.Exists(ctx, portLockKey(p)).Result(); err != nil || exists != 0 {
			t.Fatal("retry left an advisory lock")
		}
	}
}

func TestPortAllocationFailedInsertCannotReleaseReplacementLease(t *testing.T) {
	db, ctx := allocatorFixture(t)
	if _, err := db.DB.ExecContext(ctx, `ALTER TABLE port_assignments ADD CONSTRAINT allocator_fixture_reject CHECK(port < 10000)`); err != nil {
		t.Fatal(err)
	}
	replacement := uuid.New()
	var acquired int
	hook := &allocatorRedisHook{after: func(ctx context.Context, port int, _ uuid.UUID) error {
		acquired = port
		// Simulate lease expiry/reacquisition before a failed SQL insert.
		return db.Redis.Set(ctx, portLockKey(port), replacement.String(), time.Minute).Err()
	}}
	db.Redis.AddHook(hook)
	_, _, err := NewService(db).GenerateTokenForTeam(ctx, "allocator", "failed", "", nil)
	if acquired != 0 {
		cleanupTestPortLock(t, db, acquired, replacement)
	}
	if err == nil || acquired == 0 || hook.attempts.Load() != 1 {
		t.Fatalf("fixture did not reject its acquired candidate: %v", err)
	}
	var count int
	if err := db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM team_tokens`).Scan(&count); err != nil || count != 0 {
		t.Fatal("failed allocation retained its token")
	}
	if got, err := db.Redis.Get(ctx, portLockKey(acquired)).Result(); err != nil || got != replacement.String() {
		t.Fatal("failed allocation cleanup deleted a replacement lease")
	}
}

func TestPortAllocationCancellationReleasesOwnedLease(t *testing.T) {
	db, fixtureCtx := allocatorFixture(t)
	ctx, cancel := context.WithCancel(fixtureCtx)
	defer cancel()
	var acquired int
	var owner uuid.UUID
	db.Redis.AddHook(&allocatorRedisHook{after: func(_ context.Context, port int, id uuid.UUID) error {
		acquired, owner = port, id
		cancel()
		return nil
	}})
	_, _, err := NewService(db).GenerateTokenForTeam(ctx, "allocator", "cancelled", "", nil)
	if acquired != 0 {
		cleanupTestPortLock(t, db, acquired, owner)
	}
	if !errors.Is(err, context.Canceled) || acquired == 0 {
		t.Fatalf("allocation did not preserve cancellation: %v", err)
	}
	if exists, err := db.Redis.Exists(fixtureCtx, portLockKey(acquired)).Result(); err != nil || exists != 0 {
		t.Fatal("cancelled request stranded its advisory lease")
	}
	var count int
	if err := db.DB.QueryRowContext(fixtureCtx, `SELECT COUNT(*) FROM team_tokens`).Scan(&count); err != nil || count != 0 {
		t.Fatal("cancelled allocation retained its token")
	}
}

func TestPortAllocationLostRedisReplyReleasesOnlyItsLease(t *testing.T) {
	db, ctx := allocatorFixture(t)
	lostReply := errors.New("fixture lost acquisition reply")
	var acquired int
	var owner uuid.UUID
	db.Redis.AddHook(&allocatorRedisHook{after: func(_ context.Context, port int, id uuid.UUID) error {
		acquired, owner = port, id
		return lostReply
	}})
	_, _, err := NewService(db).GenerateTokenForTeam(ctx, "allocator", "lost-reply", "", nil)
	if acquired != 0 {
		cleanupTestPortLock(t, db, acquired, owner)
	}
	if !errors.Is(err, lostReply) || acquired == 0 {
		t.Fatalf("allocation did not preserve the failed reply: %v", err)
	}
	if exists, err := db.Redis.Exists(ctx, portLockKey(acquired)).Result(); err != nil || exists != 0 {
		t.Fatal("failed acquisition reply stranded its advisory lease")
	}
	var count int
	if err := db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM team_tokens`).Scan(&count); err != nil || count != 0 {
		t.Fatal("failed acquisition reply retained its token")
	}
}

func TestPortAllocationContentionIsBounded(t *testing.T) {
	db, ctx := allocatorFixture(t)
	owner := uuid.New()
	for port := firstTunnelPort; port < firstTunnelPort+portAllocationAttempts; port++ {
		won, err := db.TryPortLock(ctx, port, owner, time.Minute)
		if err != nil || !won {
			t.Fatalf("fixture requires unused Redis port locks: %v %v", won, err)
		}
		cleanupTestPortLock(t, db, port, owner)
	}
	hook := &allocatorRedisHook{}
	db.Redis.AddHook(hook)
	_, _, err := NewService(db).GenerateTokenForTeam(ctx, "allocator", "contended", "", nil)
	if !errors.Is(err, errPortAllocationBusy) || int(hook.attempts.Load()) != portAllocationAttempts {
		t.Fatalf("contention exceeded its attempt budget: attempts=%d err=%v", hook.attempts.Load(), err)
	}
	var count int
	if err := db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM team_tokens`).Scan(&count); err != nil || count != 0 {
		t.Fatal("exhausted allocation retained its token")
	}
	for port := firstTunnelPort; port < firstTunnelPort+portAllocationAttempts; port++ {
		if got, err := db.Redis.Get(ctx, portLockKey(port)).Result(); err != nil || got != owner.String() {
			t.Fatal("contending allocation changed another owner's lease")
		}
	}
}
