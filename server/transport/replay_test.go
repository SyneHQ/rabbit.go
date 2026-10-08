package transport

import (
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestReplayConsumptionIsAtomicAndBounded(t *testing.T) {
	claims, trust, private, state, now := grantFixture(t)
	v, err := VerifyOpen(mustSign(t, claims, private), claims.Authority, trust, state, now)
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewReplayRegistry(1)
	if err != nil {
		t.Fatal(err)
	}
	var accepted, rejected atomic.Int32
	var workers sync.WaitGroup
	for range 64 {
		workers.Go(func() {
			switch err := r.Consume(v, now); {
			case err == nil:
				accepted.Add(1)
			case errors.Is(err, ErrReplay):
				rejected.Add(1)
			default:
				t.Errorf("unexpected consumption result: %v", err)
			}
		})
	}
	workers.Wait()
	if accepted.Load() != 1 || rejected.Load() != 63 {
		t.Fatal("one-use open admitted more than once")
	}
	claims.ID = strings.Repeat("a", 64)
	second, err := VerifyOpen(mustSign(t, claims, private), claims.Authority, trust, state, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Consume(second, now); !errors.Is(err, ErrCapacity) {
		t.Fatal("registry evicted a live ticket to admit another")
	}
	if err := r.Consume(v, now); !errors.Is(err, ErrReplay) {
		t.Fatal("capacity rejection forgot earlier consumption")
	}
	later := now.Add(30 * time.Second)
	claims.IssuedAt, claims.ExpiresAt = later.Unix(), later.Add(30*time.Second).Unix()
	third, err := VerifyOpen(mustSign(t, claims, private), claims.Authority, trust, state, later)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Consume(third, later); err != nil {
		t.Fatalf("expired replay state did not release capacity: %v", err)
	}
	if err := r.Consume(v, later); !errors.Is(err, ErrAuthority) {
		t.Fatal("expired old ticket became usable after pruning")
	}
	if len(r.entries) != 1 || len(r.expires) != 1 {
		t.Fatal("replay registry retained expired entries")
	}
}

func TestReplayRejectsUnverifiedAndInvalidConfiguration(t *testing.T) {
	for _, limit := range []int{-1, 0, 1_000_001} {
		if _, err := NewReplayRegistry(limit); !errors.Is(err, ErrCapacity) {
			t.Fatal("invalid capacity accepted")
		}
	}
	r, _ := NewReplayRegistry(1)
	if err := r.Consume(VerifiedOpen{}, time.Now()); !errors.Is(err, ErrAuthority) {
		t.Fatal("unverified open consumed")
	}
}
