package transport

import (
	"container/heap"
	"errors"
	"sync"
	"time"
)

var (
	ErrReplay   = errors.New("private transport open was already consumed")
	ErrCapacity = errors.New("private transport replay registry is full")
)

// ReplayRegistry consumes authenticated opens atomically within one process.
// It never evicts an unexpired ticket to admit another. Call Consume only after
// verifying current route ownership and obtaining the first live authority lease.
// Restart safety requires each ticket to bind the current control-owner generation;
// this registry does not provide distributed routing or cross-process ownership.
type ReplayRegistry struct {
	mu      sync.Mutex
	limit   int
	entries map[string]struct{}
	expires expiryQueue
}

func NewReplayRegistry(limit int) (*ReplayRegistry, error) {
	if limit < 1 || limit > 1_000_000 {
		return nil, ErrCapacity
	}
	return &ReplayRegistry{limit: limit, entries: make(map[string]struct{})}, nil
}

func (r *ReplayRegistry) Consume(v VerifiedOpen, now time.Time) error {
	if r == nil || v.digest == "" || validateClaims(v.claims, now) != nil || !now.Before(v.peerUntil) {
		return ErrAuthority
	}
	return r.consume(v.claims, now)
}

// ConsumeReservation shares the version-1 replay namespace and capacity. Call
// only after live authority, parent custody and both-socket admission succeed.
func (r *ReplayRegistry) ConsumeReservation(v VerifiedReservation, now time.Time) error {
	if r == nil || v.digest == "" || validateReservationClaims(v.claims, now) != nil || !now.Before(v.peerUntil) {
		return ErrAuthority
	}
	return r.consume(v.claims.OpenClaims, now)
}

func (r *ReplayRegistry) consume(claims OpenClaims, now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for len(r.expires) > 0 && r.expires[0].until <= now.Unix() {
		item := heap.Pop(&r.expires).(expiryEntry)
		delete(r.entries, item.key)
	}
	key := claims.Issuer + "\x00" + claims.Audience + "\x00" + claims.ID
	if _, exists := r.entries[key]; exists {
		return ErrReplay
	}
	if len(r.entries) >= r.limit {
		return ErrCapacity
	}
	r.entries[key] = struct{}{}
	heap.Push(&r.expires, expiryEntry{key: key, until: claims.ExpiresAt})
	return nil
}

type expiryEntry struct {
	key   string
	until int64
}

type expiryQueue []expiryEntry

func (q expiryQueue) Len() int           { return len(q) }
func (q expiryQueue) Less(i, j int) bool { return q[i].until < q[j].until }
func (q expiryQueue) Swap(i, j int)      { q[i], q[j] = q[j], q[i] }
func (q *expiryQueue) Push(value any)    { *q = append(*q, value.(expiryEntry)) }
func (q *expiryQueue) Pop() any {
	last := len(*q) - 1
	value := (*q)[last]
	(*q)[last] = expiryEntry{}
	*q = (*q)[:last]
	return value
}
