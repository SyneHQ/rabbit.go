package transport

import (
	"errors"
	"sync"
	"time"
)

var (
	ErrSocketCapacity   = errors.New("private transport socket capacity is exhausted")
	ErrReservationState = errors.New("private transport reservation is not admissible")
)

// ReservationLimits partitions one process socket ceiling. Handshakes are
// charged permanently; an authenticated parent reserves four further slots for
// its data and auxiliary pairs. Ordinary sockets cannot spend either reserve.
type ReservationLimits struct {
	Sockets, Handshakes, Parents    int
	SetupTimeout, TerminationWindow time.Duration
}

// ReservationAccounting is dormant bookkeeping for trusted server owners. It
// neither opens nor closes sockets. Every ingress must use this same ledger,
// and issuer admission must bound legitimate setup before dialing, before any
// runtime enables it. Anonymous capacity does not guarantee flood availability.
// A Joined call requires actual socket closure and all associated work joined;
// never call it in response to a child acknowledgement or elapsed deadline.
type ReservationAccounting struct {
	mu                   sync.Mutex
	limits               ReservationLimits
	replays              *ReplayRegistry
	parents              map[string]*reservationParent
	sockets              map[*AdmittedSocket]struct{}
	handshakes, ordinary int
	draining             bool
}

type reservationParent struct {
	verified             VerifiedReservation
	data, auxiliary      *ReservationPair
	deadline, leaseUntil time.Time
	terminating, closing bool
}

// AdmittedSocket is an allocation identity, not a network capability. Copying a
// handle does not copy its admission. A failed promotion leaves this new ingress
// with its caller; it never closes or changes a previously admitted parent.
type AdmittedSocket struct {
	owner            *ReservationAccounting
	deadline         time.Time
	pair             *ReservationPair
	ordinary, joined bool
}

// ReservationPair pins one private ingress and its single pending DATA socket.
// The setup hold remains charged until capability pairing and cleanup are joined.
type ReservationPair struct {
	owner                            *ReservationAccounting
	parent                           *reservationParent
	verified                         VerifiedReservation
	deadline, leaseUntil, setupUntil time.Time
	sockets                          int
	dataBound, setupJoined, closing  bool
}

type ReservationSnapshot struct {
	Limit, Charged, LiveSockets, Handshakes, Ordinary, Parents, Pairing, Closing int
	Draining                                                                     bool
}

// ReservationCleanup contains exact allocations the trusted owner must close
// and join. Taking this snapshot does not release any capacity. The same handle
// can appear in later snapshots until its once-only Joined call completes.
type ReservationCleanup struct {
	Sockets []*AdmittedSocket
	Setups  []*ReservationPair
}

func NewReservationAccounting(limits ReservationLimits, sharedReplays *ReplayRegistry) (*ReservationAccounting, error) {
	if sharedReplays == nil || limits.Sockets < 6 || limits.Sockets > 1_000_000 ||
		limits.Handshakes < 2 || limits.Handshakes >= limits.Sockets || limits.Parents < 1 ||
		limits.Parents > (limits.Sockets-limits.Handshakes)/4 ||
		limits.SetupTimeout < 100*time.Millisecond || limits.SetupTimeout > 30*time.Second ||
		limits.TerminationWindow < 100*time.Millisecond || limits.TerminationWindow > MaxAuxiliaryTTL {
		return nil, ErrReservationState
	}
	return &ReservationAccounting{limits: limits, replays: sharedReplays,
		parents: make(map[string]*reservationParent), sockets: make(map[*AdmittedSocket]struct{})}, nil
}

func (a *ReservationAccounting) Accept(now time.Time) (*AdmittedSocket, error) {
	if a == nil {
		return nil, ErrReservationState
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.draining {
		return nil, ErrReservationState
	}
	if a.handshakes >= a.limits.Handshakes {
		return nil, ErrSocketCapacity
	}
	p := &AdmittedSocket{owner: a, deadline: now.Add(a.limits.SetupTimeout)}
	a.sockets[p] = struct{}{}
	a.handshakes++
	return p, nil
}

func (a *ReservationAccounting) ingressLocked(p *AdmittedSocket, now time.Time) bool {
	if a.draining || p == nil || p.owner != a || p.joined || p.ordinary || p.pair != nil || !now.Before(p.deadline) {
		return false
	}
	_, present := a.sockets[p]
	return present
}

func (a *ReservationAccounting) chargedLocked() int {
	return a.limits.Handshakes + a.ordinary + 4*len(a.parents)
}

func (a *ReservationAccounting) AdmitOrdinary(p *AdmittedSocket, now time.Time) error {
	if a == nil {
		return ErrReservationState
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.ingressLocked(p, now) {
		return ErrReservationState
	}
	if a.chargedLocked() >= a.limits.Sockets {
		return ErrSocketCapacity
	}
	p.ordinary = true
	a.handshakes--
	a.ordinary++
	return nil
}

// AdmitData requires a verified ticket and a fresh live-authority response.
// Route/execution custody must be checked by the caller under its ownership lock.
// Replay consumption happens only after all local admission checks succeed.
func (a *ReservationAccounting) AdmitData(v VerifiedReservation, leaseUntil time.Time, ingress *AdmittedSocket, now time.Time) (*ReservationPair, error) {
	if a == nil || v.digest == "" || v.claims.ParentOpenSHA256 != "" {
		return nil, ErrAuthority
	}
	validatedLease, err := v.LeaseDeadline(v.digest, leaseUntil.Unix(), now)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.expireParentLocked(a.parents[v.digest], now)
	if !a.ingressLocked(ingress, now) {
		return nil, ErrReservationState
	}
	if _, exists := a.parents[v.digest]; exists {
		return nil, ErrReplay
	}
	if len(a.parents) >= a.limits.Parents || a.chargedLocked()+4 > a.limits.Sockets {
		return nil, ErrSocketCapacity
	}
	if err := a.replays.ConsumeReservation(v, now); err != nil {
		return nil, err
	}
	parent := &reservationParent{verified: v, deadline: earlier(time.Unix(v.claims.SessionExpiresAt, 0), v.peerUntil), leaseUntil: validatedLease}
	pair := &ReservationPair{owner: a, parent: parent, verified: v, deadline: parent.deadline, leaseUntil: validatedLease, setupUntil: ingress.deadline, sockets: 1}
	parent.data = pair
	a.parents[v.digest] = parent
	a.transferLocked(ingress, pair)
	return pair, nil
}

func (a *ReservationAccounting) AdmitAuxiliary(v VerifiedReservation, leaseUntil time.Time, ingress *AdmittedSocket, now time.Time) (*ReservationPair, error) {
	if a == nil || v.digest == "" || v.claims.ParentOpenSHA256 == "" {
		return nil, ErrAuthority
	}
	validatedLease, err := v.LeaseDeadline(v.digest, leaseUntil.Unix(), now)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.expireParentLocked(a.parents[v.claims.ParentOpenSHA256], now)
	if !a.ingressLocked(ingress, now) {
		return nil, ErrReservationState
	}
	parent := a.parents[v.claims.ParentOpenSHA256]
	if parent == nil || parent.closing || parent.auxiliary != nil || !parent.data.dataBound || !parent.data.setupJoined ||
		!now.Before(parent.deadline) || !now.Before(parent.leaseUntil) {
		return nil, ErrReservationState
	}
	actual, expected := v.claims.OpenClaims, parent.verified.claims.OpenClaims
	actual.ID, actual.IssuedAt, actual.ExpiresAt, actual.SessionExpiresAt = expected.ID, expected.IssuedAt, expected.ExpiresAt, expected.SessionExpiresAt
	if actual != expected || v.claims.ID == expected.ID || v.claims.IssuedAt < expected.IssuedAt ||
		v.claims.SessionExpiresAt > expected.SessionExpiresAt || time.Unix(v.claims.SessionExpiresAt, 0).After(parent.verified.peerUntil) {
		return nil, ErrAuthority
	}
	if err := a.replays.ConsumeReservation(v, now); err != nil {
		return nil, err
	}
	pair := &ReservationPair{owner: a, parent: parent, verified: v, sockets: 1,
		deadline: earlier(parent.deadline, earlier(time.Unix(v.claims.SessionExpiresAt, 0), v.peerUntil)), leaseUntil: validatedLease, setupUntil: ingress.deadline}
	parent.auxiliary = pair
	a.transferLocked(ingress, pair)
	return pair, nil
}

func (a *ReservationAccounting) transferLocked(p *AdmittedSocket, pair *ReservationPair) {
	a.handshakes--
	p.pair = pair
}

func (p *ReservationPair) activeLocked() bool {
	return p.owner.parents[p.parent.verified.digest] == p.parent && (p.parent.data == p || p.parent.auxiliary == p)
}

// AdmitDATASocket transfers only the socket paired by this exact pending DATA
// capability. The caller must verify its current customer control owner first.
func (p *ReservationPair) AdmitDATASocket(ingress *AdmittedSocket, now time.Time) error {
	if p == nil || p.owner == nil || p.parent == nil {
		return ErrReservationState
	}
	a := p.owner
	a.mu.Lock()
	defer a.mu.Unlock()
	a.expireParentLocked(p.parent, now)
	if !p.activeLocked() || p.parent.closing || p.closing || p.setupJoined || p.dataBound || !a.ingressLocked(ingress, now) {
		return ErrReservationState
	}
	a.transferLocked(ingress, p)
	p.dataBound = true
	p.sockets++
	return nil
}

// SetupJoined acknowledges the trusted pairing owner has removed its pending
// capability and joined all setup callbacks. It does not close either socket.
func (p *ReservationPair) SetupJoined(now time.Time) error {
	if p == nil || p.owner == nil || p.parent == nil {
		return ErrReservationState
	}
	a := p.owner
	a.mu.Lock()
	defer a.mu.Unlock()
	if p.setupJoined {
		return nil
	}
	a.expireParentLocked(p.parent, now)
	if !p.activeLocked() {
		return ErrReservationState
	}
	p.setupJoined = true
	if !p.dataBound {
		p.closing = true
		if p.parent.data == p {
			a.terminateLocked(p.parent, now)
		}
	}
	a.expireParentLocked(p.parent, now)
	return nil
}

// BeginTermination fences data immediately, even while its socket Close is
// pending. Repeated calls cannot extend the absolute termination deadline.
func (p *ReservationPair) BeginTermination(now time.Time) error {
	if p == nil || p.owner == nil || p.parent == nil {
		return ErrReservationState
	}
	a := p.owner
	a.mu.Lock()
	defer a.mu.Unlock()
	a.expireParentLocked(p.parent, now)
	if !p.activeLocked() || p.parent.data != p {
		return ErrReservationState
	}
	a.terminateLocked(p.parent, now)
	a.expireParentLocked(p.parent, now)
	return nil
}

func (a *ReservationAccounting) terminateLocked(parent *reservationParent, now time.Time) {
	if !parent.terminating {
		parent.terminating = true
		parent.deadline = earlier(parent.deadline, now.Add(a.limits.TerminationWindow))
	}
	parent.data.closing = true
	if parent.auxiliary != nil {
		parent.auxiliary.deadline = earlier(parent.auxiliary.deadline, parent.deadline)
	}
}

// Renew requires a new authoritative lease. The data parent's lease may be
// renewed during its termination window after data closure, retaining bounded
// auxiliary custody. Once any lease lapses, this allocation cannot be revived.
func (p *ReservationPair) Renew(until, now time.Time) error {
	if p == nil || p.owner == nil || p.parent == nil {
		return ErrReservationState
	}
	validatedLease, err := p.verified.LeaseDeadline(p.verified.digest, until.Unix(), now)
	if err != nil {
		return err
	}
	a := p.owner
	a.mu.Lock()
	defer a.mu.Unlock()
	a.expireParentLocked(p.parent, now)
	if !p.activeLocked() || p.parent.closing || (p.parent.data != p && p.closing) {
		return ErrReservationState
	}
	if p.parent.data == p {
		p.parent.leaseUntil = validatedLease
	}
	p.leaseUntil = validatedLease
	return nil
}

// Revoke fences the entire parent immediately. It releases network capacity
// only after all socket/setup joins, and never proves source SQL has stopped.
func (p *ReservationPair) Revoke(now time.Time) error {
	if p == nil || p.owner == nil || p.parent == nil {
		return ErrReservationState
	}
	a := p.owner
	a.mu.Lock()
	defer a.mu.Unlock()
	if !p.activeLocked() {
		return ErrReservationState
	}
	p.parent.closing = true
	a.expireParentLocked(p.parent, now)
	return nil
}

// Joined is called only after this exact physical socket and its work are gone.
// A deadline or Close error alone is not a join. Failed cleanup stays charged.
func (p *AdmittedSocket) Joined(now time.Time) error {
	if p == nil || p.owner == nil {
		return ErrReservationState
	}
	a := p.owner
	a.mu.Lock()
	defer a.mu.Unlock()
	if p.joined {
		return nil
	}
	if _, exists := a.sockets[p]; !exists {
		return ErrReservationState
	}
	if p.pair != nil {
		a.expireParentLocked(p.pair.parent, now)
	}
	p.joined = true
	delete(a.sockets, p)
	switch {
	case p.pair != nil:
		p.pair.sockets--
		if p.pair.parent.data == p.pair {
			a.terminateLocked(p.pair.parent, now)
		}
	case p.ordinary:
		a.ordinary--
	default:
		a.handshakes--
	}
	if p.pair != nil {
		a.expireParentLocked(p.pair.parent, now)
	}
	return nil
}

func (a *ReservationAccounting) expireLocked(now time.Time) {
	for _, parent := range a.parents {
		a.expireParentLocked(parent, now)
	}
}

func (a *ReservationAccounting) expireParentLocked(parent *reservationParent, now time.Time) {
	if parent == nil || a.parents[parent.verified.digest] != parent {
		return
	}
	if !parent.data.setupJoined && !now.Before(parent.data.setupUntil) {
		a.terminateLocked(parent, parent.data.setupUntil)
	}
	if a.draining || !now.Before(parent.deadline) || !now.Before(parent.leaseUntil) {
		parent.closing = true
	}
	for _, pair := range []*ReservationPair{parent.data, parent.auxiliary} {
		if pair == nil {
			continue
		}
		if parent.closing || !now.Before(pair.deadline) || !pair.setupJoined && !now.Before(pair.setupUntil) ||
			(pair != parent.data && !now.Before(pair.leaseUntil)) {
			pair.closing = true
		}
		if pair == parent.auxiliary && pair.sockets == 0 && pair.setupJoined {
			parent.auxiliary = nil
		}
	}
	if parent.closing && parent.data.sockets == 0 && parent.data.setupJoined && parent.auxiliary == nil {
		delete(a.parents, parent.verified.digest)
	}
}

func (a *ReservationAccounting) Cleanup(now time.Time) ReservationCleanup {
	if a == nil {
		return ReservationCleanup{}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.expireLocked(now)
	var result ReservationCleanup
	for socket := range a.sockets {
		if a.draining || socket.pair != nil && socket.pair.closing || socket.pair == nil && !socket.ordinary && !now.Before(socket.deadline) {
			result.Sockets = append(result.Sockets, socket)
		}
	}
	for _, parent := range a.parents {
		for _, pair := range []*ReservationPair{parent.data, parent.auxiliary} {
			if pair != nil && pair.closing && !pair.setupJoined {
				result.Setups = append(result.Setups, pair)
			}
		}
	}
	return result
}

func (a *ReservationAccounting) Drain(now time.Time) {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.draining = true
	a.expireLocked(now)
}

func (a *ReservationAccounting) Snapshot(now time.Time) ReservationSnapshot {
	if a == nil {
		return ReservationSnapshot{}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.expireLocked(now)
	s := ReservationSnapshot{Limit: a.limits.Sockets, Charged: a.chargedLocked(), LiveSockets: len(a.sockets),
		Handshakes: a.handshakes, Ordinary: a.ordinary, Parents: len(a.parents), Draining: a.draining}
	for _, parent := range a.parents {
		if parent.closing {
			s.Closing++
		}
		for _, pair := range []*ReservationPair{parent.data, parent.auxiliary} {
			if pair != nil && !pair.setupJoined {
				s.Pairing++
			}
		}
	}
	return s
}

func earlier(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
