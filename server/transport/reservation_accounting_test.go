package transport

import (
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type accountingFixture struct {
	a      *ReservationAccounting
	now    time.Time
	parent VerifiedReservation
	trust  Trust
	key    ed25519.PrivateKey
	tls    tls.ConnectionState
}

func newAccountingFixture(t *testing.T, sockets, handshakes, parents int) accountingFixture {
	t.Helper()
	_, trust, key, state, now, parent := reservationFixture(t)
	replays, _ := NewReplayRegistry(512)
	a, err := NewReservationAccounting(ReservationLimits{Sockets: sockets, Handshakes: handshakes, Parents: parents,
		SetupTimeout: 2 * time.Second, TerminationWindow: 3 * time.Second}, replays)
	if err != nil {
		t.Fatal(err)
	}
	return accountingFixture{a, now, parent, trust, key, state}
}

func (f accountingFixture) accept(t *testing.T, now time.Time) *AdmittedSocket {
	t.Helper()
	p, err := f.a.Accept(now)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func (f accountingFixture) data(t *testing.T) (*ReservationPair, *AdmittedSocket, *AdmittedSocket) {
	t.Helper()
	private := f.accept(t, f.now)
	pair, err := f.a.AdmitData(f.parent, f.now.Add(10*time.Second), private, f.now)
	if err != nil {
		t.Fatal(err)
	}
	data := f.accept(t, f.now)
	if err := pair.AdmitDATASocket(data, f.now); err != nil {
		t.Fatal(err)
	}
	if err := pair.SetupJoined(f.now); err != nil {
		t.Fatal(err)
	}
	return pair, private, data
}

func (f accountingFixture) auxiliary(t *testing.T, now time.Time, id string) VerifiedReservation {
	t.Helper()
	claims := auxiliaryClaims(f.parent, now)
	claims.ID = id
	v, err := VerifyReservationAuxiliary(signReservation(t, claims, f.key), claims.Authority, f.trust, f.tls, f.parent, now)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func assertAccounting(t *testing.T, a *ReservationAccounting, now time.Time, parents, sockets int) ReservationSnapshot {
	t.Helper()
	s := a.Snapshot(now)
	if s.Parents != parents || s.LiveSockets != sockets || s.Charged > s.Limit || s.LiveSockets > s.Charged || s.Handshakes < 0 || s.Ordinary < 0 {
		t.Fatal("socket ownership or capacity invariant failed", s)
	}
	return s
}

func TestReservationAccountingPreservesAuxiliaryPairAtOrdinarySaturation(t *testing.T) {
	f := newAccountingFixture(t, 6, 2, 1)
	data, private, paired := f.data(t)
	s := assertAccounting(t, f.a, f.now, 1, 2)
	if s.Charged != 6 {
		t.Fatal("parent did not charge four slots plus handshake partition", s)
	}
	ordinary := f.accept(t, f.now)
	if err := f.a.AdmitOrdinary(ordinary, f.now); !errors.Is(err, ErrSocketCapacity) {
		t.Fatal("ordinary work consumed reserved capacity", err)
	}
	if err := ordinary.Joined(f.now); err != nil {
		t.Fatal(err)
	}
	auxIngress := f.accept(t, f.now)
	aux, err := f.a.AdmitAuxiliary(f.auxiliary(t, f.now, strings.Repeat("a", 64)), f.now.Add(10*time.Second), auxIngress, f.now)
	if err != nil {
		t.Fatal("reserved auxiliary ingress failed", err)
	}
	auxData := f.accept(t, f.now)
	if err := aux.AdmitDATASocket(auxData, f.now); err != nil {
		t.Fatal("reserved auxiliary DATA failed", err)
	}
	if err := aux.SetupJoined(f.now); err != nil {
		t.Fatal(err)
	}
	first, second := f.accept(t, f.now), f.accept(t, f.now)
	if _, err := f.a.Accept(f.now); !errors.Is(err, ErrSocketCapacity) {
		t.Fatal("anonymous socket ceiling exceeded", err)
	}
	assertAccounting(t, f.a, f.now, 1, 6)
	if err := data.Revoke(f.now); err != nil {
		t.Fatal(err)
	}
	for _, socket := range []*AdmittedSocket{private, paired, auxIngress, auxData, first, second} {
		if err := socket.Joined(f.now); err != nil {
			t.Fatal(err)
		}
	}
	assertAccounting(t, f.a, f.now, 0, 0)
}

func TestReservationTerminationDeadlineStartsBeforePendingClose(t *testing.T) {
	f := newAccountingFixture(t, 6, 2, 1)
	data, private, paired := f.data(t)
	start := f.now.Add(time.Second)
	if err := data.BeginTermination(start); err != nil {
		t.Fatal(err)
	}
	if err := data.BeginTermination(start.Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if data.parent.deadline != start.Add(3*time.Second) {
		t.Fatal("repeated termination extended the deadline")
	}
	auxIngress := f.accept(t, start)
	aux, err := f.a.AdmitAuxiliary(f.auxiliary(t, start, strings.Repeat("a", 64)), start.Add(10*time.Second), auxIngress, start)
	if err != nil {
		t.Fatal("pending data Close erased termination custody", err)
	}
	auxData := f.accept(t, start)
	if err := aux.AdmitDATASocket(auxData, start); err != nil {
		t.Fatal(err)
	}
	if err := aux.SetupJoined(start); err != nil {
		t.Fatal(err)
	}
	expired := start.Add(3 * time.Second)
	cleanup := f.a.Cleanup(expired)
	if len(cleanup.Sockets) != 4 || len(cleanup.Setups) != 0 {
		t.Fatal("deadline failed to request exact socket cleanup", cleanup)
	}
	if s := assertAccounting(t, f.a, expired, 1, 4); s.Closing != 1 || s.Charged != 6 {
		t.Fatal("expiry freed unconfirmed resources", s)
	}
	if err := data.Renew(expired.Add(time.Second), expired); !errors.Is(err, ErrReservationState) {
		t.Fatal("expired parent was revived", err)
	}
	for _, socket := range []*AdmittedSocket{private, paired, auxIngress} {
		_ = socket.Joined(expired)
	}
	assertAccounting(t, f.a, expired, 1, 1)
	_ = auxData.Joined(expired)
	assertAccounting(t, f.a, expired, 0, 0)
}

func TestReservationRetainsClosedDataForTerminationWithoutClaimingComputeExit(t *testing.T) {
	f := newAccountingFixture(t, 6, 2, 1)
	data, private, paired := f.data(t)
	at := f.now.Add(time.Second)
	_ = data.BeginTermination(at)
	_ = private.Joined(at)
	_ = paired.Joined(at)
	if s := assertAccounting(t, f.a, at, 1, 0); s.Charged != 6 {
		t.Fatal("data EOF released termination reserve", s)
	}
	if err := data.Renew(at.Add(2*time.Second), at); err != nil {
		t.Fatal("live termination custody could not renew after data closure", err)
	}
	ingress := f.accept(t, at)
	aux, err := f.a.AdmitAuxiliary(f.auxiliary(t, at, strings.Repeat("a", 64)), at.Add(2*time.Second), ingress, at)
	if err != nil {
		t.Fatal(err)
	}
	_ = ingress.Joined(at)
	_ = aux.SetupJoined(at)
	assertAccounting(t, f.a, at, 1, 0)
	assertAccounting(t, f.a, at.Add(3*time.Second), 0, 0)
}

func TestReservationSetupHoldsRemainChargedAfterExpiredIngress(t *testing.T) {
	f := newAccountingFixture(t, 6, 2, 1)
	ingress := f.accept(t, f.now)
	data, err := f.a.AdmitData(f.parent, f.now.Add(10*time.Second), ingress, f.now)
	if err != nil {
		t.Fatal(err)
	}
	auxIngress := f.accept(t, f.now)
	if _, err := f.a.AdmitAuxiliary(f.auxiliary(t, f.now, strings.Repeat("a", 64)), f.now.Add(10*time.Second), auxIngress, f.now); err == nil {
		t.Fatal("auxiliary admitted before parent DATA setup joined")
	}
	_ = auxIngress.Joined(f.now)
	late := f.now.Add(20 * time.Second)
	cleanup := f.a.Cleanup(late)
	if len(cleanup.Sockets) != 1 || len(cleanup.Setups) != 1 || cleanup.Setups[0] != data {
		t.Fatal("pending capability cleanup was lost", cleanup)
	}
	if data.parent.deadline != f.now.Add(5*time.Second) {
		t.Fatal("late sweep extended setup termination deadline", data.parent.deadline)
	}
	_ = ingress.Joined(late)
	if s := assertAccounting(t, f.a, late, 1, 0); s.Pairing != 1 {
		t.Fatal("socket closure released unjoined setup", s)
	}
	_ = data.SetupJoined(late)
	assertAccounting(t, f.a, late, 0, 0)
}

func TestReservationReplayAndCopiedHandlesDoNotChangeOriginalCustody(t *testing.T) {
	f := newAccountingFixture(t, 6, 2, 1)
	data, private, paired := f.data(t)
	other := f.accept(t, f.now)
	if _, err := f.a.AdmitData(f.parent, f.now.Add(time.Second), other, f.now); !errors.Is(err, ErrReplay) {
		t.Fatal(err)
	}
	_ = other.Joined(f.now)
	copySocket := *private
	if err := copySocket.Joined(f.now); !errors.Is(err, ErrReservationState) {
		t.Fatal("copied socket released original capacity", err)
	}
	copyPair := *data
	if err := copyPair.Revoke(f.now); !errors.Is(err, ErrReservationState) {
		t.Fatal("copied pair revoked original", err)
	}
	assertAccounting(t, f.a, f.now, 1, 2)
	_ = data.Revoke(f.now)
	var joins sync.WaitGroup
	for range 64 {
		joins.Add(1)
		go func() {
			defer joins.Done()
			_ = private.Joined(f.now)
			_ = paired.Joined(f.now)
			_ = data.SetupJoined(f.now)
		}()
	}
	joins.Wait()
	assertAccounting(t, f.a, f.now, 0, 0)
}

func TestReservationAuxiliaryLimitAndSharedReplaySurvivePairCleanup(t *testing.T) {
	f := newAccountingFixture(t, 6, 2, 1)
	data, private, paired := f.data(t)
	v := f.auxiliary(t, f.now, strings.Repeat("a", 64))
	first := f.accept(t, f.now)
	aux, err := f.a.AdmitAuxiliary(v, f.now.Add(time.Second), first, f.now)
	if err != nil {
		t.Fatal(err)
	}
	second := f.accept(t, f.now)
	unspent := f.auxiliary(t, f.now, strings.Repeat("b", 64))
	if _, err := f.a.AdmitAuxiliary(unspent, f.now.Add(time.Second), second, f.now); err == nil {
		t.Fatal("second concurrent auxiliary pair admitted")
	}
	_ = second.Joined(f.now)
	_ = first.Joined(f.now)
	_ = aux.SetupJoined(f.now)
	third := f.accept(t, f.now)
	if _, err := f.a.AdmitAuxiliary(v, f.now.Add(time.Second), third, f.now); !errors.Is(err, ErrReplay) {
		t.Fatal("completed auxiliary JTI was reusable", err)
	}
	_ = third.Joined(f.now)
	fourth := f.accept(t, f.now)
	retry, err := f.a.AdmitAuxiliary(unspent, f.now.Add(time.Second), fourth, f.now)
	if err != nil {
		t.Fatal("failed capacity check consumed an unused ticket", err)
	}
	_ = fourth.Joined(f.now)
	_ = retry.SetupJoined(f.now)
	assertAccounting(t, f.a, f.now, 1, 2)
	_ = data.Revoke(f.now)
	_ = private.Joined(f.now)
	_ = paired.Joined(f.now)
	assertAccounting(t, f.a, f.now, 0, 0)
}

func TestReservationLateJoinCannotHideSetupExpiry(t *testing.T) {
	for _, first := range []string{"socket", "setup", "termination"} {
		t.Run(first, func(t *testing.T) {
			f := newAccountingFixture(t, 6, 2, 1)
			ingress := f.accept(t, f.now)
			pair, err := f.a.AdmitData(f.parent, f.now.Add(10*time.Second), ingress, f.now)
			if err != nil {
				t.Fatal(err)
			}
			data := f.accept(t, f.now)
			if err := pair.AdmitDATASocket(data, f.now); err != nil {
				t.Fatal(err)
			}
			late := f.now.Add(3 * time.Second)
			switch first {
			case "socket":
				err = ingress.Joined(late)
			case "setup":
				err = pair.SetupJoined(late)
			case "termination":
				err = pair.BeginTermination(late)
			}
			if err != nil {
				t.Fatal(err)
			}
			if pair.parent.deadline != f.now.Add(5*time.Second) || !pair.closing {
				t.Fatal("late join concealed the earlier setup expiry", pair.parent.deadline)
			}
			_ = ingress.Joined(late)
			_ = data.Joined(late)
			_ = pair.SetupJoined(late)
			assertAccounting(t, f.a, f.now.Add(5*time.Second), 0, 0)
		})
	}
}

func TestReservationForeignPermitCannotSpendAnotherLedger(t *testing.T) {
	f, other := newAccountingFixture(t, 6, 2, 1), newAccountingFixture(t, 6, 2, 1)
	foreign := other.accept(t, other.now)
	if _, err := f.a.AdmitData(f.parent, f.now.Add(time.Second), foreign, f.now); !errors.Is(err, ErrReservationState) {
		t.Fatal("foreign socket admitted", err)
	}
	assertAccounting(t, f.a, f.now, 0, 0)
	assertAccounting(t, other.a, other.now, 0, 1)
	_ = foreign.Joined(other.now)
	assertAccounting(t, other.a, other.now, 0, 0)
}

func TestReservationConcurrentAdmissionAndDrainKeepExactOwners(t *testing.T) {
	f := newAccountingFixture(t, 68, 64, 1)
	var accepted atomic.Int64
	var workers sync.WaitGroup
	var winner *ReservationPair
	for range 64 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			ingress, err := f.a.Accept(f.now)
			if err != nil {
				t.Error(err)
				return
			}
			pair, err := f.a.AdmitData(f.parent, f.now.Add(10*time.Second), ingress, f.now)
			if err == nil {
				accepted.Add(1)
				winner = pair
			} else if !errors.Is(err, ErrReplay) {
				t.Error(err)
			}
			_ = ingress.Joined(f.now)
		}()
	}
	workers.Wait()
	if accepted.Load() != 1 {
		t.Fatal("concurrent ticket admitted more than once", accepted.Load())
	}
	f.a.Drain(f.now)
	if _, err := f.a.Accept(f.now); !errors.Is(err, ErrReservationState) {
		t.Fatal("draining ledger admitted a socket", err)
	}
	if s := assertAccounting(t, f.a, f.now, 1, 0); s.Pairing != 1 || !s.Draining {
		t.Fatal("drain released in-flight capability", s)
	}
	if err := winner.SetupJoined(f.now); err != nil {
		t.Fatal(err)
	}
	assertAccounting(t, f.a, f.now, 0, 0)
}

func TestReservationExpiredLeaseAndSetupCannotBeRevived(t *testing.T) {
	f := newAccountingFixture(t, 6, 2, 1)
	data, private, paired := f.data(t)
	if err := data.Renew(f.now.Add(time.Second+900*time.Millisecond), f.now); err != nil {
		t.Fatal(err)
	}
	// Preserve the verified whole-second lease; fractional input must not add
	// unverified authority beyond that response.
	if data.parent.leaseUntil != f.now.Add(time.Second) {
		t.Fatal("fractional lease extended authority")
	}
	late := f.now.Add(time.Second)
	if err := data.Renew(late.Add(time.Second), late); !errors.Is(err, ErrReservationState) {
		t.Fatal("expired lease revived parent", err)
	}
	if len(f.a.Cleanup(late).Sockets) != 2 {
		t.Fatal("expired lease did not fence both sockets")
	}
	_ = private.Joined(late)
	_ = paired.Joined(late)
	assertAccounting(t, f.a, late, 0, 0)
	p := f.accept(t, late)
	afterSetup := late.Add(2 * time.Second)
	if err := f.a.AdmitOrdinary(p, afterSetup); !errors.Is(err, ErrReservationState) {
		t.Fatal("expired anonymous setup gained admission", err)
	}
	if s := assertAccounting(t, f.a, afterSetup, 0, 1); s.Handshakes != 1 {
		t.Fatal("unjoined expired handshake stopped counting", s)
	}
	_ = p.Joined(afterSetup)
	assertAccounting(t, f.a, afterSetup, 0, 0)
}

func TestReservationAuxiliaryExpiryDoesNotRevokeLiveDataParent(t *testing.T) {
	for _, reason := range []string{"lease", "setup"} {
		t.Run(reason, func(t *testing.T) {
			f := newAccountingFixture(t, 6, 2, 1)
			parent, private, data := f.data(t)
			ingress := f.accept(t, f.now)
			lease, expired := f.now.Add(time.Second), f.now.Add(time.Second)
			if reason == "setup" {
				lease, expired = f.now.Add(10*time.Second), f.now.Add(2*time.Second)
			}
			aux, err := f.a.AdmitAuxiliary(f.auxiliary(t, f.now, strings.Repeat("a", 64)), lease, ingress, f.now)
			if err != nil {
				t.Fatal(err)
			}
			var paired *AdmittedSocket
			if reason == "lease" {
				paired = f.accept(t, f.now)
				if err := aux.AdmitDATASocket(paired, f.now); err != nil {
					t.Fatal(err)
				}
				if err := aux.SetupJoined(f.now); err != nil {
					t.Fatal(err)
				}
			}
			cleanup := f.a.Cleanup(expired)
			if !aux.closing || parent.closing || parent.parent.closing {
				t.Fatal("auxiliary expiry revoked live parent")
			}
			for _, socket := range cleanup.Sockets {
				if socket == private || socket == data {
					t.Fatal("auxiliary cleanup selected a data socket")
				}
			}
			if err := aux.Renew(expired.Add(time.Second), expired); !errors.Is(err, ErrReservationState) {
				t.Fatal("expired auxiliary was revived", err)
			}
			_ = ingress.Joined(expired)
			if paired != nil {
				_ = paired.Joined(expired)
			}
			_ = aux.SetupJoined(expired)
			assertAccounting(t, f.a, expired, 1, 2)
			fresh := f.accept(t, expired)
			next, err := f.a.AdmitAuxiliary(f.auxiliary(t, expired, strings.Repeat("b", 64)), expired.Add(time.Second), fresh, expired)
			if err != nil {
				t.Fatal("live parent lost its reusable auxiliary reserve", err)
			}
			_ = fresh.Joined(expired)
			_ = next.SetupJoined(expired)
			_ = parent.Revoke(expired)
			_ = private.Joined(expired)
			_ = data.Joined(expired)
			assertAccounting(t, f.a, expired, 0, 0)
		})
	}
}
