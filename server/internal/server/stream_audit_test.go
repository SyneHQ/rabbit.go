package server

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"rabbit.go/internal/database"
)

func TestAuditSaturationAndShutdownDoNotBlockRelay(t *testing.T) {
	entered := make(chan struct{})
	queue := newStreamAuditQueue(1, time.Minute, 25*time.Millisecond, func(ctx context.Context, _ database.ConnectionLog) error {
		close(entered)
		<-ctx.Done()
		return ctx.Err()
	})
	queue.submit(database.ConnectionLog{})
	<-entered
	started := time.Now()
	queue.submit(database.ConnectionLog{})
	queue.submit(database.ConnectionLog{})
	if time.Since(started) > 100*time.Millisecond {
		t.Fatal("audit submission blocked on metadata")
	}
	if queue.accepted.Load() != 2 || queue.dropped.Load() != 1 {
		t.Fatal("audit queue exceeded its bound")
	}
	started = time.Now()
	queue.close()
	if time.Since(started) > time.Second {
		t.Fatal("audit shutdown exceeded its total budget")
	}
	select {
	case <-queue.done:
	case <-time.After(time.Second):
		t.Fatal("audit writer survived cancellation")
	}
	if queue.failed.Load() != 1 || queue.dropped.Load() != 2 {
		t.Fatalf("failed or dropped records were not counted: %v", queue.stats())
	}
	queue.submit(database.ConnectionLog{})
	if queue.dropped.Load() != 3 {
		t.Fatal("closed queue accepted a record")
	}
}

func TestAuditRecordsStayCompleteAndOrdered(t *testing.T) {
	var mu sync.Mutex
	var ids []uuid.UUID
	queue := newStreamAuditQueue(3, time.Second, time.Second, func(_ context.Context, record database.ConnectionLog) error {
		if record.EndedAt == nil || record.Status == "active" {
			return errors.New("incomplete record")
		}
		mu.Lock()
		ids = append(ids, record.ID)
		mu.Unlock()
		return nil
	})
	ended := time.Now()
	first, second := uuid.New(), uuid.New()
	for _, id := range []uuid.UUID{first, second} {
		queue.submit(database.ConnectionLog{ID: id, StartedAt: ended.Add(-time.Second), EndedAt: &ended, Status: "closed"})
	}
	queue.close()
	if queue.failed.Load() != 0 || queue.written.Load() != 2 {
		t.Fatalf("audit drain failed: %v", queue.stats())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(ids) != 2 || ids[0] != first || ids[1] != second {
		t.Fatal("audit records changed order")
	}
}

func TestStreamStartDoesNotCallMetadata(t *testing.T) {
	called := make(chan struct{}, 1)
	queue := newStreamAuditQueue(1, time.Second, time.Second, func(context.Context, database.ConnectionLog) error { called <- struct{}{}; return nil })
	s := &Server{streamAudit: queue}
	tunnel := &Tunnel{server: s, TeamID: "team", TokenID: uuid.NewString(), PortAssignID: uuid.NewString(), SessionID: uuid.NewString(), RemotePort: "5432"}
	record := tunnel.createConnectionLog("127.0.0.1", 4242)
	if record == nil || record.StartedAt.IsZero() {
		t.Fatal("stream metadata was not captured")
	}
	select {
	case <-called:
		t.Fatal("stream start performed metadata I/O")
	default:
	}
	tunnel.finishStreamLog(record, 12, 34, "closed", nil)
	queue.close()
	if queue.written.Load() != 1 {
		t.Fatal("completion did not publish its audit record")
	}
	if record.EndedAt != nil {
		t.Fatal("completion modified the start record")
	}
}

func TestAuditCloseReportsUnfinishedDrain(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	queue := newStreamAuditQueue(1, time.Minute, 10*time.Millisecond, func(context.Context, database.ConnectionLog) error { close(entered); <-release; return nil })
	queue.submit(database.ConnectionLog{})
	<-entered
	queue.close()
	stats := queue.stats()
	if stats["drain_complete"] != false || stats["inflight"] != int64(1) {
		t.Fatalf("unfinished drain reported complete: %v", stats)
	}
	close(release)
	select {
	case <-queue.done:
	case <-time.After(time.Second):
		t.Fatal("released audit writer did not exit")
	}
	stats = queue.stats()
	if stats["drain_complete"] != true || stats["inflight"] != int64(0) {
		t.Fatalf("finished drain reported incorrectly: %v", stats)
	}
}
