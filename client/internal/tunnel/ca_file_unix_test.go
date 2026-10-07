//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package tunnel

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestCAFileRejectsFIFOAndSymlinkWithoutBlocking(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "certificate-pipe")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readCAFile(context.Background(), fifo); err == nil {
		t.Fatal("accepted FIFO as a CA file")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := readCAFile(ctx, fifo); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled FIFO read did not stop: %v", err)
	}
	// Exercise descriptor opening independently of the initial Lstat, as when
	// an attacker replaces a regular path with a FIFO between check and open.
	opened := make(chan error, 1)
	go func() {
		file, err := openCAFile(fifo)
		if file != nil {
			file.Close()
		}
		opened <- err
	}()
	select {
	case <-opened:
	case <-time.After(time.Second):
		// Release a faulty blocking reader so a failed test leaves no worker.
		if fd, err := syscall.Open(fifo, syscall.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			syscall.Close(fd)
		}
		t.Fatal("CA open blocked on a FIFO without a writer")
	}
	regular := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(regular, []byte("certificate"), 0600); err != nil {
		t.Fatal(err)
	}
	link := regular + ".link"
	if err := os.Symlink(regular, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readCAFile(context.Background(), link); err == nil {
		t.Fatal("accepted symlink as a CA file")
	}
	if file, err := openCAFile(link); err == nil {
		file.Close()
		t.Fatal("CA descriptor open followed a substituted symlink")
	}
}
