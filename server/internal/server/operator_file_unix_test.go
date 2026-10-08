//go:build !windows

package server

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestOperatorConfigurationRejectsFIFOWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.pipe")
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := LoadOperatorConfig(path); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("configuration open blocked on FIFO")
	}
}
