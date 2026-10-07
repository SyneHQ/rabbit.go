package tunnel

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestCAFileAcceptsBoundedRegularReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ca.pem")
	for _, value := range []string{"first certificate", "replacement certificate"} {
		next := path + ".new"
		if err := os.WriteFile(next, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(next, path); err != nil {
			t.Fatal(err)
		}
		got, err := readCAFile(context.Background(), path)
		if err != nil || string(got) != value {
			t.Fatalf("regular replacement was not read: %q %v", got, err)
		}
	}
}

func TestCAFileRejectsOversizedAndNonRegularPaths(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, make([]byte, maxCAFileBytes+1), 0600); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []string{path, t.TempDir(), filepath.Join(t.TempDir(), "missing")} {
		if _, err := readCAFile(context.Background(), candidate); err == nil {
			t.Fatalf("accepted invalid CA path: %s", candidate)
		}
	}
	if err := os.Truncate(path, maxCAFileBytes); err != nil {
		t.Fatal(err)
	}
	got, err := readCAFile(context.Background(), path)
	if err != nil || len(got) != maxCAFileBytes {
		t.Fatalf("rejected file at byte bound: len=%d err=%v", len(got), err)
	}
}

func TestCAFileCancellationPrecedesFilesystemWork(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := readCAFile(ctx, filepath.Join(t.TempDir(), "missing")); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled CA read touched the filesystem: %v", err)
	}
}
