//go:build !windows

package server

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

type privateOwnerInfo struct {
	os.FileInfo
	stat any
}

func (i privateOwnerInfo) Sys() any { return i.stat }

func TestPrivateFileOwnerRequiresRootOrServerUser(t *testing.T) {
	foreign := uint32(os.Geteuid()) + 1
	if foreign == 0 {
		foreign++
	}
	for _, tc := range []struct {
		name string
		stat any
		want bool
	}{
		{"root", &syscall.Stat_t{Uid: 0}, true},
		{"server", &syscall.Stat_t{Uid: uint32(os.Geteuid())}, true},
		{"foreign", &syscall.Stat_t{Uid: foreign}, false},
		{"unknown", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := operatorFileOwnerAllowed(privateOwnerInfo{stat: tc.stat}); got != tc.want {
				t.Fatal("incorrect owner decision", got)
			}
		})
	}
}

func TestPrivateOperatorConfigRejectsWritableTrust(t *testing.T) {
	for _, mode := range []os.FileMode{0600, 0644, 0620, 0602} {
		path := filepath.Join(t.TempDir(), "rabbit.yml")
		if err := os.WriteFile(path, []byte("private_connect:\n  listen: 127.0.0.1:14443\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		_, err := LoadOperatorConfig(path)
		if (err == nil) != (mode&0022 == 0) {
			t.Fatalf("operator trust mode %o: %v", mode, err)
		}
	}
}

func TestPrivateReferencedFilesEnforceWriteAndReadPermissions(t *testing.T) {
	for _, mode := range []os.FileMode{0600, 0644, 0620, 0602} {
		path := filepath.Join(t.TempDir(), "input.pem")
		if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		for _, secret := range []bool{false, true} {
			_, err := privateFile(path, secret)
			want := mode&0022 == 0 && (!secret || mode&0077 == 0)
			if (err == nil) != want {
				t.Fatalf("input mode %o secret %v: %v", mode, secret, err)
			}
		}
	}
}
