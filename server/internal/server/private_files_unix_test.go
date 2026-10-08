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

func TestPrivateMountedKeysRequireExplicitServiceGroup(t *testing.T) {
	gid := uint32(os.Getegid())
	for _, mode := range []os.FileMode{0400, 0600, 0440, 0640, 0444, 0644, 0660, 0650, 0641} {
		path := filepath.Join(t.TempDir(), "mounted.key")
		if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(path, -1, int(gid)); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		_, err := privateFileForGroup(path, true, &gid)
		want := mode&0077 == 0 || mode&0077 == 0040
		if (err == nil) != want {
			t.Fatalf("key mode %o with trusted group: %v", mode, err)
		}
		if mode&0077 == 0040 {
			if _, err := privateFile(path, true); err == nil {
				t.Fatal("group-readable key accepted without opt-in")
			}
			foreign := gid + 1
			if _, err := privateFileForGroup(path, true, &foreign); err == nil {
				t.Fatal("key accepted for a different configured group")
			}
		}
	}
	if !operatorFileGroupAllowed(privateOwnerInfo{stat: &syscall.Stat_t{Gid: gid}}, gid) ||
		operatorFileGroupAllowed(privateOwnerInfo{stat: &syscall.Stat_t{Gid: gid + 1}}, gid) ||
		operatorFileGroupAllowed(privateOwnerInfo{}, gid) {
		t.Fatal("mounted key group ownership is not exact")
	}
}
