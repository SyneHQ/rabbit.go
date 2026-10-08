//go:build !windows

package server

import (
	"os"
	"syscall"
)

func openOperatorFile(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

func operatorFileOwnerAllowed(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && (stat.Uid == 0 || stat.Uid == uint32(os.Geteuid()))
}

func operatorFileGroupAllowed(info os.FileInfo, gid uint32) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Gid == gid
}

func operatorGroupMember(gid uint32) bool {
	if gid == uint32(os.Getegid()) {
		return true
	}
	groups, err := os.Getgroups()
	if err != nil {
		return false
	}
	for _, group := range groups {
		if gid == uint32(group) {
			return true
		}
	}
	return false
}
