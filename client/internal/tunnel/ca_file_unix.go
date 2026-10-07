//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package tunnel

import (
	"os"
	"syscall"
)

func openCAFile(path string) (*os.File, error) {
	// NONBLOCK prevents a regular-file-to-FIFO replacement from blocking open.
	// NOFOLLOW rejects replacement with a symlink before descriptor validation.
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}
