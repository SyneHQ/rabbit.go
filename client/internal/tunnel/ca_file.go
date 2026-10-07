package tunnel

import (
	"context"
	"errors"
	"io"
	"os"
)

const maxCAFileBytes = 1 << 20

// readCAFile accepts a bounded regular file. It deliberately rejects symlinks
// and device/FIFO paths; certificate rotation may replace the regular file.
// Reads have a byte bound; filesystem I/O latency still depends on the OS.
func readCAFile(ctx context.Context, path string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("tunnel CA must be a readable regular file")
	}
	if info.Size() > maxCAFileBytes {
		return nil, errors.New("tunnel CA exceeds 1 MiB")
	}
	file, err := openCAFile(path)
	if err != nil {
		return nil, errors.New("cannot open regular tunnel CA file")
	}
	defer file.Close()
	info, err = file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("tunnel CA must be a readable regular file")
	}
	if info.Size() > maxCAFileBytes {
		return nil, errors.New("tunnel CA exceeds 1 MiB")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	pem, err := io.ReadAll(io.LimitReader(file, maxCAFileBytes+1))
	if err != nil {
		return nil, errors.New("cannot read tunnel CA file")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(pem) > maxCAFileBytes {
		return nil, errors.New("tunnel CA exceeds 1 MiB")
	}
	return pem, nil
}
