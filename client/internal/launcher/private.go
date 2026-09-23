//go:build linux || darwin

package launcher

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

func strictJSON(data []byte, target any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var value func() error
	value = func() error {
		token, err := d.Token()
		if err != nil {
			return ErrConfiguration
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				name, ok := key.(string)
				if err != nil || !ok || seen[name] {
					return ErrConfiguration
				}
				seen[name] = true
				if value() != nil {
					return ErrConfiguration
				}
			}
			end, err := d.Token()
			if err != nil || end != json.Delim('}') {
				return ErrConfiguration
			}
		case '[':
			for d.More() {
				if value() != nil {
					return ErrConfiguration
				}
			}
			end, err := d.Token()
			if err != nil || end != json.Delim(']') {
				return ErrConfiguration
			}
		default:
			return ErrConfiguration
		}
		return nil
	}
	if value() != nil {
		return ErrConfiguration
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrConfiguration
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(target) != nil || d.Decode(new(any)) != io.EOF {
		return ErrConfiguration
	}
	return nil
}

func privateRead(path string, target any) error {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return ErrConfiguration
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 16384 {
		return ErrConfiguration
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(owner.Uid) != os.Getuid() || owner.Nlink != 1 {
		return ErrConfiguration
	}
	data, err := io.ReadAll(io.LimitReader(file, 16385))
	if err != nil || len(data) > 16384 {
		return ErrConfiguration
	}
	return strictJSON(data, target)
}

func privateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return ErrConfiguration
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(owner.Uid) != os.Getuid() {
		return ErrConfiguration
	}
	return nil
}

func saveState(path string, config Config) error {
	directory := filepath.Dir(path)
	if privateDirectory(directory) != nil {
		return ErrConfiguration
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return ErrConfiguration
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || int(owner.Uid) != os.Getuid() || owner.Nlink != 1 {
			return ErrConfiguration
		}
	} else if !os.IsNotExist(err) {
		return ErrConfiguration
	}
	data, err := json.Marshal(config)
	if err != nil || len(data) > 16384 {
		return ErrConfiguration
	}
	file, err := os.CreateTemp(directory, ".runtime-state-")
	if err != nil {
		return ErrConfiguration
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	defer file.Close()
	if file.Chmod(0600) != nil {
		return ErrConfiguration
	}
	if _, err = file.Write(data); err != nil {
		return ErrConfiguration
	}
	if file.Sync() != nil || file.Close() != nil {
		return ErrConfiguration
	}
	if os.Rename(temporary, path) != nil {
		return ErrConfiguration
	}
	parent, err := os.Open(directory)
	if err != nil {
		return ErrConfiguration
	}
	defer parent.Close()
	if parent.Sync() != nil {
		return ErrConfiguration
	}
	return nil
}

func lockState(directory string) (func(), error) {
	if privateDirectory(directory) != nil {
		return nil, ErrConfiguration
	}
	file, err := os.OpenFile(filepath.Join(directory, "launcher.lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return nil, ErrConfiguration
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		file.Close()
		return nil, ErrConfiguration
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(owner.Uid) != os.Getuid() || owner.Nlink != 1 {
		file.Close()
		return nil, ErrConfiguration
	}
	if syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		file.Close()
		return nil, ErrBusy
	}
	return func() { _ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN); _ = file.Close() }, nil
}
