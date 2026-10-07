package tunnel

import (
	"errors"
	"os"
	"syscall"
)

func openCAFile(path string) (*os.File, error) {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	// Open the reparse point itself so a path swap cannot redirect a regular
	// certificate file to a named pipe or device through a symlink.
	handle, err := syscall.CreateFile(name, syscall.GENERIC_READ,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil, syscall.OPEN_EXISTING, syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	kind, err := syscall.GetFileType(handle)
	var info syscall.ByHandleFileInformation
	if err == nil && kind == syscall.FILE_TYPE_DISK {
		err = syscall.GetFileInformationByHandle(handle, &info)
	}
	if err != nil || kind != syscall.FILE_TYPE_DISK || info.FileAttributes&(syscall.FILE_ATTRIBUTE_REPARSE_POINT|syscall.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		syscall.CloseHandle(handle)
		return nil, errors.New("tunnel CA must be a regular disk file")
	}
	return os.NewFile(uintptr(handle), path), nil
}
