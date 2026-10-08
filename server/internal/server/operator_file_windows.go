//go:build windows

package server

import (
	"fmt"
	"os"
)

func openOperatorFile(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("operator configuration must be a regular file")
	}
	return os.Open(path)
}

// Private ingress requires an audited filesystem ownership boundary.
func operatorFileOwnerAllowed(os.FileInfo) bool         { return false }
func operatorFileGroupAllowed(os.FileInfo, uint32) bool { return false }
func operatorGroupMember(uint32) bool                   { return false }
