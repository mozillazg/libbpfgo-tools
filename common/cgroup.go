package common

import (
	"fmt"
	"syscall"
)

func GetCgroupDirFD(cgroupV2DirPath string) (int, error) {
	const (
		O_DIRECTORY int = 0200000
		O_RDONLY    int = 00
	)
	fd, err := syscall.Open(cgroupV2DirPath, O_DIRECTORY|O_RDONLY, 0)
	if fd < 0 {
		return 0, fmt.Errorf("failed to open cgroupv2 directory path %s: %w", cgroupV2DirPath, err)
	}
	return fd, nil
}
