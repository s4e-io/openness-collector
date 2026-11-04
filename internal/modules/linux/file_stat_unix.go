//go:build unix

package linux

import (
	"os"
	"strconv"
	"syscall"
)

func fileOwnerUID(fi os.FileInfo) int {
	sys, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0
	}
	return int(sys.Uid)
}

func fileInodeKey(fi os.FileInfo) string {
	sys, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	return strconv.FormatUint(uint64(sys.Dev), 10) + ":" + strconv.FormatUint(sys.Ino, 10)
}
