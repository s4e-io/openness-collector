//go:build windows

package linux

import "os"

func fileOwnerUID(fi os.FileInfo) int { return 0 }

func fileInodeKey(fi os.FileInfo) string { return "" }
