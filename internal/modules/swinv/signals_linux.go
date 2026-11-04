//go:build linux

package swinv

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// hostRoots returns the scan roots for the host. Linux has one root.
func hostRoots() []string { return []string{"/"} }

// runningProcesses lists pid, executable path and comm from /proc. It reads
// only; unreadable exe links (other users' processes without root) yield an
// empty path and the comm name is still usable for matching.
func runningProcesses() []procInfo {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var out []procInfo
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 0 {
			continue
		}
		p := procInfo{PID: pid}
		if exe, err := os.Readlink(filepath.Join("/proc", e.Name(), "exe")); err == nil {
			p.Exe = strings.TrimSuffix(exe, " (deleted)")
		}
		if b, err := os.ReadFile(filepath.Join("/proc", e.Name(), "comm")); err == nil {
			p.Name = strings.TrimSpace(string(b))
		}
		if p.Name == "" && p.Exe != "" {
			p.Name = filepath.Base(p.Exe)
		}
		if p.Name == "" {
			continue
		}
		out = append(out, p)
		if len(out) >= maxProcesses {
			break
		}
	}
	return out
}

// listeningTCPPorts maps each listening TCP port (/proc/net/tcp{,6}) to the
// pids owning the socket, found by matching socket inodes in /proc/<pid>/fd.
// Without root other users' fds are unreadable and the owner list stays
// empty: the port is still observed but attributed to nobody.
func listeningTCPPorts() map[int][]int {
	ports := map[int][]int{}
	byInode := map[string][]int{}
	for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		fh, err := os.Open(f)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(fh)
		sc.Scan() // header
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) < 10 || fields[3] != "0A" {
				continue
			}
			i := strings.LastIndex(fields[1], ":")
			if i < 0 {
				continue
			}
			port, err := strconv.ParseUint(fields[1][i+1:], 16, 16)
			if err != nil {
				continue
			}
			if _, ok := ports[int(port)]; !ok {
				ports[int(port)] = nil
			}
			if fields[9] != "0" {
				byInode[fields[9]] = append(byInode[fields[9]], int(port))
			}
		}
		fh.Close()
	}
	if len(byInode) == 0 {
		return ports
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return ports
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 0 {
			continue
		}
		fdDir := filepath.Join("/proc", e.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			for _, port := range byInode[strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")] {
				ports[port] = appendUnique(ports[port], pid)
			}
		}
	}
	return ports
}

func appendUnique(s []int, v int) []int {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

// registryHits is a no-op on Linux.
func registryHits(_ RegistrySignal) []registryHit { return nil }

// registryValue is a no-op on Linux.
func registryValue(_ registryHit, _ Reader) (string, string, bool) { return "", "", false }

// peVersion is a no-op on Linux. PE resources are a Windows concern in v1.
func peVersion(_ string) (string, bool) { return "", false }
