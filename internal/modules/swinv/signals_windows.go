//go:build windows

package swinv

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// hostRoots returns the system drive root. Other fixed drives are a later
// slice; the catalog paths use %ProgramFiles% style anchors under it.
func hostRoots() []string {
	d := os.Getenv("SystemDrive")
	if d == "" {
		d = "C:"
	}
	return []string{d + `\`}
}

// runningProcesses uses the toolhelp snapshot (no WMI, no PowerShell).
// Image paths need OpenProcess; protected processes yield an empty path.
func runningProcesses() []procInfo {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(snap)
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	if err := windows.Process32First(snap, &pe); err != nil {
		return nil
	}
	var out []procInfo
	for {
		p := procInfo{PID: int(pe.ProcessID), Name: windows.UTF16ToString(pe.ExeFile[:])}
		if h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pe.ProcessID); err == nil {
			buf := make([]uint16, 1024)
			n := uint32(len(buf))
			if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err == nil {
				p.Exe = windows.UTF16ToString(buf[:n])
			}
			windows.CloseHandle(h)
		}
		if p.Name != "" {
			out = append(out, p)
		}
		if len(out) >= maxProcesses {
			break
		}
		if err := windows.Process32Next(snap, &pe); err != nil {
			break
		}
	}
	return out
}

// listeningTCPPorts maps each listening TCP port (IPv4 and IPv6) to the
// owning pids via GetExtendedTcpTable(TCP_TABLE_OWNER_PID_LISTENER).
func listeningTCPPorts() map[int][]int {
	ports := map[int][]int{}
	proc := windows.NewLazySystemDLL("iphlpapi.dll").NewProc("GetExtendedTcpTable")
	if proc.Find() != nil {
		return ports
	}
	const tcpTableOwnerPIDListener = 3
	// family, row size, offset of local port, state and owning pid in a row.
	layouts := []struct{ af, row, port, state, pid int }{
		{windows.AF_INET, 24, 8, 0, 20},    // MIB_TCPROW_OWNER_PID
		{windows.AF_INET6, 56, 20, 48, 52}, // MIB_TCP6ROW_OWNER_PID
	}
	for _, l := range layouts {
		var size uint32
		proc.Call(0, uintptr(unsafe.Pointer(&size)), 0, uintptr(l.af), tcpTableOwnerPIDListener, 0)
		if size == 0 || size > 16<<20 {
			continue
		}
		buf := make([]byte, size)
		r, _, _ := proc.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, uintptr(l.af), tcpTableOwnerPIDListener, 0)
		if r != 0 {
			continue
		}
		n := int(*(*uint32)(unsafe.Pointer(&buf[0])))
		for i := 0; i < n; i++ {
			off := 4 + i*l.row
			if off+l.row > len(buf) {
				break
			}
			if *(*uint32)(unsafe.Pointer(&buf[off+l.state])) != 2 { // MIB_TCP_STATE_LISTEN
				continue
			}
			lp := *(*uint32)(unsafe.Pointer(&buf[off+l.port]))
			// Port is in network byte order in the low 16 bits.
			port := int((lp&0xff)<<8 | (lp>>8)&0xff)
			pid := int(*(*uint32)(unsafe.Pointer(&buf[off+l.pid])))
			ports[port] = appendUnique(ports[port], pid)
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

// registryHits expands a key glob under HKLM. Only the last path element may
// contain a wildcard (KEY_*, MySQL Server *).
func registryHits(sig RegistrySignal) []registryHit {
	key := strings.TrimPrefix(strings.TrimPrefix(sig.Key, `HKLM\`), `HKEY_LOCAL_MACHINE\`)
	parent, leaf := filepath.Split(filepath.FromSlash(key))
	parent = strings.TrimSuffix(parent, `\`)
	var keys []string
	if strings.ContainsAny(leaf, "*?") {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, parent, registry.ENUMERATE_SUB_KEYS)
		if err != nil {
			return nil
		}
		names, _ := k.ReadSubKeyNames(maxGlobMatches)
		k.Close()
		for _, n := range names {
			if ok, _ := filepath.Match(leaf, n); ok {
				keys = append(keys, parent+`\`+n)
			}
		}
	} else {
		keys = []string{key}
	}
	var out []registryHit
	for _, k := range keys {
		rk, err := registry.OpenKey(registry.LOCAL_MACHINE, k, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		h := registryHit{Key: `HKLM\` + k}
		if sig.InstallPathValue != "" {
			if v, _, err := rk.GetStringValue(sig.InstallPathValue); err == nil {
				h.InstallPath = strings.TrimRight(v, `\`)
			}
		}
		rk.Close()
		out = append(out, h)
	}
	return out
}

// registryValue reads a string or DWORD value under a hit key (plus optional
// relative subpath from the reader).
func registryValue(h registryHit, r Reader) (string, string, bool) {
	key := strings.TrimPrefix(h.Key, `HKLM\`)
	if r.Path != "" {
		key = key + `\` + strings.Trim(r.Path, `\`)
	}
	rk, err := registry.OpenKey(registry.LOCAL_MACHINE, key, registry.QUERY_VALUE)
	if err != nil {
		return "", "", false
	}
	defer rk.Close()
	src := `HKLM\` + key + `:` + r.Value
	if v, _, err := rk.GetStringValue(r.Value); err == nil && v != "" {
		return v, src, true
	}
	if v, _, err := rk.GetIntegerValue(r.Value); err == nil {
		return fmt.Sprintf("%d", v), src, true
	}
	return "", "", false
}

// peVersion reads the fixed file version from a PE resource (no execution).
func peVersion(path string) (string, bool) {
	size, err := windows.GetFileVersionInfoSize(path, nil)
	if err != nil || size == 0 {
		return "", false
	}
	buf := make([]byte, size)
	if err := windows.GetFileVersionInfo(path, 0, size, unsafe.Pointer(&buf[0])); err != nil {
		return "", false
	}
	var fixed *windows.VS_FIXEDFILEINFO
	var n uint32
	if err := windows.VerQueryValue(unsafe.Pointer(&buf[0]), `\`, unsafe.Pointer(&fixed), &n); err != nil || fixed == nil {
		return "", false
	}
	v := fmt.Sprintf("%d.%d.%d.%d",
		fixed.FileVersionMS>>16, fixed.FileVersionMS&0xffff,
		fixed.FileVersionLS>>16, fixed.FileVersionLS&0xffff)
	return v, true
}
