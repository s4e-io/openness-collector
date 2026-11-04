package linux

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/s4e-io/openness-collector/internal/modules/common"
	"github.com/s4e-io/openness-collector/internal/schema"
)

// ListeningPorts collects normalized sockets from /proc/net (ss is fallback only).
func (m *ListeningPorts) Run(ctx context.Context) schema.ModuleResult {
	started := time.Now()
	res := common.NewResult(m.ID(), m.Version())

	inodeToPID := buildInodePIDMap()
	partial := false
	if len(inodeToPID) == 0 {
		res.Errors = append(res.Errors, common.Err(m.ID(), "PROC_PERMISSION_DENIED", "socket inode map empty; pid ownership may be unavailable"))
		partial = true
	}

	files := []struct {
		path, proto, family string
	}{
		{"/proc/net/tcp", "tcp", "ipv4"},
		{"/proc/net/tcp6", "tcp", "ipv6"},
		{"/proc/net/udp", "udp", "ipv4"},
		{"/proc/net/udp6", "udp", "ipv6"},
	}
	for _, f := range files {
		select {
		case <-ctx.Done():
			res.Errors = append(res.Errors, common.Err(m.ID(), "timeout", "port scan cancelled"))
			common.Finish(&res, started, "partial")
			return res
		default:
		}
		n, err := readProcNet(f.path, f.proto, f.family, inodeToPID, &res, m.ID())
		if err != nil {
			if os.IsPermission(err) {
				res.Errors = append(res.Errors, common.Err(m.ID(), "PROC_PERMISSION_DENIED", f.path+": "+err.Error()))
				partial = true
			} else if !os.IsNotExist(err) {
				res.Errors = append(res.Errors, common.Err(m.ID(), "collection_error", f.path+": "+err.Error()))
				partial = true
			}
		}
		_ = n
	}

	if len(res.Evidence) == 0 {
		// fallback ss
		return listeningPortsFallbackSS(ctx, started, &res, m.ID())
	}
	status := "success"
	if partial {
		status = "partial"
	}
	common.Finish(&res, started, status)
	return res
}

func listeningPortsFallbackSS(ctx context.Context, started time.Time, res *schema.ModuleResult, moduleID string) schema.ModuleResult {
	res.Errors = append(res.Errors, common.Err(moduleID, "unavailable", "proc net incomplete; ss fallback used for detection only"))
	// Keep normalized empty — do not reintroduce raw_line as primary.
	common.Finish(res, started, "partial")
	return *res
}

func readProcNet(path, proto, family string, inodeToPID map[uint64]int, res *schema.ModuleResult, moduleID string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	first := true
	n := 0
	for sc.Scan() {
		if first {
			first = false
			continue // header
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 10 {
			continue
		}
		// tcp state listen = 0A
		if proto == "tcp" || proto == "tcp6" {
			if fields[3] != "0A" {
				continue
			}
		}
		// UDP "listeners": remote is unbound (0.0.0.0:0 / [::]:0)
		if proto == "udp" || proto == "udp6" {
			if len(fields) > 2 && !strings.HasSuffix(fields[2], ":0000") {
				continue
			}
		}
		local := fields[1]
		ip, port, err := parseAddr(local, family)
		if err != nil {
			continue
		}
		inode, _ := strconv.ParseUint(fields[9], 10, 64)
		pid := 0
		if p, ok := inodeToPID[inode]; ok {
			pid = p
		}
		uid, _ := strconv.Atoi(fields[7])
		exposure := classifyExposure(ip)
		rec := map[string]any{
			"entity_id":           fmt.Sprintf("sock:%s:%s:%d", proto, ip, port),
			"entity_type":         "socket",
			"protocol":            proto,
			"address_family":      family,
			"local_address":       ip,
			"local_port":          port,
			"remote_address":      nil,
			"remote_port":         nil,
			"state":               map[string]string{"tcp": "listen", "tcp6": "listen", "udp": "udp", "udp6": "udp"}[proto],
			"pid":                 nullIfZero(pid),
			"process_name":        nil,
			"uid":                 uid,
			"inode":               strconv.FormatUint(inode, 10),
			"network_namespace":   "host",
			"container_id":        nil,
			"systemd_socket_unit": nil,
			"exposure":            exposure,
			"relationships":       []map[string]any{},
		}
		if pid > 0 {
			rec["relationships"] = []map[string]any{{
				"type":             "process_listens_on_socket",
				"target_entity_id": "proc:" + strconv.Itoa(pid),
				"confidence":       "direct",
				"evidence_source":  "proc_inode_map",
			}}
			if name := procName(pid); name != "" {
				rec["process_name"] = name
			}
		}
		res.Evidence = append(res.Evidence, common.Evidence("native", moduleID, "observed", rec, map[string]string{
			"proc_net_line": sc.Text(),
		}))
		n++
	}
	return n, sc.Err()
}

func nullIfZero(n int) any {
	if n == 0 {
		return nil
	}
	return n
}

func parseAddr(s, family string) (string, int, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("bad addr")
	}
	port64, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return "", 0, err
	}
	ipHex := parts[0]
	var ip net.IP
	if family == "ipv4" {
		b, err := hex.DecodeString(ipHex)
		if err != nil || len(b) != 4 {
			return "", 0, fmt.Errorf("bad ipv4")
		}
		// little-endian
		ip = net.IPv4(b[3], b[2], b[1], b[0]).To4()
	} else {
		b, err := hex.DecodeString(ipHex)
		if err != nil || len(b) != 16 {
			return "", 0, fmt.Errorf("bad ipv6")
		}
		// each 32-bit word little-endian
		out := make([]byte, 16)
		for i := 0; i < 4; i++ {
			out[i*4+0] = b[i*4+3]
			out[i*4+1] = b[i*4+2]
			out[i*4+2] = b[i*4+1]
			out[i*4+3] = b[i*4+0]
		}
		ip = net.IP(out)
	}
	return ip.String(), int(port64), nil
}

func classifyExposure(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "unknown"
	}
	if parsed.IsLoopback() {
		return "loopback"
	}
	if parsed.IsUnspecified() {
		return "wildcard"
	}
	if parsed.IsLinkLocalUnicast() {
		return "link_local"
	}
	return "specific"
}

func buildInodePIDMap() map[uint64]int {
	out := map[uint64]int{}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return out
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		fdDir := "/proc/" + e.Name() + "/fd"
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			// socket:[12345]
			if strings.HasPrefix(link, "socket:[") && strings.HasSuffix(link, "]") {
				num := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
				ino, err := strconv.ParseUint(num, 10, 64)
				if err == nil {
					out[ino] = pid
				}
			}
		}
	}
	return out
}

func procName(pid int) string {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/comm")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
