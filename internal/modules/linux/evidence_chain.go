package linux

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/s4e-io/openness-collector/internal/modules/common"
	"github.com/s4e-io/openness-collector/internal/schema"
)

// EvidenceChain builds socket→process→binary→package→source chains for listening sockets.
type EvidenceChain struct{}

func (m *EvidenceChain) ID() string          { return "evidence_chain" }
func (m *EvidenceChain) Version() string     { return "1.0.0" }
func (m *EvidenceChain) Platforms() []string { return []string{"linux"} }

const maxChainHashBytes = 32 * 1024 * 1024
const maxChainBinaries = 40

func (m *EvidenceChain) Run(ctx context.Context) schema.ModuleResult {
	started := time.Now()
	res := common.NewResult(m.ID(), m.Version())

	inodeToPID := buildInodePIDMap()
	sockets := collectListenSockets(inodeToPID)
	if len(sockets) == 0 {
		res.Errors = append(res.Errors, common.Err(m.ID(), "unavailable", "no listening sockets discovered"))
		common.Finish(&res, started, "unavailable")
		return res
	}

	ownerCache := map[string]map[string]any{}
	hashCache := map[string]string{}
	seenBin := map[string]bool{}
	hashed := 0

	for _, sock := range sockets {
		select {
		case <-ctx.Done():
			res.Errors = append(res.Errors, common.Err(m.ID(), "timeout", "evidence chain cancelled"))
			common.Finish(&res, started, "partial")
			return res
		default:
		}

		pid := asInt(sock["pid"])
		if pid == 0 {
			gap := "owning_pid_unavailable"
			if asString(sock["uid"]) == "0" {
				// still unknown without pid
			}
			res.Evidence = append(res.Evidence, common.Evidence("native", m.ID(), "observed", map[string]any{
				"entity_id":   sock["entity_id"],
				"entity_type": "evidence_chain",
				"chain":       []string{"socket"},
				"socket":      sock,
				"complete":    false,
				"gap":         gap,
			}, nil))
			continue
		}

		proc, st, _ := readProcess(pid)
		if st != "observed" {
			gap := "permission_denied"
			switch st {
			case "not_found":
				gap = "process_exited"
			case "permission_denied":
				gap = "permission_denied"
			default:
				gap = "process_" + st
			}
			res.Evidence = append(res.Evidence, common.Evidence("native", m.ID(), "observed", map[string]any{
				"entity_id":   sock["entity_id"],
				"entity_type": "evidence_chain",
				"chain":       []string{"socket"},
				"socket":      sock,
				"gap":         gap,
				"complete":    false,
			}, nil))
			continue
		}

		exeReal := asString(proc["executable_realpath"])
		if exeReal == "" {
			exeReal = asString(proc["executable_path"])
		}

		bin := map[string]any{
			"entity_id":   "bin:" + exeReal,
			"entity_type": "binary",
			"path":        nullIfEmpty(exeReal),
			"exists":      false,
			"sha256":      nil,
			"size":        nil,
		}
		owner := map[string]any{"status": "unavailable"}
		if exeReal != "" {
			if stInfo, err := os.Stat(exeReal); err == nil && !stInfo.IsDir() {
				bin["exists"] = true
				bin["size"] = stInfo.Size()
				if !seenBin[exeReal] && hashed < maxChainBinaries && stInfo.Size() > 0 && stInfo.Size() <= maxChainHashBytes {
					seenBin[exeReal] = true
					hashed++
					if h, ok := hashCache[exeReal]; ok {
						bin["sha256"] = h
					} else if h, err := sha256File(exeReal); err == nil {
						hashCache[exeReal] = h
						bin["sha256"] = h
					}
				}
			}
			if o, ok := ownerCache[exeReal]; ok {
				owner = o
			} else {
				owner = PackageOwner(ctx, exeReal)
				ownerCache[exeReal] = owner
			}
			bin["package_owner"] = owner
		}

		pkgName := asString(owner["package_name"])
		var pkgMeta map[string]any
		if pkgName != "" {
			pkgMeta = map[string]any{
				"name":            pkgName,
				"package_manager": owner["package_manager"],
			}
			if owner["package_manager"] == "dpkg" {
				src, ver := dpkgSourceOf(ctx, pkgName)
				pkgMeta["source_package"] = nullIfEmpty(src)
				pkgMeta["source_version"] = ver
				// Repository origin for packages comes from parsing /var/lib/apt/lists
				// in the packages module — never apt-cache here.
				pkgMeta["repository"] = nil
			}
		}

		unit := systemdUnitForPID(ctx, pid)

		rels := []map[string]any{
			{"type": "process_listens_on_socket", "target_entity_id": sock["entity_id"], "confidence": "direct", "evidence_source": "proc_inode_map"},
		}
		if exeReal != "" {
			rels = append(rels, map[string]any{
				"type": "process_executed_binary", "target_entity_id": bin["entity_id"],
				"confidence": "direct", "evidence_source": "/proc/pid/exe",
			})
		}
		if pkgName != "" {
			rels = append(rels, map[string]any{
				"type": "binary_owned_by_package", "target_entity_id": "pkg:dpkg:" + pkgName,
				"confidence": "direct", "evidence_source": "dpkg-query:-S",
			})
			if src := asString(pkgMeta["source_package"]); src != "" {
				rels = append(rels, map[string]any{
					"type": "package_built_from_source_package", "target_entity_id": "srcpkg:dpkg:" + src,
					"confidence": "direct", "evidence_source": "dpkg:Source",
				})
			}
		} else if exeReal != "" && owner["status"] == "not_found" {
			res.Errors = append(res.Errors, common.Err(m.ID(), "BINARY_NOT_PACKAGE_OWNED", exeReal))
		}
		if unit != "" {
			rels = append(rels, map[string]any{
				"type": "process_belongs_to_service", "target_entity_id": "svc:" + unit,
				"confidence": "strong", "evidence_source": "systemctl:pid",
			})
		}

		complete := pid > 0 && exeReal != "" && pkgName != ""
		chain := []string{"socket", "process"}
		if exeReal != "" {
			chain = append(chain, "binary")
		}
		if unit != "" {
			chain = append(chain, "service")
		}
		if pkgName != "" {
			chain = append(chain, "package")
			if pkgMeta != nil && pkgMeta["source_package"] != nil {
				chain = append(chain, "source_package")
			}
			// Repository hop is observed in packages module (apt lists), not here.
		}

		gap := ""
		if !complete {
			switch {
			case exeReal == "":
				gap = "process_path_unavailable"
			case pkgName == "":
				gap = "binary_not_package_owned"
			default:
				gap = "incomplete_chain"
			}
		}

		val := map[string]any{
			"entity_id":     "chain:" + asString(sock["entity_id"]),
			"entity_type":   "evidence_chain",
			"chain":         chain,
			"complete":      complete,
			"socket":        sock,
			"process":       proc,
			"binary":        bin,
			"service_unit":  nullIfEmpty(unit),
			"package":       pkgMeta,
			"relationships": rels,
		}
		if gap != "" {
			val["gap"] = gap
		}
		res.Evidence = append(res.Evidence, common.Evidence("native", m.ID(), "observed", val, nil))
	}

	modStatus := "success"
	for _, ev := range res.Evidence {
		if v, ok := ev.Value.(map[string]any); ok {
			if c, _ := v["complete"].(bool); !c {
				modStatus = "partial"
				break
			}
		}
	}
	common.Finish(&res, started, modStatus)
	return res
}

func collectListenSockets(inodeToPID map[uint64]int) []map[string]any {
	tmp := &schema.ModuleResult{}
	for _, f := range []struct{ path, proto, family string }{
		{"/proc/net/tcp", "tcp", "ipv4"},
		{"/proc/net/tcp6", "tcp", "ipv6"},
		{"/proc/net/udp", "udp", "ipv4"},
		{"/proc/net/udp6", "udp", "ipv6"},
	} {
		_, _ = readProcNet(f.path, f.proto, f.family, inodeToPID, tmp, "evidence_chain")
	}
	out := make([]map[string]any, 0, len(tmp.Evidence))
	for _, ev := range tmp.Evidence {
		if v, ok := ev.Value.(map[string]any); ok {
			v["pid"] = asInt(v["pid"])
			out = append(out, v)
		}
	}
	return out
}

func dpkgSourceOf(ctx context.Context, pkg string) (string, any) {
	cmd := exec.CommandContext(ctx, "dpkg-query", "-W", "-f=${Source}", pkg)
	b, err := cmd.Output()
	if err != nil {
		return pkg, nil
	}
	raw := strings.TrimSpace(string(b))
	if raw == "" {
		return pkg, nil
	}
	return ParseDebianSource(raw)
}

func systemdUnitForPID(ctx context.Context, pid int) string {
	cmd := exec.CommandContext(ctx, "systemctl", "status", strconv.Itoa(pid), "--no-pager", "-n", "0")
	b, _ := cmd.CombinedOutput()
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		line = strings.TrimPrefix(line, "●")
		line = strings.TrimPrefix(line, "○")
		line = strings.TrimSpace(line)
		fields := strings.Fields(line)
		if len(fields) > 0 && strings.HasSuffix(fields[0], ".service") {
			return fields[0]
		}
	}
	return ""
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, maxChainHashBytes)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func asString(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func asInt(v any) int {
	switch t := v.(type) {
	case int:
		return t
	case int64:
		return int(t)
	case float64:
		return int(t)
	case string:
		n, _ := strconv.Atoi(t)
		return n
	default:
		return 0
	}
}
