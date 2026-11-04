package linux

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/s4e-io/openness-collector/internal/modules/common"
	"github.com/s4e-io/openness-collector/internal/schema"
)

type KernelInventory struct{}

func (m *KernelInventory) ID() string          { return "kernel_inventory" }
func (m *KernelInventory) Version() string     { return "1.1.0" }
func (m *KernelInventory) Platforms() []string { return []string{"linux"} }

func (m *KernelInventory) Run(ctx context.Context) schema.ModuleResult {
	started := time.Now()
	res := common.NewResult(m.ID(), m.Version())

	running, _ := os.ReadFile("/proc/sys/kernel/osrelease")
	rebootRequired, rebootPkgs := readRebootRequired()
	value := map[string]any{
		"running_kernel":           strings.TrimSpace(string(running)),
		"kernel_architecture":      readCmd(ctx, "uname", "-m"),
		"reboot_required":          rebootRequired,
		"reboot_required_packages": rebootPkgs,
	}

	if out := readCmd(ctx, "uname", "-r"); out != "" {
		value["kernel_package_hint"] = out
	}

	modules := []string{}
	if f, err := os.Open("/proc/modules"); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) > 0 {
				modules = append(modules, fields[0])
			}
		}
		_ = f.Close()
	}
	value["loaded_modules_count"] = len(modules)
	value["loaded_modules"] = modules

	res.Evidence = append(res.Evidence, common.Evidence("native", m.ID(), "observed", value, nil))
	common.Finish(&res, started, "success")
	return res
}

type Services struct{}

func (m *Services) ID() string          { return "services" }
func (m *Services) Version() string     { return "1.1.0" }
func (m *Services) Platforms() []string { return []string{"linux"} }

func (m *Services) Run(ctx context.Context) schema.ModuleResult {
	started := time.Now()
	res := common.NewResult(m.ID(), m.Version())

	if _, err := exec.LookPath("systemctl"); err != nil {
		res.Errors = append(res.Errors, common.Err(m.ID(), "unavailable", "systemctl not found"))
		common.Finish(&res, started, "unavailable")
		return res
	}

	cmd := exec.CommandContext(ctx, "systemctl", "list-units", "--type=service", "--all", "--no-pager", "--no-legend", "--plain")
	out, err := cmd.Output()
	if err != nil {
		res.Errors = append(res.Errors, common.Err(m.ID(), "collection_error", err.Error()))
		common.Finish(&res, started, "error")
		return res
	}

	type unitRow struct{ name, load, active, sub string }
	var units []unitRow
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 {
			continue
		}
		units = append(units, unitRow{fields[0], fields[1], fields[2], fields[3]})
	}

	// Enrich active (and a capped set of inactive) via systemctl show — machine-readable.
	enriched := 0
	const maxEnrich = 120
	for _, u := range units {
		select {
		case <-ctx.Done():
			res.Errors = append(res.Errors, common.Err(m.ID(), "timeout", "service enrich cancelled"))
			common.Finish(&res, started, "partial")
			return res
		default:
		}
		value := map[string]any{
			"entity_id":       "svc:" + u.name,
			"entity_type":     "service",
			"unit_name":       u.name,
			"service_name":    u.name,
			"load_state":      u.load,
			"active_state":    u.active,
			"sub_state":       u.sub,
			"init_system":     "systemd",
			"description":     nil,
			"unit_file_state": nil,
			"fragment_path":   nil,
			"exec_start":      []string{},
			"main_pid":        nil,
			"user":            nil,
			"relationships":   []map[string]any{},
		}
		doShow := u.active == "active" || enriched < maxEnrich
		if doShow {
			props := systemctlShow(ctx, u.name)
			if props != nil {
				enriched++
				if v := props["Description"]; v != "" {
					value["description"] = v
				}
				if v := props["UnitFileState"]; v != "" {
					value["unit_file_state"] = v
				}
				if v := props["FragmentPath"]; v != "" {
					value["fragment_path"] = v
				}
				if v := props["ExecStart"]; v != "" {
					value["exec_start"] = []string{v}
				}
				if v := props["MainPID"]; v != "" && v != "0" {
					if pid, err := strconv.Atoi(v); err == nil {
						value["main_pid"] = pid
						value["relationships"] = []map[string]any{{
							"type":             "process_belongs_to_service",
							"target_entity_id": "proc:" + v,
							"confidence":       "direct",
							"evidence_source":  "systemctl:MainPID",
						}}
					}
				}
				if v := props["User"]; v != "" {
					value["user"] = v
				}
			}
		}
		res.Evidence = append(res.Evidence, common.Evidence("native", m.ID(), "observed", value, nil))
	}
	common.Finish(&res, started, "success")
	return res
}

func systemctlShow(ctx context.Context, unit string) map[string]string {
	cmd := exec.CommandContext(ctx, "systemctl", "show", unit,
		"--property=Description,UnitFileState,FragmentPath,ExecStart,MainPID,User,Id,Type",
		"--no-pager")
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	m := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if ok {
			m[k] = v
		}
	}
	return m
}

type Processes struct{}

func (m *Processes) ID() string          { return "processes" }
func (m *Processes) Version() string     { return "1.1.0" }
func (m *Processes) Platforms() []string { return []string{"linux"} }

type ListeningPorts struct{}

func (m *ListeningPorts) ID() string          { return "listening_ports" }
func (m *ListeningPorts) Version() string     { return "1.1.0" }
func (m *ListeningPorts) Platforms() []string { return []string{"linux"} }

type SecurityConfiguration struct{}

func (m *SecurityConfiguration) ID() string          { return "security_configuration" }
func (m *SecurityConfiguration) Version() string     { return "1.2.0" }
func (m *SecurityConfiguration) Platforms() []string { return []string{"linux"} }

func (m *SecurityConfiguration) Run(ctx context.Context) schema.ModuleResult {
	started := time.Now()
	res := common.NewResult(m.ID(), m.Version())

	selinux := probeCmd(ctx, "getenforce")
	apparmor := probeCmd(ctx, "aa-status", "--enabled")
	ufw := probeCmd(ctx, "ufw", "status")
	firewalld := probeService(ctx, "firewalld")
	auditd := probeService(ctx, "auditd")

	value := map[string]any{
		"selinux":      selinux.asMap(),
		"apparmor":     apparmor.asMap(),
		"firewalld":    firewalld.asMap(),
		"ufw":          ufw.asMap(),
		"auditd":       auditd.asMap(),
		"secure_boot":  readTrim("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c") != "",
		"ssh_version":  readCmd(ctx, "ssh", "-V"),
		"sudo_version": firstLine(readCmd(ctx, "sudo", "--version")),
	}
	enrichSecurityWithEffective(ctx, value)

	denied := 0
	for _, p := range []probeResult{selinux, apparmor, ufw, firewalld, auditd} {
		if p.Status == "permission_denied" {
			denied++
			res.Errors = append(res.Errors, common.Err(m.ID(), "permission_denied", p.Name+": "+p.Message))
		}
	}

	evStatus := "observed"
	modStatus := "success"
	switch {
	case denied > 0 && denied < 5:
		modStatus = "partial"
	case denied >= 5:
		evStatus = "permission_denied"
		modStatus = "permission_denied"
	}
	res.Evidence = append(res.Evidence, common.Evidence("native", m.ID(), evStatus, value, nil))
	common.Finish(&res, started, modStatus)
	return res
}

type probeResult struct {
	Name    string
	Status  string // observed | permission_denied | unavailable
	Value   string
	Message string
}

func (p probeResult) asMap() map[string]any {
	return map[string]any{
		"status":  p.Status,
		"value":   p.Value,
		"message": p.Message,
	}
}

func probeCmd(ctx context.Context, name string, args ...string) probeResult {
	pr := probeResult{Name: name, Status: "unavailable"}
	if _, err := exec.LookPath(name); err != nil {
		pr.Message = "not found"
		return pr
	}
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	s := strings.TrimSpace(string(out))
	if err != nil {
		lower := strings.ToLower(s + " " + err.Error())
		if looksLikePermissionDenied(lower) {
			pr.Status = "permission_denied"
			pr.Message = truncateMsg(s)
			if pr.Message == "" {
				pr.Message = err.Error()
			}
			return pr
		}
		pr.Status = "unavailable"
		pr.Message = truncateMsg(s)
		if pr.Message == "" {
			pr.Message = err.Error()
		}
		return pr
	}
	if looksLikePermissionDenied(strings.ToLower(s)) {
		pr.Status = "permission_denied"
		pr.Message = truncateMsg(s)
		return pr
	}
	pr.Status = "observed"
	pr.Value = s
	return pr
}

func probeService(ctx context.Context, name string) probeResult {
	pr := probeCmd(ctx, "systemctl", "is-active", name)
	pr.Name = name
	return pr
}

func looksLikePermissionDenied(s string) bool {
	s = strings.ToLower(s)
	needles := []string{
		"permission denied",
		"you need to be root",
		"must be root",
		"operation not permitted",
		"access denied",
		"requires root",
		"only root",
	}
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

func truncateMsg(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 200 {
		return s[:200]
	}
	return s
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return s
}

type Users struct{}

func (m *Users) ID() string          { return "users" }
func (m *Users) Version() string     { return "1.0.0" }
func (m *Users) Platforms() []string { return []string{"linux"} }

func (m *Users) Run(ctx context.Context) schema.ModuleResult {
	started := time.Now()
	res := common.NewResult(m.ID(), m.Version())
	f, err := os.Open("/etc/passwd")
	if err != nil {
		res.Errors = append(res.Errors, common.Err(m.ID(), "permission_denied", err.Error()))
		common.Finish(&res, started, "permission_denied")
		return res
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.Split(sc.Text(), ":")
		if len(parts) < 7 {
			continue
		}
		uid, _ := strconv.Atoi(parts[2])
		gid, _ := strconv.Atoi(parts[3])
		value := map[string]any{
			"username": parts[0],
			"uid":      uid,
			"gid":      gid,
			"gecos":    parts[4],
			"home":     parts[5],
			"shell":    parts[6],
		}
		res.Evidence = append(res.Evidence, common.Evidence("native", m.ID(), "observed", value, map[string]string{"raw": sc.Text()}))
	}
	common.Finish(&res, started, "success")
	return res
}

type NetworkInventory struct{}

func (m *NetworkInventory) ID() string          { return "network_inventory" }
func (m *NetworkInventory) Version() string     { return "1.0.0" }
func (m *NetworkInventory) Platforms() []string { return []string{"linux"} }

func (m *NetworkInventory) Run(ctx context.Context) schema.ModuleResult {
	started := time.Now()
	res := common.NewResult(m.ID(), m.Version())
	out := readCmd(ctx, "ip", "-o", "addr", "show")
	if out == "" {
		out = readCmd(ctx, "ifconfig", "-a")
	}
	if out == "" {
		res.Errors = append(res.Errors, common.Err(m.ID(), "unavailable", "no network tools"))
		common.Finish(&res, started, "unavailable")
		return res
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		res.Evidence = append(res.Evidence, common.Evidence("native", m.ID(), "observed", map[string]any{"raw_line": line}, nil))
	}
	common.Finish(&res, started, "success")
	return res
}

func readCmd(ctx context.Context, name string, args ...string) string {
	if _, err := exec.LookPath(name); err != nil {
		return ""
	}
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	s := strings.TrimSpace(string(out))
	if err != nil && s == "" {
		return ""
	}
	return s
}

func serviceActive(ctx context.Context, name string) string {
	return readCmd(ctx, "systemctl", "is-active", name)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
