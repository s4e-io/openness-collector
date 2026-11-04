package linux

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// collectOpenSSHEffective gathers effective sshd settings via allowlisted `sshd -T`.
// Never mutates configuration. Records includes/sources when discoverable from unit/cmdline.
func collectOpenSSHEffective(ctx context.Context) map[string]any {
	out := map[string]any{
		"adapter":               "openssh",
		"status":                "unavailable",
		"effective":             map[string]string{},
		"configuration_sources": []string{},
		"parse_errors":          []string{},
		"permission_failure":    false,
	}
	bin, err := exec.LookPath("sshd")
	if err != nil {
		out["status"] = "tool_not_installed"
		out["message"] = "sshd not found"
		return out
	}
	out["sshd_path"] = bin

	// Discover config path from systemd unit if present (read-only).
	sources := []string{}
	for _, u := range []string{"/lib/systemd/system/ssh.service", "/lib/systemd/system/sshd.service", "/etc/systemd/system/ssh.service"} {
		if b, err := os.ReadFile(u); err == nil {
			sources = append(sources, u)
			for _, line := range strings.Split(string(b), "\n") {
				if strings.Contains(line, "/sshd") && strings.Contains(line, "-f") {
					// ExecStart=... -f /path
					fields := strings.Fields(line)
					for i, f := range fields {
						if f == "-f" && i+1 < len(fields) {
							sources = append(sources, fields[i+1])
						}
					}
				}
			}
		}
	}
	if st, err := os.Stat("/etc/ssh/sshd_config"); err == nil && st.Mode().IsRegular() {
		sources = append(sources, "/etc/ssh/sshd_config")
	}
	dropins, _ := filepath.Glob("/etc/ssh/sshd_config.d/*.conf")
	sources = append(sources, dropins...)
	out["configuration_sources"] = uniqueStrings(sources)

	cmd := exec.CommandContext(ctx, bin, "-T")
	b, err := cmd.CombinedOutput()
	s := strings.TrimSpace(string(b))
	if err != nil {
		low := strings.ToLower(s + " " + err.Error())
		if looksLikePermissionDenied(low) {
			out["status"] = "permission_denied"
			out["permission_failure"] = true
			out["message"] = truncateMsg(s)
			return out
		}
		out["status"] = "parse_error"
		out["parse_errors"] = []string{truncateMsg(s)}
		out["message"] = err.Error()
		return out
	}

	effective := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, " ", 2)
		if len(parts) == 0 {
			continue
		}
		key := strings.ToLower(parts[0])
		val := ""
		if len(parts) > 1 {
			val = strings.TrimSpace(parts[1])
		}
		// Redact potential secrets in banner/authorized keys paths values are paths, OK.
		if key == "authorizedkeyscommand" || key == "authorizedkeyscommanduser" {
			val = RedactSecrets(val)
		}
		effective[key] = val
	}
	out["effective"] = effective
	out["effective_count"] = len(effective)
	out["status"] = "observed"
	// Highlight commonly security-relevant keys without deciding vulnerability.
	highlights := map[string]string{}
	for _, k := range []string{"passwordauthentication", "permitrootlogin", "pubkeyauthentication", "port", "protocol", "x11forwarding", "allowusers", "denyusers", "ciphers", "macs", "kexalgorithms"} {
		if v, ok := effective[k]; ok {
			highlights[k] = v
		}
	}
	out["highlights"] = highlights
	return out
}

// collectSysctlEffective gathers runtime sysctl values and persistent source files.
func collectSysctlEffective(ctx context.Context) map[string]any {
	out := map[string]any{
		"adapter":               "sysctl",
		"status":                "unavailable",
		"runtime":               map[string]string{},
		"persistent_sources":    []map[string]any{},
		"conflicts":             []map[string]any{},
		"kernel_cmdline_params": []string{},
	}

	// Runtime: allowlisted important keys via /proc/sys (no sysctl -w).
	keys := []string{
		"net.ipv4.ip_forward",
		"net.ipv4.conf.all.rp_filter",
		"net.ipv4.conf.default.rp_filter",
		"net.ipv4.tcp_syncookies",
		"net.ipv4.conf.all.accept_redirects",
		"net.ipv4.conf.all.send_redirects",
		"net.ipv4.conf.all.accept_source_route",
		"kernel.randomize_va_space",
		"kernel.kptr_restrict",
		"kernel.dmesg_restrict",
		"kernel.yama.ptrace_scope",
		"fs.suid_dumpable",
		"vm.swappiness",
	}
	runtime := map[string]string{}
	for _, k := range keys {
		path := sysctlKeyToProcPath(k)
		if b, err := os.ReadFile(path); err == nil {
			runtime[k] = strings.TrimSpace(string(b))
		}
	}
	out["runtime"] = runtime
	out["runtime_count"] = len(runtime)

	// Persistent sources (read-only).
	files := []string{"/etc/sysctl.conf"}
	more, _ := filepath.Glob("/etc/sysctl.d/*.conf")
	files = append(files, more...)
	more2, _ := filepath.Glob("/usr/lib/sysctl.d/*.conf")
	files = append(files, more2...)
	more3, _ := filepath.Glob("/run/sysctl.d/*.conf")
	files = append(files, more3...)

	persistent := map[string][]string{} // key -> values in precedence order (later overrides)
	var sources []map[string]any
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		parsed := parseSysctlConf(string(b))
		sources = append(sources, map[string]any{
			"path":      f,
			"key_count": len(parsed),
			"keys":      keysOf(parsed),
			"readable":  true,
		})
		for k, v := range parsed {
			persistent[k] = append(persistent[k], v)
		}
	}
	out["persistent_sources"] = sources

	var conflicts []map[string]any
	effectivePersistent := map[string]string{}
	for k, vals := range persistent {
		uniq := uniqueStrings(vals)
		if len(uniq) > 1 {
			conflicts = append(conflicts, map[string]any{
				"key":    k,
				"values": uniq,
			})
		}
		if len(vals) > 0 {
			effectivePersistent[k] = vals[len(vals)-1] // last file wins (approx; real order is more nuanced)
		}
	}
	out["conflicts"] = conflicts
	out["persistent_effective"] = effectivePersistent

	// Kernel cmdline effects (read-only).
	if b, err := os.ReadFile("/proc/cmdline"); err == nil {
		var params []string
		for _, tok := range strings.Fields(string(b)) {
			if strings.HasPrefix(tok, "sysctl.") || strings.Contains(tok, "=") && (strings.HasPrefix(tok, "ipv6.") || strings.HasPrefix(tok, "numa")) {
				params = append(params, tok)
			}
			// Common security-related cmdline tokens
			for _, p := range []string{"apparmor=", "security=", "selinux=", "enforcing=", "quiet", "ro"} {
				if strings.HasPrefix(tok, p) || tok == p {
					params = append(params, tok)
				}
			}
		}
		out["kernel_cmdline_params"] = uniqueStrings(params)
		out["kernel_cmdline_raw"] = RedactSecrets(strings.TrimSpace(string(b)))
	}

	if len(runtime) == 0 && len(sources) == 0 {
		out["status"] = "unavailable"
		return out
	}
	out["status"] = "observed"
	return out
}

func sysctlKeyToProcPath(key string) string {
	return "/proc/sys/" + strings.ReplaceAll(key, ".", "/")
}

func parseSysctlConf(s string) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		line = strings.ReplaceAll(line, "=", " ")
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			out[parts[0]] = parts[1]
		}
	}
	return out
}

func keysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func enrichSecurityWithEffective(ctx context.Context, value map[string]any) {
	value["openssh_effective"] = collectOpenSSHEffective(ctx)
	value["sysctl_effective"] = collectSysctlEffective(ctx)
	value["sudo_effective"] = collectSudoEffective(ctx)
	value["pam_effective"] = collectPAMEffective(ctx)
	value["firewall_effective"] = collectFirewallEffective(ctx)
}

func collectSudoEffective(ctx context.Context) map[string]any {
	out := map[string]any{
		"adapter":               "sudo",
		"status":                "unavailable",
		"configuration_sources": []string{},
		"includes":              []string{},
		"parse_errors":          []string{},
	}
	sources := []string{}
	if st, err := os.Stat("/etc/sudoers"); err == nil && st.Mode().IsRegular() {
		sources = append(sources, "/etc/sudoers")
	}
	dropins, _ := filepath.Glob("/etc/sudoers.d/*")
	for _, d := range dropins {
		base := filepath.Base(d)
		if strings.HasPrefix(base, ".") || strings.HasSuffix(base, "~") {
			continue
		}
		sources = append(sources, d)
	}
	out["configuration_sources"] = sources
	if len(sources) == 0 {
		out["status"] = "not_present"
		out["message"] = "no sudoers files found"
		return out
	}

	// Read-only parse of Defaults and #include directives — never execute sudo -l (can prompt/log).
	var includes []string
	defaults := map[string]string{}
	readable := 0
	for _, src := range sources {
		b, err := os.ReadFile(src)
		if err != nil {
			if os.IsPermission(err) {
				out["permission_failure"] = true
				out["status"] = "permission_denied"
				out["message"] = "cannot read " + src
				return out
			}
			continue
		}
		readable++
		sc := bufio.NewScanner(strings.NewReader(string(b)))
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "#include") && !strings.HasPrefix(line, "#includedir") {
				continue
			}
			if strings.HasPrefix(line, "#includedir") || strings.HasPrefix(line, "@includedir") {
				includes = append(includes, strings.TrimSpace(strings.Fields(line)[len(strings.Fields(line))-1]))
				continue
			}
			if strings.HasPrefix(line, "#include") || strings.HasPrefix(line, "@include") {
				includes = append(includes, strings.TrimSpace(strings.Fields(line)[len(strings.Fields(line))-1]))
				continue
			}
			if strings.HasPrefix(line, "Defaults") {
				rest := strings.TrimSpace(strings.TrimPrefix(line, "Defaults"))
				// Defaults:foo or Defaults foo
				rest = strings.TrimLeft(rest, ":")
				rest = strings.TrimSpace(rest)
				if i := strings.IndexAny(rest, "=,"); i > 0 {
					defaults[strings.TrimSpace(rest[:i])] = strings.TrimSpace(rest[i:])
				} else if rest != "" {
					defaults[rest] = "set"
				}
			}
		}
	}
	out["includes"] = uniqueStrings(includes)
	out["defaults"] = defaults
	out["defaults_count"] = len(defaults)
	out["files_readable"] = readable
	out["status"] = "observed"
	return out
}

func collectPAMEffective(ctx context.Context) map[string]any {
	out := map[string]any{
		"adapter":  "pam",
		"status":   "unavailable",
		"services": []map[string]any{},
	}
	// Allowlisted common PAM service files only — no full /etc/pam.d crawl of every drop-in name beyond list.
	names := []string{"sshd", "sudo", "su", "login", "passwd", "common-auth", "common-password", "common-session", "common-account"}
	var services []map[string]any
	for _, name := range names {
		path := "/etc/pam.d/" + name
		b, err := os.ReadFile(path)
		if err != nil {
			if os.IsPermission(err) {
				out["permission_failure"] = true
				out["status"] = "permission_denied"
				out["message"] = "cannot read " + path
				return out
			}
			continue
		}
		var modules []map[string]string
		sc := bufio.NewScanner(strings.NewReader(string(b)))
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 3 {
				continue
			}
			modules = append(modules, map[string]string{
				"type":    fields[0],
				"control": fields[1],
				"module":  fields[2],
			})
		}
		services = append(services, map[string]any{
			"service":      name,
			"path":         path,
			"module_count": len(modules),
			"modules":      modules,
		})
	}
	out["services"] = services
	out["service_count"] = len(services)
	if len(services) == 0 {
		out["status"] = "not_present"
		return out
	}
	out["status"] = "observed"
	return out
}

func collectFirewallEffective(ctx context.Context) map[string]any {
	out := map[string]any{
		"adapter":  "firewall",
		"status":   "observed",
		"backends": map[string]any{},
	}
	backends := map[string]any{}

	// Distinguish tool missing vs inactive vs empty vs permission denied.
	backends["ufw"] = firewallProbeUFW(ctx)
	backends["firewalld"] = firewallProbeFirewalld(ctx)
	backends["nftables"] = firewallProbeNft(ctx)
	backends["iptables"] = firewallProbeIptables(ctx)

	out["backends"] = backends
	// Summary without claiming "disabled" merely because a CLI is missing.
	active := []string{}
	for name, v := range backends {
		if m, ok := v.(map[string]any); ok {
			if m["status"] == "active" || m["status"] == "observed_rules" {
				active = append(active, name)
			}
		}
	}
	out["active_backends"] = active
	return out
}

func firewallProbeUFW(ctx context.Context) map[string]any {
	r := map[string]any{"tool": "ufw"}
	if _, err := exec.LookPath("ufw"); err != nil {
		r["status"] = "tool_not_installed"
		return r
	}
	cmd := exec.CommandContext(ctx, "ufw", "status")
	b, err := cmd.CombinedOutput()
	s := strings.TrimSpace(string(b))
	if err != nil {
		low := strings.ToLower(s + err.Error())
		if looksLikePermissionDenied(low) {
			r["status"] = "permission_denied"
			r["message"] = truncateMsg(s)
			return r
		}
		r["status"] = "unavailable"
		r["message"] = truncateMsg(s)
		return r
	}
	low := strings.ToLower(s)
	if strings.Contains(low, "inactive") {
		r["status"] = "inactive"
	} else if strings.Contains(low, "active") {
		r["status"] = "active"
	} else {
		r["status"] = "observed"
	}
	r["summary"] = firstLine(s)
	return r
}

func firewallProbeFirewalld(ctx context.Context) map[string]any {
	r := map[string]any{"tool": "firewall-cmd"}
	if _, err := exec.LookPath("firewall-cmd"); err != nil {
		r["status"] = "tool_not_installed"
		// Still check service unit presence without equating to disabled firewall.
		svc := probeService(ctx, "firewalld")
		r["service"] = svc.asMap()
		return r
	}
	cmd := exec.CommandContext(ctx, "firewall-cmd", "--state")
	b, err := cmd.CombinedOutput()
	s := strings.TrimSpace(string(b))
	if err != nil {
		low := strings.ToLower(s + err.Error())
		if looksLikePermissionDenied(low) {
			r["status"] = "permission_denied"
			return r
		}
		if strings.Contains(low, "not running") {
			r["status"] = "inactive"
			return r
		}
		r["status"] = "unavailable"
		r["message"] = truncateMsg(s)
		return r
	}
	if strings.EqualFold(s, "running") {
		r["status"] = "active"
	} else {
		r["status"] = "observed"
		r["value"] = s
	}
	return r
}

func firewallProbeNft(ctx context.Context) map[string]any {
	r := map[string]any{"tool": "nft"}
	if _, err := exec.LookPath("nft"); err != nil {
		r["status"] = "tool_not_installed"
		return r
	}
	cmd := exec.CommandContext(ctx, "nft", "list", "ruleset")
	b, err := cmd.CombinedOutput()
	s := string(b)
	if err != nil {
		low := strings.ToLower(s + err.Error())
		if looksLikePermissionDenied(low) {
			r["status"] = "permission_denied"
			r["message"] = truncateMsg(s)
			return r
		}
		r["status"] = "unavailable"
		r["message"] = truncateMsg(s)
		return r
	}
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		r["status"] = "empty_ruleset"
	} else {
		r["status"] = "observed_rules"
		r["ruleset_bytes"] = len(trimmed)
		// Do not dump full ruleset (can be huge); count tables/chains lightly.
		r["table_lines"] = strings.Count(trimmed, "table ")
		r["chain_lines"] = strings.Count(trimmed, "chain ")
	}
	return r
}

func firewallProbeIptables(ctx context.Context) map[string]any {
	r := map[string]any{"tool": "iptables"}
	if _, err := exec.LookPath("iptables"); err != nil {
		r["status"] = "tool_not_installed"
		return r
	}
	// Detect nft compatibility backend without mutation.
	cmd := exec.CommandContext(ctx, "iptables", "-V")
	b, _ := cmd.CombinedOutput()
	ver := strings.TrimSpace(string(b))
	r["version"] = ver
	if strings.Contains(strings.ToLower(ver), "nf_tables") {
		r["backend"] = "nftables_compat"
	} else if ver != "" {
		r["backend"] = "legacy_or_unknown"
	}
	cmd = exec.CommandContext(ctx, "iptables", "-S")
	b, err := cmd.CombinedOutput()
	s := string(b)
	if err != nil {
		low := strings.ToLower(s + err.Error())
		if looksLikePermissionDenied(low) {
			r["status"] = "permission_denied"
			return r
		}
		r["status"] = "unavailable"
		r["message"] = truncateMsg(s)
		return r
	}
	lines := 0
	for _, line := range strings.Split(s, "\n") {
		if strings.TrimSpace(line) != "" {
			lines++
		}
	}
	r["rule_lines"] = lines
	if lines == 0 {
		r["status"] = "empty_ruleset"
	} else {
		r["status"] = "observed_rules"
	}
	return r
}
