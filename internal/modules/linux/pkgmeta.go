package linux

import (
	"context"
	"os/exec"
	"regexp"
	"strings"
)

// ParseDebianSource parses dpkg Source field values.
// Examples: "openssl", "foo (1.2.3-1)", "linux-signed-hwe-6.8"
func ParseDebianSource(raw string) (name string, version any) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	if i := strings.Index(raw, " ("); i > 0 && strings.HasSuffix(raw, ")") {
		return strings.TrimSpace(raw[:i]), strings.TrimSpace(raw[i+2 : len(raw)-1])
	}
	return raw, nil
}

// ParseDebianVersion splits epoch:version-revision style strings.
func ParseDebianVersion(raw string) (epoch any, version, release string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, "", ""
	}
	rest := raw
	if i := strings.IndexByte(raw, ':'); i >= 0 {
		epoch = raw[:i]
		rest = raw[i+1:]
	} else {
		epoch = nil
	}
	// version-revision: last hyphen separates revision for Debian
	if i := strings.LastIndexByte(rest, '-'); i >= 0 {
		return epoch, rest[:i], rest[i+1:]
	}
	return epoch, rest, ""
}

var srcRPMRe = regexp.MustCompile(`^(.+)-([^-]+)-([^-]+)\.src\.rpm$`)

// ParseSourceRPM parses "name-version-release.src.rpm" without naive hyphen splits on name.
func ParseSourceRPM(raw string) (name, version, release string, ok bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "(none)" {
		return "", "", "", false
	}
	m := srcRPMRe.FindStringSubmatch(raw)
	if m == nil {
		// Fallback: strip .src.rpm and split from the right twice.
		s := strings.TrimSuffix(raw, ".src.rpm")
		s = strings.TrimSuffix(s, ".nosrc.rpm")
		parts := strings.Split(s, "-")
		if len(parts) < 3 {
			return raw, "", "", false
		}
		release = parts[len(parts)-1]
		version = parts[len(parts)-2]
		name = strings.Join(parts[:len(parts)-2], "-")
		return name, version, release, true
	}
	return m[1], m[2], m[3], true
}

func nullIfEmpty(s string) any {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return s
}

// PackageOwner looks up which package owns a path.
// Tries original path, realpath, and Debian /usr-merge twin paths.
func PackageOwner(ctx context.Context, path string) map[string]any {
	out := map[string]any{
		"path":            path,
		"package_name":    nil,
		"package_manager": nil,
		"status":          "not_found",
	}
	if path == "" {
		out["status"] = "unavailable"
		return out
	}
	candidates := ownershipPathCandidates(path)
	if _, err := exec.LookPath("dpkg-query"); err == nil {
		for _, cand := range candidates {
			cmd := exec.CommandContext(ctx, "dpkg-query", "-S", cand)
			b, err := cmd.CombinedOutput()
			s := strings.TrimSpace(string(b))
			if err == nil && s != "" && !strings.Contains(strings.ToLower(s), "no path found") {
				line := strings.Split(s, "\n")[0]
				pkg := line
				if i := strings.Index(line, ":"); i >= 0 {
					pkg = strings.TrimSpace(line[:i])
				}
				out["path"] = cand
				out["package_name"] = pkg
				out["package_manager"] = "dpkg"
				out["status"] = "observed"
				out["raw"] = line
				if cand != path {
					out["resolved_via"] = cand
				}
				return out
			}
		}
		out["status"] = "not_found"
		return out
	}
	if _, err := exec.LookPath("rpm"); err == nil {
		for _, cand := range candidates {
			cmd := exec.CommandContext(ctx, "rpm", "-qf", cand)
			b, err := cmd.CombinedOutput()
			s := strings.TrimSpace(string(b))
			if err == nil && s != "" && !strings.Contains(s, "not owned") {
				out["path"] = cand
				out["package_name"] = strings.Split(s, "\n")[0]
				out["package_manager"] = "rpm"
				out["status"] = "observed"
				out["raw"] = s
				return out
			}
		}
		out["status"] = "not_found"
		return out
	}
	return out
}

func ownershipPathCandidates(path string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] {
			return
		}
		seen[p] = true
		out = append(out, p)
	}
	add(path)
	if r, err := exec.Command("readlink", "-f", path).Output(); err == nil {
		add(strings.TrimSpace(string(r)))
	}
	// /usr-merge twins
	twins := [][2]string{
		{"/bin/", "/usr/bin/"},
		{"/sbin/", "/usr/sbin/"},
		{"/lib/", "/usr/lib/"},
		{"/lib64/", "/usr/lib64/"},
	}
	for _, base := range append([]string{}, out...) {
		for _, t := range twins {
			if strings.HasPrefix(base, t[0]) {
				add(t[1] + strings.TrimPrefix(base, t[0]))
			}
			if strings.HasPrefix(base, t[1]) {
				add(t[0] + strings.TrimPrefix(base, t[1]))
			}
		}
	}
	return out
}

// parseAptPolicy parses `apt-cache policy` text. Kept for unit tests and any
// offline fixtures; the collector does not execute apt-cache (see packages /
// /var/lib/apt/lists file parse instead).
func parseAptPolicy(out string) map[string]any {
	res := map[string]any{
		"repository_origin":         nil,
		"repository_label":          nil,
		"repository_suite":          nil,
		"repository_component":      nil,
		"repository_url":            nil,
		"installed_from_repository": nil,
		"status":                    "not_found",
	}
	lines := strings.Split(out, "\n")
	installedVer := ""
	for _, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "Installed:") {
			installedVer = strings.TrimSpace(strings.TrimPrefix(t, "Installed:"))
			if installedVer == "(none)" {
				installedVer = ""
			}
		}
	}
	if installedVer == "" {
		return res
	}

	// Walk Version table; find *** installedVer block and prefer http(s) origin.
	inBlock := false
	sawStatusOnly := false
	for _, line := range lines {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "*** ") || (len(line) > 0 && line[0] != ' ' && line[0] != '\t' && strings.Contains(trim, " ")) {
			// New version entry lines look like " *** 1:8.9p1-3 500" or "     1:8.9p1-3 500"
		}
		if strings.Contains(line, installedVer) && (strings.Contains(line, "***") || strings.HasPrefix(strings.TrimLeft(line, " "), installedVer) || strings.Contains(strings.TrimSpace(line), installedVer+" ")) {
			inBlock = true
			continue
		}
		if inBlock {
			// Next version block starts at less-indented version line with pin
			if isAptVersionHeader(line) && !strings.Contains(line, installedVer) {
				break
			}
			t := strings.TrimSpace(line)
			if strings.Contains(t, "http://") || strings.Contains(t, "https://") || strings.Contains(t, "ftp://") {
				applyAptOriginLine(res, t)
				res["status"] = "observed"
				res["installed_from_repository"] = true
				return res
			}
			if strings.Contains(t, "/var/lib/dpkg/status") {
				sawStatusOnly = true
			}
		}
	}

	// Fallback: any http line in whole policy (candidate often same as installed)
	for _, line := range lines {
		t := strings.TrimSpace(line)
		if strings.Contains(t, "http://") || strings.Contains(t, "https://") {
			applyAptOriginLine(res, t)
			res["status"] = "observed"
			res["installed_from_repository"] = true
			return res
		}
	}

	if sawStatusOnly {
		// Installed version only appears in dpkg status — origin unknown (not proven local .deb).
		res["status"] = "observed"
		res["installed_from_repository"] = nil
		res["repository_origin"] = nil
		res["origin_note"] = "only_dpkg_status_no_repo_index"
		return res
	}
	res["status"] = "not_found"
	return res
}

func isAptVersionHeader(line string) bool {
	t := strings.TrimSpace(line)
	if t == "" {
		return false
	}
	// Version headers are indented and end with a pin priority number.
	fields := strings.Fields(t)
	if len(fields) < 2 {
		return false
	}
	if fields[0] == "***" {
		return true
	}
	// e.g. "1:8.9p1-3ubuntu0.10 500"
	if len(fields) >= 2 {
		last := fields[len(fields)-1]
		for _, c := range last {
			if c < '0' || c > '9' {
				return false
			}
		}
		return !strings.Contains(t, "://") && !strings.Contains(t, "/var/lib/dpkg")
	}
	return false
}

func applyAptOriginLine(res map[string]any, t string) {
	fields := strings.Fields(t)
	for _, f := range fields {
		if strings.HasPrefix(f, "http://") || strings.HasPrefix(f, "https://") || strings.HasPrefix(f, "ftp://") {
			res["repository_url"] = f
			// Origin host as coarse origin label
			u := strings.TrimPrefix(strings.TrimPrefix(strings.TrimPrefix(f, "https://"), "http://"), "ftp://")
			if i := strings.IndexByte(u, '/'); i >= 0 {
				u = u[:i]
			}
			res["repository_origin"] = u
		}
	}
	for _, f := range fields {
		if strings.Contains(f, "/") && !strings.Contains(f, "://") {
			parts := strings.SplitN(f, "/", 2)
			res["repository_suite"] = parts[0]
			if len(parts) > 1 {
				comp := parts[1]
				if i := strings.IndexByte(comp, ' '); i >= 0 {
					comp = comp[:i]
				}
				res["repository_component"] = comp
			}
			break
		}
	}
}
