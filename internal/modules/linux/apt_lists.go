package linux

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pierrec/lz4/v4"
)

type aptListOrigin struct {
	URL       string
	Origin    string
	Label     string
	Suite     string
	Codename  string
	Component string
	RepoID    string
}

type aptCandidate struct {
	Version string
	Origin  aptListOrigin
}

type aptListsIndex struct {
	ByNVRA         map[string]aptListOrigin // name|version|arch
	Candidates     map[string]aptCandidate  // name|arch and name|
	ListsUpdatedAt time.Time                // newest mtime among lists files read
}

// loadAptPackageOrigins indexes /var/lib/apt/lists/*Packages{,.lz4,.gz} by name|version|arch
// and tracks the highest candidate version per name|arch (no apt-get/apt-cache).
func loadAptPackageOrigins() *aptListsIndex {
	dir := "/var/lib/apt/lists"
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	releaseMeta := map[string]aptListOrigin{} // suite prefix -> meta from InRelease/Release
	var newest time.Time
	noteTime := func(path string) {
		if st, err := os.Stat(path); err == nil {
			if st.ModTime().After(newest) {
				newest = st.ModTime()
			}
		}
	}
	for _, e := range entries {
		name := e.Name()
		if strings.HasSuffix(name, "_InRelease") || strings.HasSuffix(name, "_Release") {
			path := filepath.Join(dir, name)
			noteTime(path)
			meta := parseAptReleaseFile(path)
			prefix := strings.TrimSuffix(strings.TrimSuffix(name, "_InRelease"), "_Release")
			releaseMeta[prefix] = meta
		}
	}

	idx := &aptListsIndex{
		ByNVRA:     map[string]aptListOrigin{},
		Candidates: map[string]aptCandidate{},
	}
	for _, e := range entries {
		name := e.Name()
		if !isAptPackagesFile(name) {
			continue
		}
		path := filepath.Join(dir, name)
		noteTime(path)
		pkgPrefix := aptPackagesPrefix(name)
		base := aptListOrigin{}
		// Match InRelease by longest suite prefix (Packages path includes component/arch).
		for relPrefix, meta := range releaseMeta {
			if strings.HasPrefix(pkgPrefix, relPrefix) && len(relPrefix) > len(base.RepoID) {
				base = meta
				base.RepoID = relPrefix
			}
		}
		inferred := inferOriginFromListName(name)
		if base.URL == "" {
			base.URL = inferred.URL
		}
		if base.Origin == "" {
			base.Origin = inferred.Origin
		}
		if base.Label == "" {
			base.Label = inferred.Label
		}
		if base.Suite == "" {
			base.Suite = inferred.Suite
		}
		if base.Codename == "" {
			base.Codename = inferred.Codename
		}
		if base.Component == "" {
			base.Component = inferred.Component
		}
		content, err := readAptPackagesFile(path)
		if err != nil || len(content) == 0 {
			continue
		}
		sc := bufio.NewScanner(bytes.NewReader(content))
		sc.Buffer(make([]byte, 0, 256*1024), 4*1024*1024)
		var pkg, ver, arch, filename string
		flush := func() {
			if pkg == "" || ver == "" {
				return
			}
			o := base
			if filename != "" && o.Component == "" {
				parts := strings.Split(filename, "/")
				if len(parts) > 1 && parts[0] == "pool" {
					o.Component = parts[1]
				}
			}
			o.RepoID = pkgPrefix
			idx.ByNVRA[pkg+"|"+ver+"|"+arch] = o
			idx.ByNVRA[pkg+"|"+ver+"|"] = o
			considerAptCandidate(idx, pkg, arch, ver, o)
		}
		for sc.Scan() {
			line := sc.Text()
			if line == "" {
				flush()
				pkg, ver, arch, filename = "", "", "", ""
				continue
			}
			if strings.HasPrefix(line, "Package: ") {
				pkg = strings.TrimSpace(strings.TrimPrefix(line, "Package: "))
			} else if strings.HasPrefix(line, "Version: ") {
				ver = strings.TrimSpace(strings.TrimPrefix(line, "Version: "))
			} else if strings.HasPrefix(line, "Architecture: ") {
				arch = strings.TrimSpace(strings.TrimPrefix(line, "Architecture: "))
			} else if strings.HasPrefix(line, "Filename: ") {
				filename = strings.TrimSpace(strings.TrimPrefix(line, "Filename: "))
			}
		}
		flush()
	}
	idx.ListsUpdatedAt = newest
	if len(idx.ByNVRA) == 0 {
		return nil
	}
	return idx
}

func considerAptCandidate(idx *aptListsIndex, name, arch, ver string, o aptListOrigin) {
	// Never fall back to name-only when arch is known (avoids amd64 picking i386).
	key := name + "|"
	if arch != "" {
		key = name + "|" + arch
	}
	cur, ok := idx.Candidates[key]
	if !ok || compareDebVersion(ver, cur.Version) > 0 {
		idx.Candidates[key] = aptCandidate{Version: ver, Origin: o}
	}
}

func isAptPackagesFile(name string) bool {
	return strings.HasSuffix(name, "_Packages") ||
		strings.HasSuffix(name, "_Packages.lz4") ||
		strings.HasSuffix(name, "_Packages.gz")
}

func aptPackagesPrefix(name string) string {
	for _, suf := range []string{"_Packages.lz4", "_Packages.gz", "_Packages"} {
		if strings.HasSuffix(name, suf) {
			return strings.TrimSuffix(name, suf)
		}
	}
	return name
}

func readAptPackagesFile(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	switch {
	case strings.HasSuffix(path, ".lz4"):
		zr := lz4.NewReader(bytes.NewReader(b))
		return io.ReadAll(io.LimitReader(zr, 64<<20))
	case strings.HasSuffix(path, ".gz"):
		return gunzipBytes(b)
	default:
		return b, nil
	}
}

func gunzipBytes(b []byte) ([]byte, error) {
	gr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer gr.Close()
	return io.ReadAll(io.LimitReader(gr, 64<<20))
}

func parseAptReleaseFile(path string) aptListOrigin {
	b, err := os.ReadFile(path)
	if err != nil {
		return aptListOrigin{}
	}
	o := aptListOrigin{}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "Origin: ") {
			o.Origin = strings.TrimSpace(strings.TrimPrefix(line, "Origin: "))
		} else if strings.HasPrefix(line, "Label: ") {
			o.Label = strings.TrimSpace(strings.TrimPrefix(line, "Label: "))
		} else if strings.HasPrefix(line, "Suite: ") {
			o.Suite = strings.TrimSpace(strings.TrimPrefix(line, "Suite: "))
		} else if strings.HasPrefix(line, "Codename: ") {
			o.Codename = strings.TrimSpace(strings.TrimPrefix(line, "Codename: "))
		}
	}
	return o
}

func inferOriginFromListName(name string) aptListOrigin {
	// Example: archive.ubuntu.com_ubuntu_dists_jammy-updates_main_binary-amd64_Packages
	// Example: ports.ubuntu.com_ubuntu-ports_dists_jammy-security_main_binary-arm64_Packages.lz4
	o := aptListOrigin{}
	name = strings.TrimSuffix(strings.TrimSuffix(name, ".lz4"), ".gz")
	if i := strings.Index(name, "_dists_"); i > 0 {
		hostPart := name[:i]
		o.URL = "http://" + strings.ReplaceAll(hostPart, "_", "/")
		rest := strings.TrimSuffix(name[i+len("_dists_"):], "_Packages")
		parts := strings.Split(rest, "_")
		if len(parts) >= 1 {
			o.Suite = parts[0]
			o.Codename = parts[0]
		}
		if len(parts) >= 2 {
			o.Component = parts[1]
		}
		low := strings.ToLower(hostPart)
		if strings.Contains(low, "ubuntu") {
			o.Origin = "Ubuntu"
			o.Label = "Ubuntu"
		} else if strings.Contains(low, "debian") {
			o.Origin = "Debian"
			o.Label = "Debian"
		}
	}
	return o
}

func applyAptOriginToPackage(value map[string]any, idx *aptListsIndex) {
	if idx == nil {
		value["highest_list_version"] = nil
		value["highest_list_origin"] = nil
		value["lists_updated_at"] = nil
		value["apt_update_success_at"] = nil
		return
	}
	if !idx.ListsUpdatedAt.IsZero() {
		value["lists_updated_at"] = idx.ListsUpdatedAt.UTC().Format(time.RFC3339Nano)
	} else {
		value["lists_updated_at"] = nil
	}
	value["apt_update_success_at"] = readAptUpdateSuccessAt()

	name, _ := value["name"].(string)
	ver, _ := value["raw_version_string"].(string)
	arch, _ := value["architecture"].(string)
	if name == "" || ver == "" {
		value["highest_list_version"] = nil
		value["highest_list_origin"] = nil
		return
	}
	o, ok := idx.ByNVRA[name+"|"+ver+"|"+arch]
	if !ok {
		o, ok = idx.ByNVRA[name+"|"+ver+"|"]
	}
	if !ok {
		// Keep installed_from_repository=null (unknown). Never set false solely from missing list entry.
		value["repository_metadata_status"] = "not_in_apt_lists"
	} else {
		value["installed_from_repository"] = true
		value["repository_id"] = nullIfEmpty(o.RepoID)
		value["repository_name"] = nullIfEmpty(firstNonEmpty(o.Label, o.Origin))
		value["repository_url"] = nullIfEmpty(o.URL)
		value["repository_component"] = nullIfEmpty(o.Component)
		value["repository_suite"] = nullIfEmpty(o.Suite)
		value["repository_codename"] = nullIfEmpty(o.Codename)
		value["repository_origin"] = nullIfEmpty(o.Origin)
		value["repository_label"] = nullIfEmpty(o.Label)
		value["repository_metadata_status"] = "matched_apt_lists"
		if strings.Contains(strings.ToLower(o.Suite), "security") || strings.Contains(strings.ToLower(o.URL), "security") {
			value["security_repository"] = true
		}
		if strings.Contains(strings.ToLower(o.Suite), "esm") || strings.Contains(strings.ToLower(o.URL), "esm") {
			value["extended_support_repository"] = true
		}
	}

	key := name + "|"
	if arch != "" {
		key = name + "|" + arch
	}
	cand, ok := idx.Candidates[key]
	if !ok {
		value["highest_list_version"] = nil
		value["highest_list_origin"] = nil
		return
	}
	value["highest_list_version"] = cand.Version
	value["highest_list_origin"] = aptOriginObservation(cand.Origin)
}

func aptOriginObservation(o aptListOrigin) map[string]any {
	esm := strings.Contains(strings.ToLower(o.Suite), "esm") || strings.Contains(strings.ToLower(o.URL), "esm")
	return map[string]any{
		"origin":    nullIfEmpty(o.Origin),
		"label":     nullIfEmpty(o.Label),
		"suite":     nullIfEmpty(o.Suite),
		"component": nullIfEmpty(o.Component),
		"url":       nullIfEmpty(o.URL),
		"esm":       esm,
	}
}

// readAptUpdateSuccessAt returns mtime of apt periodic success stamp when present.
// This is closer to "apt update last succeeded" than Packages file mtime (often mirror Last-Modified).
func readAptUpdateSuccessAt() any {
	const path = "/var/lib/apt/periodic/update-success-stamp"
	st, err := os.Stat(path)
	if err != nil {
		return nil
	}
	return st.ModTime().UTC().Format(time.RFC3339Nano)
}
