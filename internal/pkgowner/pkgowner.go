// Package pkgowner answers one question for any package manager: which
// installed package owns this file. It reads package databases only (dpkg
// file lists, the apk installed database, one rpm query) and never writes.
package pkgowner

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/s4e-io/openness-collector/internal/procutil"
)

// Owner is the package that owns a file.
type Owner struct {
	Manager string // dpkg, rpm, apk
	Name    string
	Version string // raw version string as the packages module reports it
	Arch    string
	Path    string // the queried path that matched
}

// EntityID is the entity id the packages module gives the same package, or
// "" when version or architecture is unknown.
func (o Owner) EntityID() string {
	if o.Manager == "" || o.Name == "" || o.Version == "" || o.Arch == "" {
		return ""
	}
	return "pkg:" + o.Manager + ":" + o.Name + ":" + o.Arch + ":" + o.Version
}

// Value is the evidence shape of an owner.
func (o Owner) Value() map[string]any {
	var id any
	if e := o.EntityID(); e != "" {
		id = e
	}
	return map[string]any{
		"manager":      o.Manager,
		"name":         o.Name,
		"version":      nullIfEmpty(o.Version),
		"architecture": nullIfEmpty(o.Arch),
		"entity_id":    id,
		"path":         o.Path,
	}
}

// Result of one Resolve call.
type Result struct {
	// Owners maps a queried path to its owner. A path that is missing here
	// has no owner in the databases that were read.
	Owners map[string]Owner
	// Managers lists the package databases that were read. Empty means
	// ownership could not be checked at all.
	Managers []string
}

// Resolve looks up the owners of absolute file paths under root ("/" on a
// live host). Only regular files are meaningful: package managers share
// directories between packages.
func Resolve(ctx context.Context, root string, paths []string) Result {
	res := Result{Owners: map[string]Owner{}}
	if len(paths) == 0 {
		return res
	}
	// Every spelling a package database may use for a path, back to the
	// path that was asked for.
	// Two asked paths can share a spelling (a symlink and its target).
	want := map[string][]string{}
	asked := map[string]bool{}
	for _, p := range paths {
		if asked[p] {
			continue
		}
		asked[p] = true
		for _, c := range PathCandidates(p) {
			want[c] = append(want[c], p)
		}
	}
	add := func(found map[string]Owner) {
		for cand, o := range found {
			for _, orig := range want[cand] {
				if _, ok := res.Owners[orig]; ok {
					continue
				}
				o.Path = orig
				res.Owners[orig] = o
			}
		}
	}
	if found, ok := dpkgOwners(root, want); ok {
		res.Managers = append(res.Managers, "dpkg")
		add(found)
	}
	if found, ok := apkOwners(root, want); ok {
		res.Managers = append(res.Managers, "apk")
		add(found)
	}
	if found, ok := rpmOwners(ctx, root, want); ok {
		res.Managers = append(res.Managers, "rpm")
		add(found)
	}
	return res
}

// PathCandidates lists the spellings of one path that a package database may
// record: the path itself, its symlink-resolved form and the /usr-merge twin
// of each.
func PathCandidates(path string) []string {
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
	// In-process symlink resolution: no helper process that could hang.
	if r, err := filepath.EvalSymlinks(path); err == nil {
		add(r)
	}
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

func newScanner(f *os.File) *bufio.Scanner {
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	return sc
}

// dpkgOwners scans /var/lib/dpkg/info/*.list for the wanted paths. Only the
// wanted paths are kept, so memory does not grow with the package database.
func dpkgOwners(root string, want map[string][]string) (map[string]Owner, bool) {
	infoDir := filepath.Join(root, "var/lib/dpkg/info")
	ents, err := os.ReadDir(infoDir)
	if err != nil {
		return nil, false
	}
	found := map[string]Owner{}
	names := map[string]bool{}
	for _, e := range ents {
		fn := e.Name()
		if !strings.HasSuffix(fn, ".list") {
			continue
		}
		// Multi-arch packages are named <package>:<arch>.list.
		pkg, arch, _ := strings.Cut(strings.TrimSuffix(fn, ".list"), ":")
		f, err := os.Open(filepath.Join(infoDir, fn))
		if err != nil {
			continue
		}
		sc := newScanner(f)
		for sc.Scan() {
			p := sc.Text()
			if _, ok := want[p]; !ok {
				continue
			}
			if _, dup := found[p]; !dup {
				found[p] = Owner{Manager: "dpkg", Name: pkg, Arch: arch}
				names[pkg] = true
			}
		}
		_ = f.Close()
	}
	if len(found) > 0 {
		meta := dpkgVersions(filepath.Join(root, "var/lib/dpkg/status"), names)
		for p, o := range found {
			for _, m := range meta[o.Name] {
				if o.Arch == "" || o.Arch == m.Arch {
					o.Arch, o.Version = m.Arch, m.Version
					break
				}
			}
			found[p] = o
		}
	}
	return found, true
}

// dpkgVersions reads version and architecture of the named installed
// packages from the dpkg status file.
func dpkgVersions(statusPath string, names map[string]bool) map[string][]Owner {
	out := map[string][]Owner{}
	f, err := os.Open(statusPath)
	if err != nil {
		return out
	}
	defer f.Close()
	var cur Owner
	installed := false
	flush := func() {
		if cur.Name != "" && installed && names[cur.Name] {
			out[cur.Name] = append(out[cur.Name], cur)
		}
		cur, installed = Owner{}, false
	}
	sc := newScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch k {
		case "Package":
			cur.Name = v
		case "Version":
			cur.Version = v
		case "Architecture":
			cur.Arch = v
		case "Status":
			f := strings.Fields(v)
			installed = len(f) >= 3 && f[0] == "install" && f[2] == "installed"
		}
	}
	flush()
	return out
}

// apkOwners streams the apk installed database; F: names a directory and
// each following R: a file in it.
func apkOwners(root string, want map[string][]string) (map[string]Owner, bool) {
	f, err := os.Open(filepath.Join(root, "lib/apk/db/installed"))
	if err != nil {
		return nil, false
	}
	defer f.Close()
	found := map[string]Owner{}
	var cur Owner
	dir := ""
	// Paths of the current stanza; version and architecture may follow the
	// file lines, so they are filled in when the stanza ends.
	var hits []string
	flush := func() {
		for _, p := range hits {
			found[p] = cur
		}
		cur, dir, hits = Owner{}, "", nil
	}
	sc := newScanner(f)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), " \t\r")
		if line == "" {
			flush()
			continue
		}
		if len(line) < 2 || line[1] != ':' {
			continue
		}
		v := line[2:]
		switch line[0] {
		case 'P':
			cur.Manager, cur.Name = "apk", strings.TrimSpace(v)
		case 'V':
			cur.Version = strings.TrimSpace(v)
		case 'A':
			cur.Arch = strings.TrimSpace(v)
		case 'F':
			dir = v
		case 'R':
			p := "/" + v
			if dir != "" {
				p = "/" + dir + "/" + v
			}
			if _, ok := want[p]; ok {
				if _, dup := found[p]; !dup {
					hits = append(hits, p)
				}
			}
		}
	}
	flush()
	return found, true
}

// rpmDBPaths are the system rpm databases. Without one, rpm falls back to
// ~/.rpmdb and creates files there, which the collector must not cause.
var rpmDBPaths = []string{
	"var/lib/rpm/rpmdb.sqlite", "var/lib/rpm/Packages", "var/lib/rpm/Packages.db",
	"usr/lib/sysimage/rpm/rpmdb.sqlite", "usr/lib/sysimage/rpm/Packages", "usr/lib/sysimage/rpm/Packages.db",
}

const rpmOwnerFormat = "%{NAME}\t%{EPOCH}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n"

// rpmQuery runs one rpm file query and returns its stdout. A variable so
// tests can replace it.
var rpmQuery = func(ctx context.Context, paths []string) (string, error) {
	args := append([]string{"-qf", "--qf", rpmOwnerFormat, "--"}, paths...)
	out, err := procutil.Command(ctx, "rpm", args...).Output()
	// rpm exits non-zero when any file is unowned; stdout is still valid.
	if len(out) > 0 {
		return string(out), nil
	}
	return "", err
}

// rpmOwners asks rpm for the owners of the wanted files that exist, in one
// query. Only the live host root is supported.
func rpmOwners(ctx context.Context, root string, want map[string][]string) (map[string]Owner, bool) {
	if filepath.Clean(root) != "/" {
		return nil, false
	}
	if _, err := exec.LookPath("rpm"); err != nil {
		return nil, false
	}
	hasDB := false
	for _, p := range rpmDBPaths {
		if st, err := os.Stat(filepath.Join(root, p)); err == nil && st.Mode().IsRegular() {
			hasDB = true
			break
		}
	}
	if !hasDB {
		return nil, false
	}
	var files []string
	for p := range want {
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
			files = append(files, p)
		}
	}
	if len(files) == 0 {
		return map[string]Owner{}, true
	}
	out, err := rpmQuery(ctx, files)
	if err != nil {
		return nil, false
	}
	found, ok := parseRPMOwners(out, files)
	if ok {
		return found, true
	}
	// A file owned by more than one package prints several rows and breaks
	// the one-row-per-file pairing; ask again file by file.
	found = map[string]Owner{}
	for _, p := range files {
		if ctx.Err() != nil {
			return nil, false
		}
		out, err := rpmQuery(ctx, []string{p})
		if err != nil {
			continue
		}
		if o, ok := parseRPMOwnerRow(firstLine(out)); ok {
			found[p] = o
		}
	}
	return found, true
}

// parseRPMOwners pairs rpm output rows with the queried files. rpm prints one
// row per file, either the format row or a "not owned" message. ok is false
// when the row count does not match and the pairing cannot be trusted.
func parseRPMOwners(out string, files []string) (map[string]Owner, bool) {
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != len(files) {
		return nil, false
	}
	found := map[string]Owner{}
	for i, line := range lines {
		if o, ok := parseRPMOwnerRow(line); ok {
			found[files[i]] = o
		}
	}
	return found, true
}

func parseRPMOwnerRow(line string) (Owner, bool) {
	parts := strings.Split(line, "\t")
	if len(parts) != 5 || parts[0] == "" {
		return Owner{}, false
	}
	ver := parts[2] + "-" + parts[3]
	if e := parts[1]; e != "" && e != "(none)" {
		ver = e + ":" + ver
	}
	return Owner{Manager: "rpm", Name: parts[0], Version: ver, Arch: parts[4]}, true
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
