package linux

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/s4e-io/openness-collector/internal/procutil"
)

// dpkgPkgRec matches packages module entity identity:
// pkg:dpkg:<name>:<arch>:<raw_version>
type dpkgPkgRec struct {
	Name    string
	Arch    string
	Version string
	Source  string
}

func (p dpkgPkgRec) EntityID() string {
	if p.Name == "" || p.Arch == "" || p.Version == "" {
		return ""
	}
	return "pkg:dpkg:" + p.Name + ":" + p.Arch + ":" + p.Version
}

// dpkgOwnershipIndex is a process-local reuse cache: one dpkg-query -W plus
// /var/lib/dpkg/info/*.list scan. Avoids per-distribution dpkg-query -S.
type dpkgOwnershipIndex struct {
	once    sync.Once
	loaded  bool
	pkgs    map[string]dpkgPkgRec // binary package name -> record
	byPath  map[string]string     // absolute file path -> binary package name
	loadErr string
}

func newDpkgOwnershipIndex() *dpkgOwnershipIndex {
	return &dpkgOwnershipIndex{
		pkgs:   map[string]dpkgPkgRec{},
		byPath: map[string]string{},
	}
}

func (idx *dpkgOwnershipIndex) ensure() {
	if idx == nil {
		return
	}
	idx.once.Do(func() {
		idx.loaded = true
		if _, err := exec.LookPath("dpkg-query"); err != nil {
			idx.loadErr = "dpkg-query not available"
			return
		}
		idx.loadPackages(context.Background())
		idx.loadFileLists("/var/lib/dpkg/info")
	})
}

func (idx *dpkgOwnershipIndex) loadPackages(ctx context.Context) {
	cmd := procutil.Command(ctx, "dpkg-query", "-W", "-f=${Package}\t${Version}\t${Architecture}\t${Source}\n")
	out, err := cmd.Output()
	if err != nil {
		idx.loadErr = "dpkg-query -W: " + err.Error()
		return
	}
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		parts := strings.Split(sc.Text(), "\t")
		if len(parts) < 3 {
			continue
		}
		name := parts[0]
		ver := parts[1]
		arch := parts[2]
		src := ""
		if len(parts) > 3 {
			src, _ = ParseDebianSource(parts[3])
		}
		if src == "" {
			src = name
		}
		idx.pkgs[name] = dpkgPkgRec{Name: name, Arch: arch, Version: ver, Source: src}
	}
}

func (idx *dpkgOwnershipIndex) loadFileLists(infoDir string) {
	ents, err := os.ReadDir(infoDir)
	if err != nil {
		if idx.loadErr == "" {
			idx.loadErr = "dpkg info dir: " + err.Error()
		}
		return
	}
	for _, e := range ents {
		name := e.Name()
		if !strings.HasSuffix(name, ".list") {
			continue
		}
		pkg := strings.TrimSuffix(name, ".list")
		// Multi-arch: python3.10:arm64.list → package python3.10
		if i := strings.IndexByte(pkg, ':'); i >= 0 {
			pkg = pkg[:i]
		}
		if _, ok := idx.pkgs[pkg]; !ok {
			// Still index path→name; package metadata may be missing for residual lists.
		}
		f, err := os.Open(filepath.Join(infoDir, name))
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for sc.Scan() {
			p := strings.TrimSpace(sc.Text())
			if p == "" || !strings.HasPrefix(p, "/") {
				continue
			}
			// Prefer first owner; diversions are rare for Python dist paths.
			if _, exists := idx.byPath[p]; !exists {
				idx.byPath[p] = pkg
			}
		}
		_ = f.Close()
	}
}

func (idx *dpkgOwnershipIndex) ownerPackage(path string) (string, bool) {
	if idx == nil || path == "" {
		return "", false
	}
	idx.ensure()
	for _, cand := range ownershipPathCandidates(path) {
		if pkg, ok := idx.byPath[cand]; ok && pkg != "" {
			return pkg, true
		}
	}
	return "", false
}

func (idx *dpkgOwnershipIndex) lookup(name string) (dpkgPkgRec, bool) {
	if idx == nil || name == "" {
		return dpkgPkgRec{}, false
	}
	idx.ensure()
	p, ok := idx.pkgs[name]
	return p, ok
}

func (idx *dpkgOwnershipIndex) entityID(name string) string {
	p, ok := idx.lookup(name)
	if !ok {
		return ""
	}
	return p.EntityID()
}

// injectDpkgOwnershipIndex replaces the index for tests (pre-populated, skip host load).
func injectDpkgOwnershipIndex(st *pythonScanState, idx *dpkgOwnershipIndex) {
	if st == nil {
		return
	}
	if idx == nil {
		idx = newDpkgOwnershipIndex()
	}
	// Consume Once so ensure() will not attempt a host dpkg load.
	idx.once.Do(func() { idx.loaded = true })
	if idx.pkgs == nil {
		idx.pkgs = map[string]dpkgPkgRec{}
	}
	if idx.byPath == nil {
		idx.byPath = map[string]string{}
	}
	st.dpkgIdx = idx
}
