package swinv

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/s4e-io/openness-collector/internal/modules/common"
	"github.com/s4e-io/openness-collector/internal/pkgowner"
	"github.com/s4e-io/openness-collector/internal/schema"
)

const (
	maxProcesses         = 4096
	maxInstancesPerEntry = 32
	maxInstancesTotal    = 512
	maxPatchIDsPerEntry  = 200
	confidenceDirect     = "direct"        // version read from the install itself
	confidencePresence   = "presence_only" // product seen, version unreadable
)

// SoftwareInventory detects catalog products on the host root and reads
// their versions from files and registry only.
type SoftwareInventory struct{}

func (m *SoftwareInventory) ID() string          { return "software_inventory" }
func (m *SoftwareInventory) Version() string     { return "1.1.0" }
func (m *SoftwareInventory) Platforms() []string { return []string{"linux", "windows"} }

type procInfo struct {
	PID  int    `json:"pid"`
	Name string `json:"name"`
	Exe  string `json:"exe,omitempty"`
}

type registryHit struct {
	Key         string `json:"key"`
	InstallPath string `json:"install_path,omitempty"`
}

// instance is one detected install of a product under one root.
type instance struct {
	product     Product
	scope       string
	root        string
	installPath string
	paths       []string
	procs       []procInfo
	regs        []registryHit
	ports       []int
	versions    []versionHit
	patches     []string
	patchSource string
	// owner is the package that owns one of the instance's files; ownerStatus
	// says whether ownership was checked (see the ownerStatus constants).
	owner       *pkgowner.Owner
	ownerStatus string
}

func (m *SoftwareInventory) Run(ctx context.Context) schema.ModuleResult {
	started := time.Now()
	res := common.NewResult(m.ID(), m.Version())

	catalog, err := LoadCatalog()
	if err != nil {
		res.Errors = append(res.Errors, common.Err(m.ID(), "collection_error", "catalog: "+err.Error()))
		common.Finish(&res, started, "error")
		return res
	}

	goos := runtime.GOOS
	procs := runningProcesses()
	ports := listeningTCPPorts()

	var all []instance
	var notes []string
	truncated := false
	for _, root := range hostRoots() {
		for _, p := range catalog {
			if ctx.Err() != nil {
				notes = append(notes, "context_cancelled")
				break
			}
			if !p.supports(goos) {
				continue
			}
			found := detect(p, "host", root, goos, procs, ports)
			if len(found) > maxInstancesPerEntry {
				found = found[:maxInstancesPerEntry]
				notes = append(notes, p.ProductKey+":instance_cap")
			}
			all = append(all, found...)
			if len(all) >= maxInstancesTotal {
				truncated = true
				notes = append(notes, "total_instance_cap")
				break
			}
		}
	}

	managers := resolveOwners(ctx, goos, "/", all)

	counts := map[string]int{}
	for _, in := range all {
		counts[in.product.ProductKey]++
		res.Evidence = append(res.Evidence, common.Evidence("native", m.ID(), "observed", in.value(), nil))
	}

	summary := map[string]any{
		"entity_type":        "software_inventory_summary",
		"entity_id":          "swinv:summary",
		"catalog_version":    CatalogVersion,
		"catalog_entries":    len(catalog),
		"instances":          len(all),
		"instances_by_key":   counts,
		"scopes":             []string{"host"},
		"processes_observed": len(procs),
		"ports_observed":     len(ports),
		"owner_managers":     managers,
		"truncated":          truncated,
		"notes":              notes,
	}
	// Summary first so readers see the catalog version before instances.
	res.Evidence = append([]schema.EvidenceRecord{common.Evidence("native", m.ID(), "observed", summary, nil)}, res.Evidence...)

	status := "success"
	if truncated {
		status = "partial"
		res.Errors = append(res.Errors, common.Err(m.ID(), "partial", "instance cap reached"))
	}
	common.Finish(&res, started, status)
	return res
}

// detect evaluates one catalog entry on one root. Candidates come from path
// globs, registry keys and process executables; each distinct install path
// becomes one instance.
// detect finds the instances of one product. ports maps a listening TCP port
// to the pids that own it; a port is attributed to an instance only when one
// of the instance's own processes owns it, so a stopped install or another
// product on the same well-known port never inherits it.
func detect(p Product, scope, root, goos string, procs []procInfo, ports map[int][]int) []instance {
	byPath := map[string]*instance{}
	order := []string{}
	get := func(installPath string) *instance {
		key := normalizeKey(installPath)
		if in, ok := byPath[key]; ok {
			return in
		}
		in := &instance{product: p, scope: scope, root: root, installPath: installPath}
		byPath[key] = in
		order = append(order, key)
		return in
	}

	for _, pat := range p.Signals.Paths[goos] {
		for _, hit := range globUnder(root, pat) {
			in := get(installDirFor(hit))
			in.paths = append(in.paths, hit)
		}
	}
	if goos == "windows" {
		for _, sig := range p.Signals.Registry {
			for _, h := range registryHits(sig) {
				var in *instance
				if h.InstallPath != "" && existsDir(h.InstallPath) {
					in = get(h.InstallPath)
				} else {
					in = get("registry:" + h.Key)
				}
				in.regs = append(in.regs, h)
			}
		}
	}
	for _, pr := range procs {
		if !matchProcess(p.Signals.ProcessNames, pr) {
			continue
		}
		if pr.Exe != "" && scope == "host" {
			in := get(installDirFor(pr.Exe))
			in.procs = append(in.procs, pr)
		} else if len(order) > 0 {
			byPath[order[0]].procs = append(byPath[order[0]].procs, pr)
		} else {
			in := get("process:" + pr.Name)
			in.procs = append(in.procs, pr)
		}
	}
	if len(order) == 0 {
		return nil
	}
	var out []instance
	for _, key := range order {
		in := byPath[key]
		in.ports = ownedPorts(p.Signals.Ports, ports, in.procs)
		readVersions(in, goos)
		out = append(out, *in)
	}
	return out
}

// ownedPorts returns the catalog ports that one of procs is listening on.
func ownedPorts(catalogPorts []int, listening map[int][]int, procs []procInfo) []int {
	if len(procs) == 0 {
		return nil
	}
	mine := map[int]bool{}
	for _, pr := range procs {
		mine[pr.PID] = true
	}
	var out []int
	for _, port := range catalogPorts {
		for _, pid := range listening[port] {
			if mine[pid] {
				out = append(out, port)
				break
			}
		}
	}
	sort.Ints(out)
	return out
}

// readVersions runs every reader that applies and keeps all hits. The first
// hit is reported as version; the rest stay in version_candidates.
func readVersions(in *instance, goos string) {
	for _, r := range in.product.Readers {
		if !r.supports(goos) {
			continue
		}
		for _, hit := range runReader(in, r, goos) {
			in.versions = append(in.versions, hit)
		}
	}
	for _, r := range in.product.PatchReaders {
		if !r.supports(goos) {
			continue
		}
		var ids []string
		source := ""
		switch r.Type {
		case "dir_names":
			// The glob itself is the target: match base names of its entries.
			if !strings.HasPrefix(in.installPath, "registry:") && !strings.HasPrefix(in.installPath, "process:") {
				source = filepath.Join(in.installPath, r.Path)
				ids = dirNames(source, &r)
			}
		case "file_regex":
			for _, target := range readerTargets(in, r) {
				if ids = fileRegexAll(target, &r); len(ids) > 0 {
					source = target
					break
				}
			}
		}
		if len(ids) > 0 {
			if len(ids) > maxPatchIDsPerEntry {
				ids = ids[:maxPatchIDsPerEntry]
			}
			in.patches = append(in.patches, ids...)
			in.patchSource = r.Type + ":" + source
			break
		}
	}
}

func runReader(in *instance, r Reader, goos string) []versionHit {
	var out []versionHit
	switch r.Type {
	case "registry_value":
		for _, h := range in.regs {
			if v, src, ok := registryValue(h, r); ok {
				out = append(out, versionHit{Source: r.Type, Path: src, Value: strings.TrimSpace(v)})
			}
		}
	case "file_regex":
		for _, target := range readerTargets(in, r) {
			if v, ok := fileRegexFirst(target, &r); ok {
				out = append(out, versionHit{Source: r.Type, Path: target, Value: v})
				break
			}
		}
	case "zip_entry_regex":
		for _, target := range readerTargets(in, r) {
			if v, ok := zipEntryRegexFirst(target, r.Value, &r); ok {
				out = append(out, versionHit{Source: r.Type, Path: target + "!" + r.Value, Value: v})
				break
			}
		}
	case "pe_version":
		if goos != "windows" {
			return nil
		}
		for _, target := range readerTargets(in, r) {
			if v, ok := peVersion(target); ok {
				out = append(out, versionHit{Source: r.Type, Path: target, Value: v})
				break
			}
		}
	}
	return out
}

// readerTargets expands the reader path. Relative paths resolve under the
// install dir; patterns starting with "/" resolve under the scan root (for
// shared files such as /etc/oratab or system libraries).
func readerTargets(in *instance, r Reader) []string {
	if r.Path == "" {
		return nil
	}
	if strings.HasPrefix(r.Path, "/") || strings.HasPrefix(r.Path, `\`) {
		return globUnder(in.root, r.Path)
	}
	if strings.HasPrefix(in.installPath, "registry:") || strings.HasPrefix(in.installPath, "process:") {
		return nil
	}
	return globUnder(in.installPath, r.Path)
}

func (in instance) value() map[string]any {
	var version any
	var versionSource any
	confidence := confidencePresence
	var gap any = "version_unreadable"
	if len(in.versions) > 0 {
		version = in.versions[0].Value
		versionSource = in.versions[0]
		confidence = confidenceDirect
		gap = nil
	}
	procs := make([]map[string]any, 0, len(in.procs))
	for _, p := range in.procs {
		procs = append(procs, map[string]any{"pid": p.PID, "name": p.Name, "exe": nullIfEmpty(p.Exe)})
	}
	regs := make([]string, 0, len(in.regs))
	for _, r := range in.regs {
		regs = append(regs, r.Key)
	}
	ports := in.ports
	if ports == nil {
		ports = []int{}
	}
	paths := in.paths
	if paths == nil {
		paths = []string{}
	}
	cands := in.versions
	if cands == nil {
		cands = []versionHit{}
	}
	patches := in.patches
	if patches == nil {
		patches = []string{}
	}
	return map[string]any{
		"entity_type":        "software_instance",
		"entity_id":          "sw:" + in.product.ProductKey + ":" + in.scope + ":" + shortHash(normalizeKey(in.installPath)),
		"product_key":        in.product.ProductKey,
		"vendor":             in.product.Vendor,
		"product":            in.product.Product,
		"cpe_prefix":         nullIfEmpty(in.product.CPEPrefix),
		"scope":              in.scope,
		"install_path":       nullIfEmpty(in.installPath),
		"version":            version,
		"version_source":     versionSource,
		"version_candidates": cands,
		"patch_ids":          patches,
		"patch_source":       nullIfEmpty(in.patchSource),
		"confidence":         confidence,
		"gap":                gap,
		"running":            len(in.procs) > 0,
		"signals": map[string]any{
			"paths":     paths,
			"processes": procs,
			"ports":     ports,
			"registry":  regs,
		},
		"catalog_verified":     len(in.product.Verified) > 0,
		"owner_package":        in.ownerValue(),
		"owner_package_status": in.ownerStatusValue(),
	}
}

func matchProcess(patterns []string, p procInfo) bool {
	names := []string{strings.ToLower(p.Name)}
	if p.Exe != "" {
		names = append(names, strings.ToLower(filepath.Base(p.Exe)))
	}
	for _, pat := range patterns {
		pat = strings.ToLower(pat)
		for _, n := range names {
			if ok, _ := filepath.Match(pat, n); ok {
				return true
			}
		}
	}
	return false
}

// installDirFor maps a matched file or directory to an install location.
// A file hit uses its parent; a bin/ or sbin/ parent is stepped out of.
func installDirFor(hit string) string {
	dir := hit
	if !existsDir(hit) {
		dir = filepath.Dir(hit)
	}
	base := strings.ToLower(filepath.Base(dir))
	if base == "bin" || base == "sbin" || base == "lib" || base == "lib64" {
		dir = filepath.Dir(dir)
	}
	return dir
}

func normalizeKey(p string) string {
	p = strings.TrimRight(p, `/\`)
	if runtime.GOOS == "windows" {
		p = strings.ToLower(p)
	}
	return p
}

func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
