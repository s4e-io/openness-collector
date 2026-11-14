package swinv

import (
	"context"
	"os"

	"github.com/s4e-io/openness-collector/internal/pkgowner"
)

// owner_package_status values. The collector only reports the fact; whether
// an owned instance is already covered by the package's own advisories is
// decided downstream.
const (
	ownerOwned      = "owned"       // a package owns one of the instance's files
	ownerNotOwned   = "not_owned"   // package databases were read, no owner
	ownerNotChecked = "not_checked" // no package database, or no file to ask about
)

// ownerFiles returns the regular files that identify an instance: the path
// signals that hit and the executables of its processes. Directories are
// left out because packages share them.
func (in instance) ownerFiles() []string {
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		if p == "" || seen[p] {
			return
		}
		seen[p] = true
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
			out = append(out, p)
		}
	}
	for _, p := range in.paths {
		add(p)
	}
	for _, p := range in.procs {
		add(p.Exe)
	}
	return out
}

// resolveOwners fills owner and ownerStatus on every instance with one
// lookup for all of them, and returns the package databases that were read.
func resolveOwners(ctx context.Context, goos, root string, all []instance) []string {
	managers := []string{}
	for i := range all {
		all[i].ownerStatus = ownerNotChecked
	}
	if goos != "linux" || len(all) == 0 {
		return managers
	}
	files := make([][]string, len(all))
	var query []string
	for i := range all {
		files[i] = all[i].ownerFiles()
		query = append(query, files[i]...)
	}
	res := pkgowner.Resolve(ctx, root, query)
	if len(res.Managers) == 0 {
		return managers
	}
	for i := range all {
		if len(files[i]) == 0 {
			continue
		}
		all[i].ownerStatus = ownerNotOwned
		for _, f := range files[i] {
			if o, ok := res.Owners[f]; ok {
				all[i].owner = &o
				all[i].ownerStatus = ownerOwned
				break
			}
		}
	}
	return res.Managers
}

func (in instance) ownerValue() any {
	if in.owner == nil {
		return nil
	}
	return in.owner.Value()
}

func (in instance) ownerStatusValue() string {
	if in.ownerStatus == "" {
		return ownerNotChecked
	}
	return in.ownerStatus
}
