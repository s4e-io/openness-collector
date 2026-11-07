package linux

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/s4e-io/openness-collector/internal/modules/common"
	"github.com/s4e-io/openness-collector/internal/procutil"
	"github.com/s4e-io/openness-collector/internal/schema"
)

// maxContainerPackages caps package records per container (same cap as a
// host); maxContainerPackagesTotal caps them across all containers so the
// evidence file stays under its size limit.
const maxContainerPackages = maxPackages
const maxContainerPackagesTotal = 100000
const maxContainersInspect = 40

// Containers inventories Docker/Podman/containerd without mutating runtime state.
type Containers struct{}

func (m *Containers) ID() string          { return "containers" }
func (m *Containers) Version() string     { return "1.3.0" }
func (m *Containers) Platforms() []string { return []string{"linux"} }

func (m *Containers) Run(ctx context.Context) schema.ModuleResult {
	started := time.Now()
	res := common.NewResult(m.ID(), m.Version())

	runtimes := []struct {
		name string
		bin  string
	}{
		{"docker", "docker"},
		{"podman", "podman"},
		{"nerdctl", "nerdctl"},
	}

	foundRuntime := false
	anyPartial := false
	seenID := map[string]bool{}
	pkgBudget := maxContainerPackagesTotal

	for _, rt := range runtimes {
		path, err := exec.LookPath(rt.bin)
		if err != nil {
			continue
		}
		foundRuntime = true
		rows, status, errMsg := listContainersCLI(ctx, path)
		if errMsg != "" {
			code := "unavailable"
			low := strings.ToLower(errMsg)
			if strings.Contains(low, "permission") || strings.Contains(low, "denied") || strings.Contains(low, "cannot connect") {
				code = "permission_denied"
				anyPartial = true
			}
			res.Errors = append(res.Errors, common.Err(m.ID(), code, rt.name+": "+truncateStr(errMsg, 240)))
			if status == "permission_denied" {
				anyPartial = true
			}
			continue
		}
		for i, row := range rows {
			if i >= maxContainersInspect {
				res.Errors = append(res.Errors, common.Err(m.ID(), "record_limit", rt.name+": truncated container inspect"))
				anyPartial = true
				break
			}
			select {
			case <-ctx.Done():
				res.Errors = append(res.Errors, common.Err(m.ID(), "timeout", "containers cancelled"))
				common.Finish(&res, started, "partial")
				return res
			default:
			}
			id := firstString(row, "ID", "Id", "id")
			if id == "" || seenID[id] {
				continue
			}
			seenID[id] = true

			detail := inspectContainer(ctx, path, id)
			ev := normalizeContainer(rt.name, row, detail)
			// Prefer immutable digest from image inspect when list/inspect omit it.
			if asString(ev["image_digest"]) == "" {
				imgRef := asString(ev["image_reference"])
				imgID := asString(ev["image_id"])
				if d := resolveImageDigest(ctx, path, imgRef, imgID); d != "" {
					ev["image_digest"] = d
					rels, _ := ev["relationships"].([]map[string]any)
					ev["relationships"] = append(rels, map[string]any{
						"type":             "container_uses_image",
						"source_entity_id": ev["entity_id"],
						"target_entity_id": "image:" + d,
						"confidence":       "direct",
						"evidence_source":  rt.name + ":image_inspect.RepoDigests",
					})
				}
			}
			// Package DB from overlay merged dir when readable (host-side, no exec into container).
			limit := min(maxContainerPackages, pkgBudget)
			rootfs := asString(ev["rootfs_path"])
			if osr := readContainerOSRelease(ctx, path, id, rootfs); osr != nil {
				ev["os_release"] = osr
			}
			var pkgs []map[string]any
			var truncated bool
			var perr string
			if limit == 0 {
				truncated = true
			} else {
				if rootfs != "" {
					pkgs, truncated, perr = readContainerPackages(ctx, rootfs, limit)
				}
				// Fallback: docker/podman cp of package DB files (read-only, works when MergedDir not mounted).
				if len(pkgs) == 0 {
					pkgs2, truncated2, perr2 := readContainerPackagesViaCopy(ctx, path, id, limit)
					if len(pkgs2) > 0 {
						pkgs, truncated = pkgs2, truncated2
						ev["package_source"] = "runtime_cp"
						// The copy succeeded, so a rootfs read error is moot.
						perr = ""
					} else if perr == "" {
						perr = perr2
					}
				} else {
					ev["package_source"] = "rootfs"
				}
			}
			pkgBudget -= len(pkgs)
			if perr != "" {
				code := "partial"
				if pe := containerPackagesError(perr); pe != nil {
					// A package database is there but was not read: the
					// container's packages are unknown, not empty.
					ev["packages_error"] = pe
					code = "container_packages_unread"
				}
				res.Errors = append(res.Errors, common.Err(m.ID(), code, shortID(id)+": "+perr))
				anyPartial = true
			}
			if truncated {
				// Kept separate from perr so no later step can erase it.
				res.Errors = append(res.Errors, common.Err(m.ID(), "package_limit_truncated",
					shortID(id)+": package records capped at "+itoa(limit)))
				ev["packages_truncated"] = true
				ev["package_limit"] = limit
				res.Truncated = true
				anyPartial = true
			}
			if len(pkgs) > 0 {
				ev["packages"] = pkgs
				ev["package_count"] = len(pkgs)
			} else if rootfs != "" || perr == "no_package_database" {
				ev["package_count"] = 0
				ev["package_db_status"] = "absent_or_unreadable"
			}
			res.Evidence = append(res.Evidence, common.Evidence("native", m.ID(), "observed", ev, nil))
		}
	}

	// containerd via ctr if present and no docker list
	if _, err := exec.LookPath("ctr"); err == nil && len(res.Evidence) == 0 {
		foundRuntime = true
		n, err := listContainerd(ctx, &res)
		if err != nil {
			res.Errors = append(res.Errors, common.Err(m.ID(), "unavailable", "ctr: "+err.Error()))
		} else if n == 0 {
			// ok empty
		}
	}

	if !foundRuntime {
		res.Errors = append(res.Errors, common.Err(m.ID(), "not_supported", "no docker/podman/nerdctl/ctr runtime found"))
		common.Finish(&res, started, "unavailable")
		return res
	}
	status := "success"
	if anyPartial {
		status = "partial"
	}
	if len(res.Evidence) == 0 && len(res.Errors) > 0 {
		// runtime present but inaccessible
		for _, e := range res.Errors {
			if e.Code == "permission_denied" {
				common.Finish(&res, started, "permission_denied")
				return res
			}
		}
		status = "partial"
	}
	common.Finish(&res, started, status)
	return res
}

func listContainersCLI(ctx context.Context, bin string) ([]map[string]any, string, string) {
	// Include stopped; never start/stop.
	cmd := procutil.Command(ctx, bin, "ps", "-a", "--format", "{{json .}}")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, "error", strings.TrimSpace(string(out)) + " " + err.Error()
	}
	var rows []map[string]any
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var row map[string]any
		if json.Unmarshal([]byte(line), &row) == nil {
			rows = append(rows, row)
			continue
		}
	}
	// Some engines emit a JSON array
	if len(rows) == 0 {
		var arr []map[string]any
		if json.Unmarshal(out, &arr) == nil {
			rows = arr
		}
	}
	return rows, "success", ""
}

func inspectContainer(ctx context.Context, bin, id string) map[string]any {
	cmd := procutil.Command(ctx, bin, "inspect", id)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return map[string]any{"inspect_error": strings.TrimSpace(string(out))}
	}
	var arr []map[string]any
	if json.Unmarshal(out, &arr) == nil && len(arr) > 0 {
		return arr[0]
	}
	var one map[string]any
	if json.Unmarshal(out, &one) == nil {
		return one
	}
	return nil
}

func normalizeContainer(runtime string, listRow, detail map[string]any) map[string]any {
	id := firstString(listRow, "ID", "Id", "id")
	name := firstString(listRow, "Names", "Name", "name")
	image := firstString(listRow, "Image", "image")
	state := firstString(listRow, "State", "Status", "state")
	digest := ""
	imageID := ""
	rootfs := ""
	pid := 0
	if detail != nil {
		if id == "" {
			id = firstString(detail, "Id", "ID")
		}
		if name == "" {
			name = firstString(detail, "Name")
		}
		if cfg, ok := detail["Config"].(map[string]any); ok {
			if image == "" {
				image = asString(cfg["Image"])
			}
		}
		if img, ok := detail["Image"].(string); ok && imageID == "" {
			imageID = img
		}
		if stateMap, ok := detail["State"].(map[string]any); ok {
			if state == "" {
				state = asString(stateMap["Status"])
			}
			pid = asInt(stateMap["Pid"])
		}
		// RepoDigests from ImageInspect is separate; try GraphDriver UpperDir / MergedDir
		if gd, ok := detail["GraphDriver"].(map[string]any); ok {
			if data, ok := gd["Data"].(map[string]any); ok {
				rootfs = firstString(data, "MergedDir", "UpperDir")
			}
		}
		if ri, ok := detail["ImageManifestDescriptor"].(map[string]any); ok {
			digest = asString(ri["digest"])
		}
		// podman/docker may expose ImageDigest
		digest = firstNonEmpty(digest, asString(detail["ImageDigest"]), asString(listRow["Digest"]))
	}
	if digest == "" && strings.Contains(image, "@sha256:") {
		parts := strings.Split(image, "@")
		digest = parts[len(parts)-1]
	}
	if digest == "" && strings.HasPrefix(imageID, "sha256:") {
		digest = imageID
	}

	ev := map[string]any{
		"entity_id":            "container:" + shortID(id),
		"entity_type":          "container",
		"runtime":              runtime,
		"container_id":         id,
		"name":                 strings.TrimPrefix(name, "/"),
		"image_reference":      nullIfEmpty(image),
		"image_id":             nullIfEmpty(imageID),
		"image_digest":         nullIfEmpty(digest),
		"state":                nullIfEmpty(state),
		"pid":                  nullIfZero(pid),
		"rootfs_path":          nullIfEmpty(rootfs),
		"packages_scope":       "container",
		"host_packages_merged": false,
		"identity_primary":     "image_digest",
		"relationships":        []map[string]any{},
	}
	if pid > 0 {
		ev["relationships"] = []map[string]any{{
			"type":             "process_runs_in_container",
			"source_entity_id": "process:" + itoa(pid),
			"target_entity_id": ev["entity_id"],
			"confidence":       "direct",
			"evidence_source":  runtime + ":inspect.State.Pid",
		}}
	}
	if digest != "" {
		rels, _ := ev["relationships"].([]map[string]any)
		ev["relationships"] = append(rels, map[string]any{
			"type":             "container_uses_image",
			"source_entity_id": ev["entity_id"],
			"target_entity_id": "image:" + digest,
			"confidence":       "direct",
			"evidence_source":  runtime + ":image_digest",
		})
	}
	return ev
}

func resolveImageDigest(ctx context.Context, bin, imageRef, imageID string) string {
	for _, key := range []string{imageRef, imageID} {
		if strings.TrimSpace(key) == "" {
			continue
		}
		cmd := procutil.Command(ctx, bin, "image", "inspect", key, "--format", "{{json .RepoDigests}}")
		out, err := cmd.CombinedOutput()
		if err != nil {
			continue
		}
		var digests []string
		if json.Unmarshal(out, &digests) == nil {
			for _, d := range digests {
				if i := strings.Index(d, "@"); i >= 0 {
					return d[i+1:]
				}
				if strings.HasPrefix(d, "sha256:") {
					return d
				}
			}
		}
		// fallback: Image ID is content-addressable even if not a registry digest
		cmd2 := procutil.Command(ctx, bin, "image", "inspect", key, "--format", "{{.Id}}")
		out2, err2 := cmd2.CombinedOutput()
		if err2 == nil {
			id := strings.TrimSpace(string(out2))
			if strings.HasPrefix(id, "sha256:") {
				return id
			}
		}
	}
	return ""
}

func listContainerd(ctx context.Context, res *schema.ModuleResult) (int, error) {
	cmd := procutil.Command(ctx, "ctr", "-n", "moby", "containers", "ls", "-q")
	out, err := cmd.CombinedOutput()
	if err != nil {
		// try default namespace
		cmd = procutil.Command(ctx, "ctr", "containers", "ls", "-q")
		out, err = cmd.CombinedOutput()
		if err != nil {
			return 0, err
		}
	}
	n := 0
	for _, id := range strings.Fields(string(out)) {
		if id == "" {
			continue
		}
		res.Evidence = append(res.Evidence, common.Evidence("native", "containers", "observed", map[string]any{
			"entity_id":        "container:" + shortID(id),
			"entity_type":      "container",
			"runtime":          "containerd",
			"container_id":     id,
			"image_digest":     nil,
			"packages_scope":   "container",
			"identity_primary": "container_id",
		}, nil))
		n++
		if n >= maxContainersInspect {
			break
		}
	}
	return n, nil
}

// readContainerPackages reads the package database in a host-visible
// container rootfs. The error string is a code, optionally followed by ": "
// and a detail.
// rpm_timeout, rpm_unavailable and package_read_failed mean a package
// database is present but was not read (see containerPackagesError).
func readContainerPackages(ctx context.Context, rootfs string, limit int) ([]map[string]any, bool, string) {
	if rootfs == "" {
		return nil, false, ""
	}
	if st, err := os.Stat(rootfs); err != nil || !st.IsDir() {
		return nil, false, "rootfs_unavailable"
	}
	var out []map[string]any
	truncated := false
	readErr := ""
	noteErr := func(what string, err error) {
		if err != nil && readErr == "" {
			readErr = pkgErrReadFailed + ": " + what + ": " + err.Error()
		}
	}
	// dpkg (status file and distroless status.d)
	if f, err := os.Open(filepath.Join(rootfs, "var/lib/dpkg/status")); err == nil {
		out, truncated, err = parseDpkgStatus(f, out, limit)
		_ = f.Close()
		noteErr("dpkg status", err)
	} else if !os.IsNotExist(err) {
		noteErr("dpkg status", err)
	}
	if !truncated {
		var err error
		out, truncated, err = parseDpkgStatusD(filepath.Join(rootfs, "var/lib/dpkg/status.d"), out, limit)
		noteErr("dpkg status.d", err)
	}
	// apk
	if !truncated {
		if f, err := os.Open(filepath.Join(rootfs, "lib/apk/db/installed")); err == nil {
			out, truncated, err = parseAPKInstalled(f, out, limit)
			_ = f.Close()
			noteErr("apk installed db", err)
		} else if !os.IsNotExist(err) {
			noteErr("apk installed db", err)
		}
	}
	// rpm sqlite/bdb is harder; try rpm -qa --root if rpm exists (read-only)
	if len(out) == 0 {
		hasDB := hasRPMDatabase(rootfs)
		if _, err := exec.LookPath("rpm"); err == nil {
			stopped, err := streamCommandLines(ctx, func(line string) bool {
				if len(out) >= limit {
					return false
				}
				if p := parseRPMRootLine(line); p != nil {
					out = append(out, p)
				}
				return true
			}, "rpm", "--root", rootfs, "-qa", "--qf", `%{NAME}\t%{EPOCH}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n`)
			truncated = stopped
			if err != nil && len(out) == 0 {
				if ctx.Err() != nil {
					return nil, false, pkgErrRPMTimeout
				}
				if hasDB {
					return nil, false, pkgErrReadFailed + ": rpm --root: " + truncateStr(err.Error(), 200)
				}
			}
		} else if hasDB {
			return nil, false, pkgErrRPMUnavailable + ": rpm database present but rpm is not installed on the host"
		}
	}
	if len(out) == 0 {
		if readErr != "" {
			return nil, false, readErr
		}
		return nil, false, "no_package_database"
	}
	return out, truncated, readErr
}

// Package read error codes for a container whose package database is present
// but could not be read.
const (
	pkgErrRPMTimeout     = "rpm_timeout"
	pkgErrRPMUnavailable = "rpm_unavailable"
	pkgErrReadFailed     = "package_read_failed"
)

// pkgErrMessages are the default messages when an error carries no detail.
var pkgErrMessages = map[string]string{
	pkgErrRPMTimeout:     "rpm --root did not finish before the module deadline",
	pkgErrRPMUnavailable: "rpm database present but rpm is not installed on the host",
	pkgErrReadFailed:     "package database could not be read",
}

// containerPackagesError maps a package read error to the container record's
// packages_error object, or nil when the error does not mean an unread
// package database (no_package_database, rootfs_unavailable, ...).
func containerPackagesError(perr string) map[string]any {
	code, detail, _ := strings.Cut(perr, ": ")
	msg, ok := pkgErrMessages[code]
	if !ok {
		return nil
	}
	if detail != "" {
		msg = detail
	}
	return map[string]any{"code": code, "message": msg}
}

// rpmDatabasePaths are rpmdb files relative to a root: the classic location
// and the /usr/lib/sysimage one used by newer RPM distributions.
var rpmDatabasePaths = []string{
	"var/lib/rpm/rpmdb.sqlite", "var/lib/rpm/Packages", "var/lib/rpm/Packages.db",
	"usr/lib/sysimage/rpm/rpmdb.sqlite", "usr/lib/sysimage/rpm/Packages", "usr/lib/sysimage/rpm/Packages.db",
}

// hasRPMDatabase reports whether rootfs holds an rpm database file.
func hasRPMDatabase(rootfs string) bool {
	for _, p := range rpmDatabasePaths {
		if _, err := os.Lstat(filepath.Join(rootfs, p)); err == nil {
			return true
		}
	}
	return false
}

// readContainerPackagesViaCopy copies package DB files out via runtime CLI (read-only).
func readContainerPackagesViaCopy(ctx context.Context, bin, containerID string, limit int) ([]map[string]any, bool, string) {
	tmp, err := os.MkdirTemp("", "openness-ctr-pkg-*")
	if err != nil {
		return nil, false, "tmpdir_failed"
	}
	defer os.RemoveAll(tmp)

	candidates := []struct {
		src  string
		kind string
	}{
		{"/var/lib/dpkg/status", "dpkg"},
		{"/var/lib/dpkg/status.d", "dpkg-status.d"},
		{"/lib/apk/db/installed", "apk"},
		{"/var/lib/apk/db/installed", "apk"},
	}
	var out []map[string]any
	truncated := false
	readErr := ""
	for _, c := range candidates {
		dst := filepath.Join(tmp, filepath.Base(c.src)+"."+c.kind)
		cmd := procutil.Command(ctx, bin, "cp", containerID+":"+c.src, dst)
		if err := cmd.Run(); err != nil {
			continue
		}
		var perr error
		if c.kind == "dpkg-status.d" {
			out, truncated, perr = parseDpkgStatusD(dst, out, limit)
		} else if f, err := os.Open(dst); err == nil {
			if c.kind == "dpkg" {
				out, truncated, perr = parseDpkgStatus(f, out, limit)
			} else {
				out, truncated, perr = parseAPKInstalled(f, out, limit)
			}
			_ = f.Close()
		} else {
			perr = err
		}
		if perr != nil && readErr == "" {
			readErr = pkgErrReadFailed + ": " + c.src + ": " + perr.Error()
		}
		if len(out) > 0 {
			break
		}
	}
	if len(out) == 0 {
		if readErr != "" {
			return nil, false, readErr
		}
		return nil, false, "no_package_database"
	}
	return out, truncated, readErr
}

// parseDpkgStatus appends installed packages from a dpkg status stream to out
// and stops at limit records; the bool reports that packages were left out.
func parseDpkgStatus(r io.Reader, out []map[string]any, limit int) ([]map[string]any, bool, error) {
	truncated := false
	err := scanDpkgStanzas(r, func(fields map[string]string) bool {
		if !dpkgStanzaInstalled(fields, false) {
			return true
		}
		if len(out) >= limit {
			truncated = true
			return false
		}
		out = append(out, containerDpkgRecord(fields))
		return true
	})
	return out, truncated, err
}

// parseDpkgStatusD is parseDpkgStatus for a distroless status.d directory.
// A missing directory is not an error.
func parseDpkgStatusD(dir string, out []map[string]any, limit int) ([]map[string]any, bool, error) {
	truncated := false
	err := scanDpkgStatusD(dir, func(fields map[string]string) bool {
		if len(out) >= limit {
			truncated = true
			return false
		}
		out = append(out, containerDpkgRecord(fields))
		return true
	})
	if errors.Is(err, fs.ErrNotExist) {
		err = nil
	}
	return out, truncated, err
}

func containerDpkgRecord(fields map[string]string) map[string]any {
	name, ver, arch := fields["Package"], fields["Version"], fields["Architecture"]
	status := fields["Status"]
	if status == "" {
		status = "install ok installed"
	}
	// Vendor rules are keyed by source package, so the dpkg Source field is
	// kept as on the host; without it the source is the binary name.
	srcName, srcVer := ParseDebianSource(fields["Source"])
	if srcName == "" {
		srcName = name
	}
	return map[string]any{
		"source_package":     srcName,
		"source_version":     srcVer,
		"entity_type":        "package",
		"entity_id":          "pkg:container:dpkg:" + name + ":" + arch + ":" + ver,
		"name":               name,
		"raw_version_string": ver,
		"architecture":       arch,
		"package_manager":    "dpkg",
		"packages_scope":     "container",
		"package_status":     status,
	}
}

func parseAPKInstalled(r io.Reader, out []map[string]any, limit int) ([]map[string]any, bool, error) {
	room := limit - len(out)
	if room <= 0 {
		return out, true, nil
	}
	// One past the room so a cut is detectable.
	pkgs, err := parseAPKDB(r, room+1)
	truncated := len(pkgs) > room
	if truncated {
		pkgs = pkgs[:room]
	}
	for _, p := range pkgs {
		out = append(out, map[string]any{
			"entity_type":        "package",
			"entity_id":          "pkg:container:apk:" + p.Name + ":" + p.Version,
			"name":               p.Name,
			"raw_version_string": p.Version,
			"architecture":       p.Arch,
			"package_manager":    "apk",
			"packages_scope":     "container",
		})
	}
	return out, truncated, err
}

func parseRPMRootLine(line string) map[string]any {
	parts := strings.Split(line, "\t")
	if len(parts) < 5 {
		return nil
	}
	epoch := parts[1]
	if epoch == "(none)" {
		epoch = ""
	}
	raw := parts[2] + "-" + parts[3]
	if epoch != "" {
		raw = epoch + ":" + raw
	}
	return map[string]any{
		"entity_type":        "package",
		"entity_id":          "pkg:container:rpm:" + parts[0] + ":" + parts[4] + ":" + raw,
		"name":               parts[0],
		"epoch":              nullIfEmpty(epoch),
		"version":            parts[2],
		"release":            parts[3],
		"architecture":       parts[4],
		"raw_version_string": raw,
		"package_manager":    "rpm",
		"packages_scope":     "container",
	}
}

// osReleaseFiles are the os-release locations, in os-release(5) order.
var osReleaseFiles = []string{"/etc/os-release", "/usr/lib/os-release"}

// maxOSReleaseBytes bounds an os-release read; real files are a few hundred bytes.
const maxOSReleaseBytes = 64 << 10

// readContainerOSRelease returns the container's os-release identity, read
// from the host-visible rootfs or, failing that, copied out with the runtime
// CLI (read-only). It returns nil when neither path has an os-release file.
func readContainerOSRelease(ctx context.Context, bin, containerID, rootfs string) map[string]any {
	if rootfs != "" {
		for _, f := range osReleaseFiles {
			if raw := readRootfsOSRelease(rootfs, f); raw != nil {
				return osReleaseIdentity(raw, "rootfs", f)
			}
		}
	}
	if bin == "" || containerID == "" {
		return nil
	}
	tmp, err := os.MkdirTemp("", "openness-ctr-osr-*")
	if err != nil {
		return nil
	}
	defer os.RemoveAll(tmp)
	for i, f := range osReleaseFiles {
		dst := filepath.Join(tmp, "os-release."+itoa(i))
		if err := procutil.Command(ctx, bin, "cp", containerID+":"+f, dst).Run(); err != nil {
			continue
		}
		// docker cp copies a symlink as a link (/etc/os-release usually is
		// one); only a regular file is read, so a link never leads to a host
		// file. The next candidate is the link target on most images.
		if raw := readOSReleaseFile(dst); raw != nil {
			return osReleaseIdentity(raw, "runtime_cp", f)
		}
	}
	return nil
}

// readRootfsOSRelease reads rel inside rootfs. A symlink is followed one
// level and only inside rootfs (absolute targets are re-rooted).
func readRootfsOSRelease(rootfs, rel string) map[string]string {
	p := filepath.Join(rootfs, rel)
	if target, err := os.Readlink(p); err == nil {
		if filepath.IsAbs(target) {
			p = filepath.Join(rootfs, target)
		} else {
			p = filepath.Join(rootfs, filepath.Dir(rel), target)
		}
		if !strings.HasPrefix(p, filepath.Clean(rootfs)+string(filepath.Separator)) {
			return nil
		}
	}
	return readOSReleaseFile(p)
}

// readOSReleaseFile parses a regular os-release file; nil when the path is
// missing, not a regular file, too large or has no identity.
func readOSReleaseFile(path string) map[string]string {
	st, err := os.Lstat(path)
	if err != nil || !st.Mode().IsRegular() || st.Size() > maxOSReleaseBytes {
		return nil
	}
	raw, err := readKeyValueFile(path)
	if err != nil || (strings.TrimSpace(raw["ID"]) == "" && strings.TrimSpace(raw["NAME"]) == "") {
		return nil
	}
	normalizeOsReleaseKeys(raw)
	return raw
}

// osReleaseIdentity maps os-release keys to the container record's
// os_release object. Absent keys are left out.
func osReleaseIdentity(raw map[string]string, source, file string) map[string]any {
	out := map[string]any{"source": source, "source_file": file}
	for _, k := range []struct{ key, field string }{
		{"ID", "id"},
		{"ID_LIKE", "id_like"},
		{"NAME", "name"},
		{"VERSION_ID", "version_id"},
		{"VERSION_CODENAME", "version_codename"},
		{"PRETTY_NAME", "pretty_name"},
	} {
		v := strings.TrimSpace(raw[k.key])
		if k.key == "ID_LIKE" {
			v = strings.ToLower(v)
		}
		if v != "" {
			out[k.field] = v
		}
	}
	return out
}

func firstString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v := asString(m[k]); v != "" {
			return v
		}
	}
	return ""
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func shortID(id string) string {
	id = strings.TrimPrefix(id, "sha256:")
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func itoa(n int) string {
	return strconv.Itoa(n)
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
