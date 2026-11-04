package linux

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/s4e-io/openness-collector/internal/modules/common"
	"github.com/s4e-io/openness-collector/internal/schema"
)

const maxContainerPackages = 500
const maxContainersInspect = 40

// Containers inventories Docker/Podman/containerd without mutating runtime state.
type Containers struct{}

func (m *Containers) ID() string          { return "containers" }
func (m *Containers) Version() string     { return "1.0.0" }
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
			rootfs := asString(ev["rootfs_path"])
			var pkgs []map[string]any
			var perr string
			if rootfs != "" {
				pkgs, perr = readContainerPackages(rootfs)
			}
			// Fallback: docker/podman cp of package DB files (read-only, works when MergedDir not mounted).
			if len(pkgs) == 0 {
				pkgs2, perr2 := readContainerPackagesViaCopy(ctx, path, id)
				if len(pkgs2) > 0 {
					pkgs = pkgs2
					ev["package_source"] = "runtime_cp"
					perr = ""
				} else if perr == "" {
					perr = perr2
				}
			} else {
				ev["package_source"] = "rootfs"
			}
			if perr != "" {
				res.Errors = append(res.Errors, common.Err(m.ID(), "partial", shortID(id)+": "+perr))
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
	cmd := exec.CommandContext(ctx, bin, "ps", "-a", "--format", "{{json .}}")
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
	cmd := exec.CommandContext(ctx, bin, "inspect", id)
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
		cmd := exec.CommandContext(ctx, bin, "image", "inspect", key, "--format", "{{json .RepoDigests}}")
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
		cmd2 := exec.CommandContext(ctx, bin, "image", "inspect", key, "--format", "{{.Id}}")
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
	cmd := exec.CommandContext(ctx, "ctr", "-n", "moby", "containers", "ls", "-q")
	out, err := cmd.CombinedOutput()
	if err != nil {
		// try default namespace
		cmd = exec.CommandContext(ctx, "ctr", "containers", "ls", "-q")
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

func readContainerPackages(rootfs string) ([]map[string]any, string) {
	if rootfs == "" {
		return nil, ""
	}
	if st, err := os.Stat(rootfs); err != nil || !st.IsDir() {
		return nil, "rootfs_unavailable"
	}
	var out []map[string]any
	// dpkg
	status := filepath.Join(rootfs, "var/lib/dpkg/status")
	if b, err := os.ReadFile(status); err == nil {
		out = append(out, parseDpkgStatus(string(b))...)
	}
	// apk
	apk := filepath.Join(rootfs, "lib/apk/db/installed")
	if b, err := os.ReadFile(apk); err == nil {
		out = append(out, parseAPKInstalled(string(b))...)
	}
	// rpm sqlite/bdb is harder; try rpm -qa --root if rpm exists (read-only)
	if len(out) == 0 {
		if _, err := exec.LookPath("rpm"); err == nil {
			cmd := exec.Command("rpm", "--root", rootfs, "-qa", "--qf", `%{NAME}\t%{EPOCH}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n`)
			if b, err := cmd.Output(); err == nil {
				out = append(out, parseRPMRoot(string(b))...)
			}
		}
	}
	if len(out) == 0 {
		return nil, "no_package_database"
	}
	if len(out) >= maxContainerPackages {
		out = out[:maxContainerPackages]
		return out, "package_limit_truncated"
	}
	return out, ""
}

// readContainerPackagesViaCopy copies package DB files out via runtime CLI (read-only).
func readContainerPackagesViaCopy(ctx context.Context, bin, containerID string) ([]map[string]any, string) {
	tmp, err := os.MkdirTemp("", "openness-ctr-pkg-*")
	if err != nil {
		return nil, "tmpdir_failed"
	}
	defer os.RemoveAll(tmp)

	candidates := []struct {
		src  string
		kind string
	}{
		{"/var/lib/dpkg/status", "dpkg"},
		{"/lib/apk/db/installed", "apk"},
		{"/var/lib/apk/db/installed", "apk"},
	}
	var out []map[string]any
	for _, c := range candidates {
		dst := filepath.Join(tmp, filepath.Base(c.src)+"."+c.kind)
		cmd := exec.CommandContext(ctx, bin, "cp", containerID+":"+c.src, dst)
		if err := cmd.Run(); err != nil {
			continue
		}
		b, err := os.ReadFile(dst)
		if err != nil || len(b) == 0 {
			continue
		}
		switch c.kind {
		case "dpkg":
			out = append(out, parseDpkgStatus(string(b))...)
		case "apk":
			out = append(out, parseAPKInstalled(string(b))...)
		}
		if len(out) > 0 {
			break
		}
	}
	if len(out) == 0 {
		return nil, "no_package_database"
	}
	if len(out) >= maxContainerPackages {
		out = out[:maxContainerPackages]
		return out, "package_limit_truncated"
	}
	return out, ""
}

func parseDpkgStatus(s string) []map[string]any {
	var out []map[string]any
	blocks := strings.Split(s, "\n\n")
	for _, block := range blocks {
		name, ver, arch, status := "", "", "", ""
		for _, line := range strings.Split(block, "\n") {
			if strings.HasPrefix(line, "Package: ") {
				name = strings.TrimSpace(strings.TrimPrefix(line, "Package: "))
			} else if strings.HasPrefix(line, "Version: ") {
				ver = strings.TrimSpace(strings.TrimPrefix(line, "Version: "))
			} else if strings.HasPrefix(line, "Architecture: ") {
				arch = strings.TrimSpace(strings.TrimPrefix(line, "Architecture: "))
			} else if strings.HasPrefix(line, "Status: ") {
				status = strings.TrimSpace(strings.TrimPrefix(line, "Status: "))
			}
		}
		if name == "" || !strings.Contains(status, "installed") {
			continue
		}
		out = append(out, map[string]any{
			"entity_type":        "package",
			"entity_id":          "pkg:container:dpkg:" + name + ":" + arch + ":" + ver,
			"name":               name,
			"raw_version_string": ver,
			"architecture":       arch,
			"package_manager":    "dpkg",
			"packages_scope":     "container",
			"package_status":     status,
		})
		if len(out) >= maxContainerPackages {
			break
		}
	}
	return out
}

func parseAPKInstalled(s string) []map[string]any {
	pkgs, _ := parseAPKDB(strings.NewReader(s), maxContainerPackages)
	out := make([]map[string]any, 0, len(pkgs))
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
	return out
}

func parseRPMRoot(s string) []map[string]any {
	var out []map[string]any
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		parts := strings.Split(sc.Text(), "\t")
		if len(parts) < 5 {
			continue
		}
		epoch := parts[1]
		if epoch == "(none)" {
			epoch = ""
		}
		raw := parts[2] + "-" + parts[3]
		if epoch != "" {
			raw = epoch + ":" + raw
		}
		out = append(out, map[string]any{
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
		})
		if len(out) >= maxContainerPackages {
			break
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
