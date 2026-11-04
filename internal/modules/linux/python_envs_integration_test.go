package linux

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/s4e-io/openness-collector/internal/evidencefile"
	"github.com/s4e-io/openness-collector/internal/modules/common"
	"github.com/s4e-io/openness-collector/internal/schema"
)

func TestIntegration_DpkgAndPipSameUpstream(t *testing.T) {
	st := newPythonScanState(defaultPythonScanLimits())
	meta := "/usr/lib/python3/dist-packages/requests-2.25.1.dist-info/METADATA"
	idx := newDpkgOwnershipIndex()
	idx.pkgs["python3-requests"] = dpkgPkgRec{
		Name: "python3-requests", Arch: "all", Version: "2.25.1-2ubuntu1", Source: "requests",
	}
	idx.byPath[meta] = "python3-requests"
	injectDpkgOwnershipIndex(st, idx)

	dpkgDist := baseDistRec("requests", "requests", "2.25.1", "system", "host", "python:env:sys", meta)
	dpkgDist["installer"] = "pip" // upstream METADATA noise
	rels := applyPythonDistOSOwnership(st, dpkgDist)
	if asString(dpkgDist["installation_origin"]) != "os_package" {
		t.Fatalf("dpkg origin %#v", dpkgDist["installation_origin"])
	}
	wantPkgID := "pkg:dpkg:python3-requests:all:2.25.1-2ubuntu1"
	if len(rels) != 1 || asString(rels[0]["target_entity_id"]) != wantPkgID {
		t.Fatalf("os package relationship target %#v want %s", rels, wantPkgID)
	}
	if strings.HasPrefix(asString(rels[0]["target_entity_id"]), "package:dpkg:") {
		t.Fatal("legacy package:dpkg: prefix must not be used")
	}

	pipDist := baseDistRec("requests", "requests", "2.32.0", "venv", "host", "python:env:venv",
		"/usr/local/lib/python3.11/site-packages/requests-2.32.0.dist-info/METADATA")
	pipDist["installer"] = "pip"
	_ = applyPythonDistOSOwnership(st, pipDist)
	if asString(pipDist["installation_origin"]) != "pip" || asString(pipDist["resolver_ecosystem"]) != "pypi" {
		t.Fatalf("pip copy %#v", pipDist)
	}
}

func TestIntegration_DistPackagesNotPyPIWithoutOwnership(t *testing.T) {
	st := newPythonScanState(defaultPythonScanLimits())
	injectDpkgOwnershipIndex(st, newDpkgOwnershipIndex()) // empty index
	d := baseDistRec("requests", "requests", "2.25.1", "system", "host", "python:env:sys",
		"/usr/lib/python3/dist-packages/requests-2.25.1.dist-info/METADATA")
	d["installer"] = "pip"
	_ = applyPythonDistOSOwnership(st, d)
	if asString(d["installation_origin"]) == "pip" || asString(d["resolver_ecosystem"]) == "pypi" {
		t.Fatalf("must not classify as pip/pypi: %#v", d)
	}
}

func TestIntegration_TwoVenvsDifferentVersions(t *testing.T) {
	root := t.TempDir()
	v1, py1, s1 := makeVenv(t, filepath.Join(root, "a"), "3.11")
	v2, py2, s2 := makeVenv(t, filepath.Join(root, "b"), "3.11")
	writeDist(t, s1, "urllib3", "1.26.0", "pip", false)
	writeDist(t, s2, "urllib3", "2.2.0", "pip", false)
	p1 := procSeed{pid: 11, exe: py1, cmdline: py1 + " a.py", environ: map[string]string{"VIRTUAL_ENV": v1}}
	p2 := procSeed{pid: 12, exe: py2, cmdline: py2 + " b.py", environ: map[string]string{"VIRTUAL_ENV": v2}}
	recs, _, _ := collectPythonInventoryFromSeeds(context.Background(), []procSeed{p1, p2}, defaultPythonScanLimits())
	vers := map[string]bool{}
	for _, d := range entitiesByType(recs, "python_distribution") {
		if asString(d["name_normalized"]) == "urllib3" {
			vers[asString(d["raw_version_string"])] = true
			if asString(d["installation_origin"]) != "pip" {
				t.Fatalf("venv dist origin %#v", d["installation_origin"])
			}
		}
	}
	if !vers["1.26.0"] || !vers["2.2.0"] {
		t.Fatalf("versions %#v", vers)
	}
}

func TestIntegration_TwoProcessesSameEnvironment(t *testing.T) {
	root := t.TempDir()
	venv, py, site := makeVenv(t, root, "3.11")
	writeDist(t, site, "sharedpkg", "1.0.0", "pip", false)
	p1 := procSeed{pid: 21, exe: py, cmdline: py + " a.py", environ: map[string]string{"VIRTUAL_ENV": venv}}
	p2 := procSeed{pid: 22, exe: py, cmdline: py + " b.py", environ: map[string]string{"VIRTUAL_ENV": venv}}
	recs, _, cov := collectPythonInventoryFromSeeds(context.Background(), []procSeed{p1, p2}, defaultPythonScanLimits())

	var envUses, interpUses int
	for _, r := range entitiesByType(recs, "relationship") {
		switch r["relationship"] {
		case "process_uses_python_environment":
			envUses++
		case "process_uses_python_interpreter":
			interpUses++
		}
	}
	if envUses < 2 || interpUses < 2 {
		t.Fatalf("expected per-process relationships, envUses=%d interpUses=%d", envUses, interpUses)
	}
	found := false
	for _, e := range entitiesByType(recs, "python_environment") {
		pids := asIntSlice(e["process_ids"])
		has21, has22 := false, false
		for _, id := range pids {
			if id == 21 {
				has21 = true
			}
			if id == 22 {
				has22 = true
			}
		}
		if has21 && has22 {
			found = true
		}
	}
	if !found {
		t.Fatalf("process_ids must contain both PIDs")
	}
	if cov.EnvsConnectedToProcesses < 1 {
		t.Fatalf("coverage connected envs %#v", cov)
	}
}

func TestIntegration_LoadedWithDirectEvidence(t *testing.T) {
	// apt_pkg*.so → python3-apt → python-apt; sibling dist in same dir stays unloaded.
	site := "/usr/lib/python3/dist-packages"
	aptSO := site + "/apt_pkg.cpython-310-aarch64-linux-gnu.so"
	st := newPythonScanState(defaultPythonScanLimits())
	idx := newDpkgOwnershipIndex()
	idx.pkgs["python3-apt"] = dpkgPkgRec{Name: "python3-apt", Arch: "arm64", Version: "2.4.0", Source: "python-apt"}
	idx.pkgs["python3-blinker"] = dpkgPkgRec{Name: "python3-blinker", Arch: "all", Version: "1.4+dfsg1-0.4", Source: "blinker"}
	idx.byPath[aptSO] = "python3-apt"
	idx.byPath[site+"/python_apt-2.4.0.dist-info/METADATA"] = "python3-apt"
	idx.byPath[site+"/blinker-1.4.dist-info/METADATA"] = "python3-blinker"
	injectDpkgOwnershipIndex(st, idx)

	aptDist := baseDistRec("python-apt", "python-apt", "2.4.0", "system", "host", "python:env:sys",
		site+"/python_apt-2.4.0.dist-info/METADATA")
	blinker := baseDistRec("blinker", "blinker", "1.4", "system", "host", "python:env:sys",
		site+"/blinker-1.4.dist-info/METADATA")
	_ = applyPythonDistOSOwnership(st, aptDist)
	_ = applyPythonDistOSOwnership(st, blinker)
	st.distRecords[asString(aptDist["entity_id"])] = aptDist
	st.distRecords[asString(blinker["entity_id"])] = blinker
	st.distByEnv["python:env:sys"] = []map[string]any{aptDist, blinker}

	st.mappedFilesByPID[31] = []string{aptSO}
	finalizePythonActiveCoverage(st, map[string]bool{"python:env:sys": true})

	if asString(aptDist["runtime_load_status"]) != "confirmed_loaded" {
		t.Fatalf("python-apt %#v", aptDist)
	}
	if asString(aptDist["runtime_detection_method"]) != "proc_maps_dpkg_ownership" {
		t.Fatalf("method %#v", aptDist["runtime_detection_method"])
	}
	paths, _ := aptDist["loaded_module_paths"].([]string)
	if len(paths) != 1 || paths[0] != aptSO {
		t.Fatalf("paths %#v", aptDist["loaded_module_paths"])
	}
	if asString(blinker["runtime_load_status"]) != "installed_not_proven_loaded" {
		t.Fatalf("blinker must stay unloaded %#v", blinker)
	}
	if st.coverage.DistributionsConfirmedLoaded != 1 {
		t.Fatalf("confirmed %#v", st.coverage.DistributionsConfirmedLoaded)
	}
	if len(st.pendingLoadRels) != 1 ||
		st.pendingLoadRels[0]["source_entity_id"] != "process:31" ||
		st.pendingLoadRels[0]["target_entity_id"] != aptDist["entity_id"] {
		t.Fatalf("rels %#v", st.pendingLoadRels)
	}
}

func TestIntegration_ConfirmedLoadedPathsOwnedByOSPackage(t *testing.T) {
	site := "/usr/lib/python3/dist-packages"
	giSO := site + "/gi/_gi.cpython-310-aarch64-linux-gnu.so"
	cairoSO := site + "/cairo/_cairo.cpython-310-aarch64-linux-gnu.so"
	st := newPythonScanState(defaultPythonScanLimits())
	idx := newDpkgOwnershipIndex()
	idx.pkgs["python3-gi"] = dpkgPkgRec{Name: "python3-gi", Arch: "arm64", Version: "3.42.1", Source: "pygobject"}
	idx.pkgs["python3-cairo"] = dpkgPkgRec{Name: "python3-cairo", Arch: "arm64", Version: "1.20.1", Source: "pycairo"}
	idx.byPath[giSO] = "python3-gi"
	idx.byPath[cairoSO] = "python3-cairo"
	idx.byPath[site+"/PyGObject-3.42.1.dist-info/METADATA"] = "python3-gi"
	idx.byPath[site+"/pycairo-1.20.1.dist-info/METADATA"] = "python3-cairo"
	injectDpkgOwnershipIndex(st, idx)

	gi := baseDistRec("PyGObject", "pygobject", "3.42.1", "system", "host", "python:env:sys",
		site+"/PyGObject-3.42.1.dist-info/METADATA")
	cairo := baseDistRec("pycairo", "pycairo", "1.20.1", "system", "host", "python:env:sys",
		site+"/pycairo-1.20.1.dist-info/METADATA")
	_ = applyPythonDistOSOwnership(st, gi)
	_ = applyPythonDistOSOwnership(st, cairo)
	st.distRecords[asString(gi["entity_id"])] = gi
	st.distRecords[asString(cairo["entity_id"])] = cairo
	st.distByEnv["python:env:sys"] = []map[string]any{gi, cairo}
	st.mappedFilesByPID[7] = []string{giSO, cairoSO}
	finalizePythonActiveCoverage(st, map[string]bool{"python:env:sys": true})

	for _, rec := range []map[string]any{gi, cairo} {
		if asString(rec["runtime_load_status"]) != "confirmed_loaded" {
			t.Fatalf("%#v", rec)
		}
		osBin := asString(rec["os_binary_package"])
		paths, _ := rec["loaded_module_paths"].([]string)
		if len(paths) == 0 {
			t.Fatalf("missing paths %#v", rec)
		}
		for _, p := range paths {
			owner, ok := st.dpkg().ownerPackage(p)
			if !ok || owner != osBin {
				t.Fatalf("path %s owned by %q want os_binary_package %q for %#v", p, owner, osBin, rec)
			}
		}
	}
}

func TestIntegration_SharedSitePackagesDoesNotMarkNeighbors(t *testing.T) {
	site := "/usr/lib/python3/dist-packages"
	dbusSO := site + "/_dbus_bindings.cpython-310-aarch64-linux-gnu.so"
	st := newPythonScanState(defaultPythonScanLimits())
	idx := newDpkgOwnershipIndex()
	idx.pkgs["python3-dbus"] = dpkgPkgRec{Name: "python3-dbus", Arch: "arm64", Version: "1.2.18", Source: "dbus-python"}
	for _, name := range []string{"brlapi", "apturl", "blinker", "command-not-found", "cupshelpers", "gpg", "louis", "pexpect", "pycups", "systemd-python", "ufw", "xdg", "xkit"} {
		pkg := "python3-" + name
		if name == "command-not-found" {
			pkg = "command-not-found"
		}
		idx.pkgs[pkg] = dpkgPkgRec{Name: pkg, Arch: "all", Version: "1", Source: name}
		idx.byPath[site+"/"+name+"-1.dist-info/METADATA"] = pkg
	}
	idx.byPath[dbusSO] = "python3-dbus"
	idx.byPath[site+"/dbus_python-1.2.18.dist-info/METADATA"] = "python3-dbus"
	injectDpkgOwnershipIndex(st, idx)

	dbus := baseDistRec("dbus-python", "dbus-python", "1.2.18", "system", "host", "python:env:sys",
		site+"/dbus_python-1.2.18.dist-info/METADATA")
	_ = applyPythonDistOSOwnership(st, dbus)
	st.distRecords[asString(dbus["entity_id"])] = dbus
	var neighbors []map[string]any
	for _, name := range []string{"brlapi", "apturl", "blinker", "command-not-found", "cupshelpers", "gpg", "louis", "pexpect", "pycups", "systemd-python", "ufw", "xdg", "xkit"} {
		d := baseDistRec(name, name, "1", "system", "host", "python:env:sys", site+"/"+name+"-1.dist-info/METADATA")
		_ = applyPythonDistOSOwnership(st, d)
		st.distRecords[asString(d["entity_id"])] = d
		neighbors = append(neighbors, d)
	}
	st.distByEnv["python:env:sys"] = append([]map[string]any{dbus}, neighbors...)
	// Two processes map the same dbus extension — only dbus-python loads, once per PID.
	st.mappedFilesByPID[11] = []string{dbusSO}
	st.mappedFilesByPID[12] = []string{dbusSO}
	finalizePythonActiveCoverage(st, map[string]bool{"python:env:sys": true})

	if asString(dbus["runtime_load_status"]) != "confirmed_loaded" {
		t.Fatalf("dbus %#v", dbus)
	}
	paths, _ := dbus["loaded_module_paths"].([]string)
	if len(paths) != 1 || paths[0] != dbusSO {
		t.Fatalf("dbus paths must be exact extension only: %#v", paths)
	}
	for _, d := range neighbors {
		if asString(d["runtime_load_status"]) != "installed_not_proven_loaded" {
			t.Fatalf("neighbor %s wrongly loaded: %#v", d["name_normalized"], d)
		}
	}
	if st.coverage.DistributionsConfirmedLoaded != 1 {
		t.Fatalf("confirmed %#v", st.coverage.DistributionsConfirmedLoaded)
	}
	if len(st.pendingLoadRels) != 2 {
		t.Fatalf("expected 2 process_loads (one per PID), got %#v", st.pendingLoadRels)
	}
}

func TestIntegration_ActiveEnvWithoutLoadEvidence(t *testing.T) {
	root := t.TempDir()
	venv, py, site := makeVenv(t, root, "3.11")
	writeDist(t, site, "onlyinstalled", "1.0.0", "pip", false)
	st := newPythonScanState(defaultPythonScanLimits())
	injectDpkgOwnershipIndex(st, newDpkgOwnershipIndex())
	p := procSeed{pid: 41, exe: py, cmdline: py + " app.py", environ: map[string]string{"VIRTUAL_ENV": venv}}
	// Active env, empty maps — must not mark loaded.
	st.mappedFilesByPID[41] = nil
	h := pythonEnvHint{root: venv, kind: "venv", scope: "host", discovery: "process_environ:VIRTUAL_ENV", activeForPID: 41, interpreter: py}
	_, _, envID, _ := materializePythonEnvironment(st, h, p)
	finalizePythonActiveCoverage(st, map[string]bool{envID: true})
	if st.coverage.DistributionsInActiveEnvs < 1 {
		t.Fatal("expected active env distributions")
	}
	if st.coverage.DistributionsConfirmedLoaded != 0 {
		t.Fatalf("active env must not imply loaded: %#v", st.coverage)
	}
	for _, d := range st.distByEnv[envID] {
		if asString(d["runtime_load_status"]) != "installed_not_proven_loaded" {
			t.Fatalf("%#v", d)
		}
	}
	if len(st.pendingLoadRels) != 0 {
		t.Fatalf("unexpected load rels %#v", st.pendingLoadRels)
	}
}

func TestIntegration_HostContainerSeparation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("linux overlay2/host path fixtures are not hermetic on Windows")
	}
	root := t.TempDir()
	home := filepath.Join(root, "home")
	userSite := filepath.Join(home, ".local", "lib", "python3.11", "site-packages")
	_ = os.MkdirAll(userSite, 0o755)
	writeDist(t, userSite, "usersitepkg", "1.0.0", "pip", false)

	pipx := filepath.Join(home, ".local", "share", "pipx", "venvs", "toolx")
	pipxSite := filepath.Join(pipx, "lib", "python3.11", "site-packages")
	_ = os.MkdirAll(pipxSite, 0o755)
	_ = os.WriteFile(filepath.Join(pipx, "pyvenv.cfg"), []byte("home = /usr\nversion = 3.11.0\n"), 0o644)
	writeDist(t, pipxSite, "toolx", "3.0.0", "pip", false)

	poetryRoot := filepath.Join(root, "app")
	_ = os.MkdirAll(poetryRoot, 0o755)
	_ = os.WriteFile(filepath.Join(poetryRoot, "poetry.lock"), []byte(""), 0o644)
	pVenv := filepath.Join(poetryRoot, ".venv")
	pSite := filepath.Join(pVenv, "lib", "python3.11", "site-packages")
	_ = os.MkdirAll(pSite, 0o755)
	_ = os.WriteFile(filepath.Join(pVenv, "pyvenv.cfg"), []byte("home = /usr\nversion = 3.11.2\n"), 0o644)
	pPy := filepath.Join(pVenv, "bin", "python3.11")
	_ = os.MkdirAll(filepath.Dir(pPy), 0o755)
	_ = os.WriteFile(pPy, []byte("#!/bin/sh\n"), 0o755)
	writeDist(t, pSite, "poetrydep", "1.2.3", "pip", false)

	ctrV := filepath.Join(root, "var", "lib", "docker", "overlay2", "x", "diff", "opt", "venv")
	ctrSite := filepath.Join(ctrV, "lib", "python3.11", "site-packages")
	_ = os.MkdirAll(ctrSite, 0o755)
	_ = os.WriteFile(filepath.Join(ctrV, "pyvenv.cfg"), []byte("home = /usr\nversion = 3.10.12\n"), 0o644)
	writeDist(t, ctrSite, "ctrpkg", "1.0.0", "pip", false)

	st := newPythonScanState(defaultPythonScanLimits())
	injectDpkgOwnershipIndex(st, newDpkgOwnershipIndex())
	p := procSeed{pid: 40, exe: pPy, cmdline: pPy + " main.py", cwd: poetryRoot,
		environ: map[string]string{"VIRTUAL_ENV": pVenv, "POETRY_ACTIVE": "1", "HOME": home}}
	for _, h := range []pythonEnvHint{
		{root: filepath.Join(home, ".local"), kind: "user_site", scope: "host", discovery: "fixture"},
		{root: pipx, kind: "pipx", scope: "host", discovery: "fixture"},
		{root: pVenv, kind: "poetry", scope: "host", discovery: "process_environ:VIRTUAL_ENV", activeForPID: 40, interpreter: pPy},
		{root: ctrV, kind: "venv", scope: scopeForPath(ctrV), discovery: "fixture"},
	} {
		_, _, _, _ = materializePythonEnvironment(st, h, p)
	}
	kinds := map[string]bool{}
	scopes := map[string]bool{}
	for _, e := range st.envRecords {
		kinds[asString(e["kind"])] = true
		scopes[asString(e["scope"])] = true
	}
	for _, want := range []string{"user_site", "pipx", "poetry", "venv"} {
		if !kinds[want] {
			t.Fatalf("missing kind %s in %#v", want, kinds)
		}
	}
	if !scopes["host"] || !scopes["container"] {
		t.Fatalf("host/container isolation missing scopes=%v", scopes)
	}
	var interp map[string]any
	for _, rec := range st.interpRecords {
		interp = rec
		break
	}
	if interp == nil || asString(interp["version"]) != "3.11.2" {
		t.Fatalf("exact interpreter patch version expected 3.11.2, got %#v", interp)
	}
	if asString(interp["version_source"]) != "pyvenv_cfg" {
		t.Fatalf("version_source %#v", interp["version_source"])
	}
	if asString(interp["upstream_version"]) != "3.11.2" {
		t.Fatalf("upstream_version %#v", interp["upstream_version"])
	}
}

func TestIntegration_InterpreterKeepsOSPackageRawVersion(t *testing.T) {
	root := t.TempDir()
	venv, py, _ := makeVenv(t, root, "3.10")
	_ = os.WriteFile(filepath.Join(venv, "pyvenv.cfg"), []byte("home = /usr\nversion = 3.10.12\n"), 0o644)
	st := newPythonScanState(defaultPythonScanLimits())
	idx := newDpkgOwnershipIndex()
	idx.pkgs["python3.10"] = dpkgPkgRec{
		Name: "python3.10", Arch: "arm64", Version: "3.10.12-1~22.04.10", Source: "python3.10",
	}
	idx.byPath[py] = "python3.10"
	injectDpkgOwnershipIndex(st, idx)
	p := procSeed{pid: 9, exe: py}
	id, ents := ensurePythonInterpreter(st, nil, py, p, readPyvenvCfg(filepath.Join(venv, "pyvenv.cfg")))
	if id == "" {
		t.Fatal("missing interpreter")
	}
	rec := st.interpRecords[id]
	if asString(rec["version"]) != "3.10.12" || asString(rec["upstream_version"]) != "3.10.12" {
		t.Fatalf("upstream %#v", rec)
	}
	if asString(rec["os_package_raw_version"]) != "3.10.12-1~22.04.10" {
		t.Fatalf("os raw %#v", rec["os_package_raw_version"])
	}
	want := "pkg:dpkg:python3.10:arm64:3.10.12-1~22.04.10"
	found := false
	for _, e := range ents {
		if e["entity_type"] == "relationship" && e["relationship"] == "python_interpreter_belongs_to_os_package" {
			if asString(e["target_entity_id"]) != want {
				t.Fatalf("target %#v want %s", e["target_entity_id"], want)
			}
			found = true
		}
	}
	if !found {
		t.Fatalf("missing interpreter os package rel in %#v", ents)
	}
}

func TestIntegration_RelationshipReferentialIntegrity(t *testing.T) {
	root := t.TempDir()
	venv, py, site := makeVenv(t, root, "3.11")
	writeDist(t, site, "demo", "1.0.0", "pip", false)
	meta := "/usr/lib/python3/dist-packages/mako-1.1.3.dist-info/METADATA"
	st := newPythonScanState(defaultPythonScanLimits())
	idx := newDpkgOwnershipIndex()
	pkgID := "pkg:dpkg:python3-mako:all:1.1.3+ds1-2ubuntu0.1"
	idx.pkgs["python3-mako"] = dpkgPkgRec{
		Name: "python3-mako", Arch: "all", Version: "1.1.3+ds1-2ubuntu0.1", Source: "mako",
	}
	idx.byPath[meta] = "python3-mako"
	injectDpkgOwnershipIndex(st, idx)

	p := procSeed{pid: 51, exe: py, cmdline: py + " a.py", environ: map[string]string{"VIRTUAL_ENV": venv}}
	out := []map[string]any{{
		"entity_type": "process", "entity_id": "process:51", "process_id": 51, "collection_status": "observed",
	}}
	ents, rels, envID, _ := materializePythonEnvironment(st, pythonEnvHint{
		root: venv, kind: "venv", scope: "host", discovery: "process_environ:VIRTUAL_ENV", activeForPID: 51, interpreter: py,
	}, p)
	out = append(out, ents...)
	out = append(out, rels...)
	_ = envID

	dpkgDist := baseDistRec("Mako", "mako", "1.1.3", "system", "host", "python:env:sys", meta)
	own := applyPythonDistOSOwnership(st, dpkgDist)
	out = append(out, dpkgDist)
	out = append(out, own...)

	// Package inventory entity that relationships must target.
	out = append(out, map[string]any{
		"entity_type": "package",
		"entity_id":   pkgID,
		"name":        "python3-mako",
	})

	doc := documentFromPythonRecs(t, out)
	// Also put package entity into packages module evidence (as real collector does).
	doc.Modules = append(doc.Modules, schema.ModuleResult{
		ModuleID: "packages", ModuleVersion: "1.2.0", Status: "success",
		Evidence: []schema.EvidenceRecord{
			common.Evidence("native", "packages", "observed", map[string]any{
				"entity_id": pkgID, "entity_type": "package", "name": "python3-mako",
			}, nil),
		},
	})
	sum, err := evidencefile.PayloadHash(doc)
	if err != nil {
		t.Fatal(err)
	}
	doc.Integrity = schema.IntegrityInfo{Algorithm: "SHA-256", PayloadHash: sum}
	issues := evidencefile.Validate(doc)
	for _, iss := range issues {
		if strings.Contains(iss, "missing") && strings.Contains(iss, "entity_id") {
			t.Fatalf("referential integrity failed: %v", issues)
		}
	}

	// Broken legacy target must fail validation.
	bad := documentFromPythonRecs(t, []map[string]any{
		{"entity_type": "process", "entity_id": "process:1"},
		{"entity_type": "python_distribution", "entity_id": "python:dist:x",
			"installation_origin": "os_package", "os_package_manager": "dpkg",
			"os_binary_package": "python3-mako", "os_source_package": "mako",
			"os_package_version": "1.1.3+ds1-2ubuntu0.1", "ownership_confidence": "direct"},
		rel("python_distribution_belongs_to_os_package", "python:dist:x", "package:dpkg:python3-mako", "bad"),
	})
	sum, _ = evidencefile.PayloadHash(bad)
	bad.Integrity = schema.IntegrityInfo{Algorithm: "SHA-256", PayloadHash: sum}
	badIssues := evidencefile.Validate(bad)
	found := false
	for _, iss := range badIssues {
		if strings.Contains(iss, "target_entity_id missing") && strings.Contains(iss, "package:dpkg:python3-mako") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected missing target failure, got %v", badIssues)
	}
}

func TestIntegration_SkipReasonsNormalized(t *testing.T) {
	st := newPythonScanState(defaultPythonScanLimits())
	st.skip("/missing", "path_missing_or_moved")
	st.skip("/x", "site_packages_unreadable")
	st.skip("/y", "broken_or_incomplete_metadata")
	st.skip("/z", "max_environments")
	for _, r := range []string{"not_found", "no_metadata", "scan_limit"} {
		if st.coverage.SkippedByReason[r] == 0 {
			t.Fatalf("expected reason %s in %#v", r, st.coverage.SkippedByReason)
		}
	}
	for reason := range st.coverage.SkippedByReason {
		switch reason {
		case "not_found", "permission_denied", "not_directory", "no_metadata", "inode_dedup", "scan_limit", "timeout":
		default:
			t.Fatalf("non-canonical skip reason %q", reason)
		}
	}
}

func TestFixture12_DeletedEnvPath(t *testing.T) {
	st := newPythonScanState(defaultPythonScanLimits())
	injectDpkgOwnershipIndex(st, newDpkgOwnershipIndex())
	p := procSeed{pid: 3, exe: "/missing/bin/python3.11"}
	h := pythonEnvHint{root: "/tmp/openness-does-not-exist-python-env", kind: "venv", scope: "host", discovery: "process_exe", activeForPID: 3}
	ents, rels, _, _ := materializePythonEnvironment(st, h, p)
	envs := entitiesByType(ents, "python_environment")
	if len(envs) != 1 || envs[0]["unavailable_reason"] != "not_found" {
		t.Fatalf("%#v", envs)
	}
	if len(rels) == 0 {
		t.Fatal("process should still be linked to unavailable env entity")
	}
}

func documentFromPythonRecs(t *testing.T, recs []map[string]any) *schema.Document {
	t.Helper()
	var evs []schema.EvidenceRecord
	for _, rec := range recs {
		evs = append(evs, common.Evidence("native", "language_deps", "observed", rec, nil))
	}
	return &schema.Document{
		SchemaVersion: schema.SchemaVersion,
		Collector:     schema.CollectorInfo{Name: schema.CollectorName, Version: schema.CollectorVersion},
		Collection: schema.CollectionInfo{
			CollectionID: "fixture-refint", StartedAt: schema.NowUTC(), CompletedAt: schema.NowUTC(),
			ExecutionMode: "fixture", PrivilegeLevel: "user", Status: "complete",
		},
		Asset:   schema.AssetInfo{Hostname: "fixture", Platform: "linux"},
		Modules: []schema.ModuleResult{{ModuleID: "language_deps", ModuleVersion: "1.1.3", Status: "success", Evidence: evs}},
	}
}
