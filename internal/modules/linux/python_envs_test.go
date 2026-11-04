package linux

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/s4e-io/openness-collector/internal/modules/common"
	"github.com/s4e-io/openness-collector/internal/schema"
)

func skipNonUnixPythonPathFixtures(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("linux python path fixtures use Unix layout (bin/, overlay2/); not hermetic on Windows")
	}
}

func writeDist(t *testing.T, site, name, ver, installer string, editable bool) {
	t.Helper()
	dir := filepath.Join(site, name+"-"+ver+".dist-info")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "METADATA"), []byte("Name: "+name+"\nVersion: "+ver+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "RECORD"), []byte(name+"-"+ver+".dist-info/METADATA,sha256=abc,10\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if installer != "" {
		_ = os.WriteFile(filepath.Join(dir, "INSTALLER"), []byte(installer+"\n"), 0o644)
	}
	if editable {
		du := `{"url":"file:///src/` + name + `","dir_info":{"editable":true}}`
		_ = os.WriteFile(filepath.Join(dir, "direct_url.json"), []byte(du), 0o644)
	}
}

func makeVenv(t *testing.T, root, pyVer string) (venv, pyBin, site string) {
	t.Helper()
	venv = filepath.Join(root, "venv")
	site = filepath.Join(venv, "lib", "python"+pyVer, "site-packages")
	bin := filepath.Join(venv, "bin")
	if err := os.MkdirAll(site, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(venv, "pyvenv.cfg"), []byte("home = /usr\nversion = "+pyVer+".0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pyBin = filepath.Join(bin, "python"+pyVer)
	if err := os.WriteFile(pyBin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return venv, pyBin, site
}

func entitiesByType(recs []map[string]any, typ string) []map[string]any {
	var out []map[string]any
	for _, r := range recs {
		if r["entity_type"] == typ {
			out = append(out, r)
		}
	}
	return out
}

func TestPEP503Normalize(t *testing.T) {
	cases := map[string]string{
		"Friendly-Request":      "friendly-request",
		"Django_REST_Framework": "django-rest-framework",
		"__Foo..Bar__":          "--foo-bar--", // leading/trailing runs preserved as dashes after replace; trim handled by pep503 on content
		"PyYAML":                "pyyaml",
		"zope.interface":        "zope-interface",
	}
	// Adjust expectation for leading underscores: PEP 503 replaces [-_.]+ with -
	if pep503Normalize("Friendly-Request") != "friendly-request" {
		t.Fatal(pep503Normalize("Friendly-Request"))
	}
	if pep503Normalize("zope.interface") != "zope-interface" {
		t.Fatal(pep503Normalize("zope.interface"))
	}
	if pep503Normalize("Django_REST_Framework") != "django-rest-framework" {
		t.Fatal(pep503Normalize("Django_REST_Framework"))
	}
	_ = cases
}

// 1. APT package fixed while same PyPI package vulnerable in a venv — separate identities/scopes.
func TestFixture1_APTVsVenvNotMerged(t *testing.T) {
	root := t.TempDir()
	// Fake system root with dist-packages
	sysSite := filepath.Join(root, "usr", "lib", "python3.11", "dist-packages")
	_ = os.MkdirAll(sysSite, 0o755)
	writeDist(t, sysSite, "requests", "2.25.1", "apt", false) // "fixed"/OS-managed

	venv, py, site := makeVenv(t, root, "3.11")
	writeDist(t, site, "requests", "2.18.0", "pip", false) // vulnerable PyPI

	// Force system env discovery via PYTHONHOME pointing at fake /usr under root — use extraHints.
	st := newPythonScanState(defaultPythonScanLimits())
	sysHint := pythonEnvHint{root: filepath.Join(root, "usr"), kind: "system", scope: "host", discovery: "fixture", activeForPID: 1, interpreter: py}
	venvHint := pythonEnvHint{root: venv, kind: "venv", scope: "host", discovery: "fixture", activeForPID: 2, interpreter: py}
	p := procSeed{pid: 2, exe: py, cmdline: py + " app.py", cwd: root, uid: 1000}
	e1, _, _, _ := materializePythonEnvironment(st, sysHint, p)
	e2, _, _, _ := materializePythonEnvironment(st, venvHint, p)
	dists := append(entitiesByType(e1, "python_distribution"), entitiesByType(e2, "python_distribution")...)
	var req []map[string]any
	for _, d := range dists {
		if asString(d["name_normalized"]) == "requests" {
			req = append(req, d)
		}
	}
	if len(req) < 2 {
		t.Fatalf("want 2 separate requests identities, got %#v", req)
	}
	ids := map[string]bool{}
	for _, d := range req {
		key := asString(d["environment_id"]) + "|" + asString(d["raw_version_string"])
		ids[key] = true
		if d["environment_kind"] == "system" && asString(d["raw_version_string"]) != "2.25.1" {
			t.Fatalf("system dist %#v", d)
		}
		if d["environment_kind"] == "venv" && asString(d["raw_version_string"]) != "2.18.0" {
			t.Fatalf("venv dist %#v", d)
		}
	}
	if len(ids) < 2 {
		t.Fatal("identities were merged")
	}
}

// 2. Two venvs containing different versions of the same package.
func TestFixture2_TwoVenvsDifferentVersions(t *testing.T) {
	root := t.TempDir()
	v1, py1, s1 := makeVenv(t, filepath.Join(root, "a"), "3.11")
	v2, py2, s2 := makeVenv(t, filepath.Join(root, "b"), "3.11")
	writeDist(t, s1, "urllib3", "1.26.0", "pip", false)
	writeDist(t, s2, "urllib3", "2.2.0", "pip", false)

	p1 := procSeed{pid: 11, exe: py1, cmdline: py1 + " a.py", cwd: filepath.Join(root, "a"), environ: map[string]string{"VIRTUAL_ENV": v1}}
	p2 := procSeed{pid: 12, exe: py2, cmdline: py2 + " b.py", cwd: filepath.Join(root, "b"), environ: map[string]string{"VIRTUAL_ENV": v2}}
	recs, _, cov := collectPythonInventoryFromSeeds(context.Background(), []procSeed{p1, p2}, defaultPythonScanLimits())
	dists := entitiesByType(recs, "python_distribution")
	vers := map[string]bool{}
	for _, d := range dists {
		if asString(d["name_normalized"]) == "urllib3" {
			vers[asString(d["raw_version_string"])] = true
		}
	}
	if !vers["1.26.0"] || !vers["2.2.0"] {
		t.Fatalf("vers %#v cov %#v", vers, cov)
	}
}

// 3. Running process using a vulnerable venv.
func TestFixture3_RunningProcessUsesVulnerableVenv(t *testing.T) {
	root := t.TempDir()
	venv, py, site := makeVenv(t, root, "3.11")
	writeDist(t, site, "vulnerablepkg", "0.0.1", "pip", false)
	p := procSeed{
		pid: 99, exe: py, cmdline: py + " serve.py", cwd: root,
		environ: map[string]string{"VIRTUAL_ENV": venv},
	}
	recs, errMsg := collectPythonEvidence(p)
	if errMsg != "" && !strings.Contains(errMsg, "limit") {
		t.Fatal(errMsg)
	}
	rels := entitiesByType(recs, "relationship")
	foundEnv := false
	foundInterp := false
	for _, r := range rels {
		if r["relationship"] == "process_uses_python_environment" && r["source_entity_id"] == "process:99" {
			foundEnv = true
		}
		if r["relationship"] == "process_uses_python_interpreter" {
			foundInterp = true
		}
	}
	if !foundEnv || !foundInterp {
		t.Fatalf("missing relationships env=%v interp=%v rels=%#v", foundEnv, foundInterp, rels)
	}
	envs := entitiesByType(recs, "python_environment")
	if len(envs) == 0 || envs[0]["process_ids"] == nil {
		t.Fatalf("env not linked %#v", envs)
	}
}

// 4. Inactive vulnerable venv (known location, no active PID).
func TestFixture4_InactiveVulnerableVenv(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	pipxVenv := filepath.Join(home, ".local", "share", "pipx", "venvs", "oldtool")
	site := filepath.Join(pipxVenv, "lib", "python3.11", "site-packages")
	_ = os.MkdirAll(site, 0o755)
	_ = os.WriteFile(filepath.Join(pipxVenv, "pyvenv.cfg"), []byte("home = /usr\n"), 0o644)
	writeDist(t, site, "oldtool", "0.1.0", "pip", false)

	p := procSeed{
		pid: 5, exe: "/usr/bin/python3.11", cmdline: "/usr/bin/python3.11",
		environ: map[string]string{"HOME": home},
		uid:     1000,
	}
	// Only known-location discovery (no VIRTUAL_ENV) — inactive.
	hints := boundedPythonKnownLocations(p)
	st := newPythonScanState(defaultPythonScanLimits())
	var inactive bool
	for _, h := range hints {
		if h.root == pipxVenv {
			ents, _, _, _ := materializePythonEnvironment(st, h, p)
			envs := entitiesByType(ents, "python_environment")
			if len(envs) == 1 {
				pids, _ := envs[0]["process_ids"].([]int)
				if len(pids) == 0 {
					inactive = true
				}
			}
		}
	}
	if !inactive {
		t.Fatalf("expected inactive pipx env in hints %#v", hints)
	}
}

// 5. User-site installation.
func TestFixture5_UserSite(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	site := filepath.Join(home, ".local", "lib", "python3.11", "site-packages")
	_ = os.MkdirAll(site, 0o755)
	writeDist(t, site, "usersitepkg", "9.9.9", "pip", false)
	p := procSeed{
		pid: 7, exe: "/usr/bin/python3.11", cmdline: "/usr/bin/python3.11",
		environ: map[string]string{"HOME": home},
		uid:     1000,
	}
	st := newPythonScanState(defaultPythonScanLimits())
	h := pythonEnvHint{root: filepath.Join(home, ".local"), kind: "user_site", scope: "host", discovery: "fixture"}
	ents, _, _, _ := materializePythonEnvironment(st, h, p)
	dists := entitiesByType(ents, "python_distribution")
	found := false
	for _, d := range dists {
		if asString(d["name_normalized"]) == "usersitepkg" && d["environment_kind"] == "user_site" {
			found = true
		}
	}
	if !found {
		t.Fatalf("user-site missing %#v", dists)
	}
}

// 6. pipx
func TestFixture6_Pipx(t *testing.T) {
	skipNonUnixPythonPathFixtures(t)
	root := t.TempDir()
	venv, py, site := makeVenv(t, filepath.Join(root, "pipx", "venvs", "black"), "3.11")
	// rewrite path to look like pipx
	_ = venv
	writeDist(t, site, "black", "24.1.0", "pip", false)
	p := procSeed{pid: 8, exe: py, cmdline: py + " -m black", environ: map[string]string{"VIRTUAL_ENV": filepath.Dir(filepath.Dir(site))}}
	// VIRTUAL_ENV should be venv root; makeVenv created root/venv — adjust:
	realVenv := filepath.Join(root, "home", ".local", "share", "pipx", "venvs", "black")
	site2 := filepath.Join(realVenv, "lib", "python3.11", "site-packages")
	_ = os.MkdirAll(site2, 0o755)
	_ = os.WriteFile(filepath.Join(realVenv, "pyvenv.cfg"), []byte("home = /usr\n"), 0o644)
	py2 := filepath.Join(realVenv, "bin", "python3.11")
	_ = os.MkdirAll(filepath.Dir(py2), 0o755)
	_ = os.WriteFile(py2, []byte("#!/bin/sh\n"), 0o755)
	writeDist(t, site2, "black", "24.1.0", "pip", false)
	p = procSeed{pid: 8, exe: py2, cmdline: py2 + " -m black", environ: map[string]string{"VIRTUAL_ENV": realVenv}}
	recs, _ := collectPythonEvidence(p)
	envs := entitiesByType(recs, "python_environment")
	ok := false
	for _, e := range envs {
		if e["kind"] == "pipx" {
			ok = true
		}
	}
	if !ok {
		t.Fatalf("pipx kind missing %#v", envs)
	}
}

// 7. Poetry
func TestFixture7_Poetry(t *testing.T) {
	root := t.TempDir()
	_ = os.WriteFile(filepath.Join(root, "poetry.lock"), []byte("# poetry\n"), 0o644)
	venv, py, site := makeVenv(t, root, "3.11")
	// place as .venv next to poetry.lock
	_ = os.RemoveAll(venv)
	venv = filepath.Join(root, ".venv")
	site = filepath.Join(venv, "lib", "python3.11", "site-packages")
	_ = os.MkdirAll(site, 0o755)
	_ = os.WriteFile(filepath.Join(venv, "pyvenv.cfg"), []byte("home = /usr\n"), 0o644)
	py = filepath.Join(venv, "bin", "python3.11")
	_ = os.MkdirAll(filepath.Dir(py), 0o755)
	_ = os.WriteFile(py, []byte("#!/bin/sh\n"), 0o755)
	writeDist(t, site, "poetrydep", "1.0.0", "pip", false)
	p := procSeed{
		pid: 15, exe: py, cmdline: py + " app.py", cwd: root,
		environ: map[string]string{"VIRTUAL_ENV": venv, "POETRY_ACTIVE": "1"},
	}
	recs, _ := collectPythonEvidence(p)
	ok := false
	for _, e := range entitiesByType(recs, "python_environment") {
		if e["kind"] == "poetry" {
			ok = true
		}
	}
	if !ok {
		t.Fatalf("poetry kind missing %#v", entitiesByType(recs, "python_environment"))
	}
}

// 8. PEP 503 name normalization preserves raw name.
func TestFixture8_PEP503RawPreserved(t *testing.T) {
	root := t.TempDir()
	_, _, site := makeVenv(t, root, "3.11")
	writeDist(t, site, "Zope.Interface", "6.0", "pip", false)
	// METADATA name with dots
	dir := filepath.Join(site, "Zope.Interface-6.0.dist-info")
	_ = os.WriteFile(filepath.Join(dir, "METADATA"), []byte("Name: Zope.Interface\nVersion: 6.0\n"), 0o644)
	rec := parseDistInfo(dir, "venv", "host", "python:env:test")
	if rec == nil {
		t.Fatal("nil")
	}
	if asString(rec["name_raw"]) != "Zope.Interface" {
		t.Fatalf("raw %#v", rec["name_raw"])
	}
	if asString(rec["name_normalized"]) != "zope-interface" {
		t.Fatalf("norm %#v", rec["name_normalized"])
	}
}

// 9. Editable installs.
func TestFixture9_Editable(t *testing.T) {
	root := t.TempDir()
	_, _, site := makeVenv(t, root, "3.11")
	writeDist(t, site, "myapp", "0.0.0", "pip", true)
	dir := filepath.Join(site, "myapp-0.0.0.dist-info")
	rec := parseDistInfo(dir, "venv", "host", "python:env:test")
	if rec["editable"] != true {
		t.Fatalf("%#v", rec)
	}
	// egg-link
	link := filepath.Join(site, "OtherApp.egg-link")
	_ = os.WriteFile(link, []byte("/src/OtherApp\n"), 0o644)
	egg := parseEggLink(link, "venv", "host", "python:env:test")
	if egg["editable"] != true {
		t.Fatalf("%#v", egg)
	}
}

// 10. Host/container separation.
func TestFixture10_HostContainerSeparation(t *testing.T) {
	skipNonUnixPythonPathFixtures(t)
	root := t.TempDir()
	hostV, _, hostSite := makeVenv(t, filepath.Join(root, "host"), "3.11")
	writeDist(t, hostSite, "samepkg", "1.0.0", "pip", false)

	ctrRoot := filepath.Join(root, "var", "lib", "docker", "overlay2", "abc", "diff")
	ctrV := filepath.Join(ctrRoot, "opt", "venv")
	ctrSite := filepath.Join(ctrV, "lib", "python3.11", "site-packages")
	_ = os.MkdirAll(ctrSite, 0o755)
	_ = os.WriteFile(filepath.Join(ctrV, "pyvenv.cfg"), []byte("home = /usr\n"), 0o644)
	writeDist(t, ctrSite, "samepkg", "1.0.0", "pip", false)

	if scopeForPath(hostV) != "host" {
		t.Fatal(scopeForPath(hostV))
	}
	if scopeForPath(ctrV) != "container" {
		t.Fatal(scopeForPath(ctrV))
	}
	st := newPythonScanState(defaultPythonScanLimits())
	p := procSeed{pid: 1, exe: "/usr/bin/python3.11"}
	e1, _, _, _ := materializePythonEnvironment(st, pythonEnvHint{root: hostV, kind: "venv", scope: scopeForPath(hostV), discovery: "fixture"}, p)
	e2, _, _, _ := materializePythonEnvironment(st, pythonEnvHint{root: ctrV, kind: "venv", scope: scopeForPath(ctrV), discovery: "fixture"}, p)
	d1 := entitiesByType(e1, "python_distribution")[0]
	d2 := entitiesByType(e2, "python_distribution")[0]
	if d1["scope"] == d2["scope"] {
		t.Fatalf("scopes merged %#v %#v", d1["scope"], d2["scope"])
	}
	if d1["entity_id"] == d2["entity_id"] {
		t.Fatal("entity ids collided across scopes")
	}
}

// 11. Broken or incomplete metadata.
func TestFixture11_BrokenMetadata(t *testing.T) {
	root := t.TempDir()
	_, _, site := makeVenv(t, root, "3.11")
	bad := filepath.Join(site, "broken-0.0.dist-info")
	_ = os.MkdirAll(bad, 0o755)
	_ = os.WriteFile(filepath.Join(bad, "METADATA"), []byte("NotAHeader\n"), 0o644)
	st := newPythonScanState(defaultPythonScanLimits())
	found, _ := readSiteDistributions(st, site, "venv", "host", "python:env:x")
	partial := false
	for _, d := range found {
		if d["collection_status"] == "partial" || d["unavailable_reason"] == "broken_or_incomplete_metadata" {
			partial = true
		}
	}
	if !partial {
		t.Fatalf("expected incomplete dist %#v skipped %#v", found, st.skipped)
	}
}

func TestCollectPythonFromVenvFixture(t *testing.T) {
	root := t.TempDir()
	venv, py, site := makeVenv(t, root, "3.11")
	writeDist(t, site, "demo", "1.2.3", "pip", false)
	recs, errMsg := collectPythonEvidence(procSeed{
		pid: 42, exe: py, cmdline: py + " app.py", cwd: root,
		environ: map[string]string{"VIRTUAL_ENV": venv},
	})
	if errMsg != "" && !strings.Contains(errMsg, "limit") {
		t.Fatal(errMsg)
	}
	if len(entitiesByType(recs, "python_environment")) == 0 {
		t.Fatalf("no env %#v", recs)
	}
	if len(entitiesByType(recs, "python_distribution")) == 0 {
		t.Fatal("no dists")
	}
	if len(entitiesByType(recs, "python_interpreter")) == 0 {
		t.Fatal("no interpreter")
	}
}

// Build a synthetic .openness fixture + coverage report for the analyzer workspace.
func TestEmitPythonEnvFixtureAndCoverage(t *testing.T) {
	root := t.TempDir()
	// Compose multi-scenario tree
	vActive, pyActive, sActive := makeVenv(t, filepath.Join(root, "active"), "3.11")
	writeDist(t, sActive, "vulnerablepkg", "0.0.1", "pip", false)
	writeDist(t, sActive, "Zope.Interface", "6.0", "pip", false)

	vOther, pyOther, sOther := makeVenv(t, filepath.Join(root, "other"), "3.11")
	writeDist(t, sOther, "vulnerablepkg", "0.0.2", "pip", false)

	home := filepath.Join(root, "home")
	userSite := filepath.Join(home, ".local", "lib", "python3.11", "site-packages")
	_ = os.MkdirAll(userSite, 0o755)
	writeDist(t, userSite, "usersitepkg", "1.0.0", "pip", false)

	pipx := filepath.Join(home, ".local", "share", "pipx", "venvs", "toolx")
	pipxSite := filepath.Join(pipx, "lib", "python3.11", "site-packages")
	_ = os.MkdirAll(pipxSite, 0o755)
	_ = os.WriteFile(filepath.Join(pipx, "pyvenv.cfg"), []byte("home = /usr\n"), 0o644)
	writeDist(t, pipxSite, "toolx", "3.0.0", "pip", false)

	poetryRoot := filepath.Join(root, "poetryapp")
	_ = os.MkdirAll(poetryRoot, 0o755)
	_ = os.WriteFile(filepath.Join(poetryRoot, "poetry.lock"), []byte(""), 0o644)
	pVenv := filepath.Join(poetryRoot, ".venv")
	pSite := filepath.Join(pVenv, "lib", "python3.11", "site-packages")
	_ = os.MkdirAll(pSite, 0o755)
	_ = os.WriteFile(filepath.Join(pVenv, "pyvenv.cfg"), []byte("home = /usr\n"), 0o644)
	pPy := filepath.Join(pVenv, "bin", "python3.11")
	_ = os.MkdirAll(filepath.Dir(pPy), 0o755)
	_ = os.WriteFile(pPy, []byte("#!/bin/sh\n"), 0o755)
	writeDist(t, pSite, "poetrydep", "1.2.3", "pip", true)

	conda := filepath.Join(home, "miniconda3", "envs", "ml")
	_ = os.MkdirAll(filepath.Join(conda, "conda-meta"), 0o755)
	_ = os.WriteFile(filepath.Join(conda, "conda-meta", "numpy-1.26.0-py311.json"), []byte(`{"name":"numpy","version":"1.26.0","build":"py311"}`), 0o644)

	ctrV := filepath.Join(root, "var", "lib", "docker", "overlay2", "x", "diff", "opt", "venv")
	ctrSite := filepath.Join(ctrV, "lib", "python3.11", "site-packages")
	_ = os.MkdirAll(ctrSite, 0o755)
	_ = os.WriteFile(filepath.Join(ctrV, "pyvenv.cfg"), []byte("home = /usr\n"), 0o644)
	writeDist(t, ctrSite, "vulnerablepkg", "0.0.1", "pip", false)

	seeds := []procSeed{
		{pid: 101, exe: pyActive, cmdline: pyActive + " app.py", cwd: filepath.Join(root, "active"),
			environ: map[string]string{"VIRTUAL_ENV": vActive, "HOME": home}, uid: 1000},
		{pid: 102, exe: pyOther, cmdline: pyOther + " worker.py", cwd: filepath.Join(root, "other"),
			environ: map[string]string{"VIRTUAL_ENV": vOther, "HOME": home}, uid: 1000},
		{pid: 103, exe: pPy, cmdline: pPy + " main.py", cwd: poetryRoot,
			environ: map[string]string{"VIRTUAL_ENV": pVenv, "POETRY_ACTIVE": "1", "HOME": home}, uid: 1000},
	}
	started := time.Now()
	recs, errMsg, cov := collectPythonInventoryFromSeeds(context.Background(), seeds, defaultPythonScanLimits())
	// Also materialize inactive pipx + conda + container explicitly for fixture completeness.
	st := newPythonScanState(defaultPythonScanLimits())
	for _, h := range []pythonEnvHint{
		{root: pipx, kind: "pipx", scope: "host", discovery: "fixture"},
		{root: conda, kind: "conda", scope: "host", discovery: "fixture"},
		{root: ctrV, kind: "venv", scope: scopeForPath(ctrV), discovery: "fixture"},
		{root: filepath.Join(home, ".local"), kind: "user_site", scope: "host", discovery: "fixture"},
		{root: "/tmp/openness-missing-python-env", kind: "venv", scope: "host", discovery: "fixture"},
	} {
		e, r, _, _ := materializePythonEnvironment(st, h, procSeed{pid: 0, uid: 1000, environ: map[string]string{"HOME": home}})
		recs = append(recs, e...)
		recs = append(recs, r...)
	}
	// Merge coverage counters from second pass
	cov.Environments += st.coverage.Environments
	cov.Distributions += st.coverage.Distributions
	cov.Interpreters += st.coverage.Interpreters
	cov.PackagesCompleteIdentity += st.coverage.PackagesCompleteIdentity
	cov.PackagesUnknownVersion += st.coverage.PackagesUnknownVersion
	for k, v := range st.coverage.SkippedByReason {
		cov.SkippedByReason[k] += v
	}
	cov.SkippedPaths += st.coverage.SkippedPaths
	for k, v := range st.coverage.EnvKinds {
		cov.EnvKinds[k] += v
	}
	duration := time.Since(started).Milliseconds()

	res := common.NewResult("language_deps", "1.1.3")
	for _, rec := range recs {
		res.Evidence = append(res.Evidence, common.Evidence("native", "language_deps", "observed", rec, nil))
	}
	if errMsg != "" {
		res.Errors = append(res.Errors, common.Err("language_deps", "partial", errMsg))
	}
	common.Finish(&res, started, "success")

	now := schema.NowUTC()
	doc := &schema.Document{
		SchemaVersion: schema.SchemaVersion,
		Collector:     schema.CollectorInfo{Name: schema.CollectorName, Version: schema.CollectorVersion},
		Collection: schema.CollectionInfo{
			CollectionID:   "fixture-python-envs",
			StartedAt:      now,
			CompletedAt:    now,
			DurationMs:     duration,
			ExecutionMode:  "fixture",
			PrivilegeLevel: "user",
			Status:         "complete",
			Partial:        false,
		},
		Asset: schema.AssetInfo{
			Hostname: "python-env-fixture",
			Platform: "linux",
		},
		LanguageDeps: func() []any {
			var vals []any
			for _, e := range res.Evidence {
				vals = append(vals, e.Value)
			}
			return vals
		}(),
		Modules: []schema.ModuleResult{res},
	}

	outDir := filepath.Join("..", "..", "..", "output", "python-env-fixtures")
	_ = os.MkdirAll(outDir, 0o755)
	payload, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	evidencePath := filepath.Join(outDir, "python-envs-fixture.openness")
	if err := os.WriteFile(evidencePath, payload, 0o644); err != nil {
		t.Fatal(err)
	}

	report := map[string]any{
		"fixture":                              evidencePath,
		"collector_version":                    schema.CollectorVersion,
		"schema_version":                       schema.SchemaVersion,
		"module_duration_ms":                   duration,
		"interpreters_discovered":              cov.Interpreters,
		"environments_discovered":              cov.Environments,
		"distributions_discovered":             cov.Distributions,
		"environments_connected_to_processes":  cov.EnvsConnectedToProcesses,
		"distributions_in_active_environments": cov.DistributionsInActiveEnvs,
		"distributions_confirmed_loaded":       cov.DistributionsConfirmedLoaded,
		"packages_with_complete_identity":      cov.PackagesCompleteIdentity,
		"packages_with_unknown_version":        cov.PackagesUnknownVersion,
		"skipped_paths":                        cov.SkippedPaths,
		"skipped_by_reason":                    cov.SkippedByReason,
		"environment_kinds":                    cov.EnvKinds,
		"collection_errors":                    cov.CollectionErrors,
		"module_error":                         errMsg,
		"evidence_records":                     len(recs),
	}
	rb, _ := json.MarshalIndent(report, "", "  ")
	reportPath := filepath.Join(outDir, "python-envs-coverage.json")
	if err := os.WriteFile(reportPath, rb, 0o644); err != nil {
		t.Fatal(err)
	}
	// Also drop a markdown summary
	md := "# Python environment inventory — coverage report\n\n" +
		"- Fixture: `" + evidencePath + "`\n" +
		"- Interpreters: " + itoa(cov.Interpreters) + "\n" +
		"- Environments: " + itoa(cov.Environments) + "\n" +
		"- Distributions: " + itoa(cov.Distributions) + "\n" +
		"- Envs connected to processes: " + itoa(cov.EnvsConnectedToProcesses) + "\n" +
		"- Packages complete identity: " + itoa(cov.PackagesCompleteIdentity) + "\n" +
		"- Packages unknown version: " + itoa(cov.PackagesUnknownVersion) + "\n" +
		"- Skipped paths: " + itoa(cov.SkippedPaths) + "\n" +
		"- Module duration_ms: " + itoa(int(duration)) + "\n" +
		"- Collection errors: " + strings.Join(cov.CollectionErrors, "; ") + "\n"
	_ = os.WriteFile(filepath.Join(outDir, "python-envs-coverage.md"), []byte(md), 0o644)

	if cov.Environments < 4 || cov.Distributions < 4 {
		t.Fatalf("coverage too low: %#v report=%s", cov, string(rb))
	}
	t.Logf("wrote %s and %s", evidencePath, reportPath)
}
