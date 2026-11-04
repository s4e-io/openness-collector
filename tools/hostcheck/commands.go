package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/s4e-io/openness-collector/internal/cli"
	"github.com/s4e-io/openness-collector/internal/evidencefile"
	"github.com/s4e-io/openness-collector/internal/schema"
	"github.com/s4e-io/openness-collector/internal/version"
)

// commands is every openness subcommand. A command that shows up in
// `openness --help` but not here fails the run, so new commands get a test.
var commands = []string{"collect", "validate", "inspect", "upload", "login", "logout", "whoami", "version", "modules", "self-test"}

// goodToken passes the stub check and the 32-character minimum of the client.
const goodToken = "hostcheck-token-0123456789abcdefghijklmnop"

type cmdResult struct {
	stdout, stderr string
	code           int
	err            error
	elapsed        time.Duration
}

func (r cmdResult) String() string {
	return fmt.Sprintf("exit=%d stdout=%q stderr=%q", r.code, clip(r.stdout, 300), clip(r.stderr, 300))
}

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

func (c *checker) configDir() string { return filepath.Join(c.opts.work, "config") }

// env is the child environment: no token variables leak in from the caller,
// and saved credentials go to a private directory under the work dir.
func (c *checker) env(extra ...string) []string {
	drop := map[string]bool{"OPENNESS_API_KEY": true, "S4E_API_TOKEN": true, "OPENNESS_CONFIG_DIR": true, "HOSTCHECK_KEY": true}
	var out []string
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if drop[strings.ToUpper(k)] {
			continue
		}
		out = append(out, kv)
	}
	out = append(out, "OPENNESS_CONFIG_DIR="+c.configDir())
	return append(out, extra...)
}

func (c *checker) run(extraEnv []string, args ...string) cmdResult {
	limit := time.Duration(c.opts.timeout+120) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	cmd := exec.CommandContext(ctx, c.opts.bin, args...)
	cmd.Env = c.env(extraEnv...)
	cmd.Dir = c.opts.work
	cmd.Stdin = strings.NewReader("")
	var so, se bytes.Buffer
	cmd.Stdout = &so
	cmd.Stderr = &se
	start := time.Now()
	err := cmd.Run()
	res := cmdResult{stdout: so.String(), stderr: se.String(), err: err, elapsed: time.Since(start)}
	if cmd.ProcessState != nil {
		res.code = cmd.ProcessState.ExitCode()
	} else {
		res.code = -1
	}
	fmt.Printf("---- %s %s (%s, exit %d)\n", cli.BinaryName, strings.Join(args, " "), res.elapsed.Round(time.Millisecond), res.code)
	return res
}

func (c *checker) path(name string) string { return filepath.Join(c.opts.work, name) }

func (c *checker) runCommands() {
	c.checkHelp()
	c.checkVersion()
	c.checkModules()
	c.checkSelfTest()

	full := c.path("full.openness")
	doc := c.checkFullCollect(full)
	if doc != nil {
		c.checkValidate(full)
		c.checkInspect(full, doc)
		c.checkDocument(doc)
		c.hostTruth(doc)
		c.checkUpload(full, doc)
	}
	c.checkCollectVariants()
	c.checkConfigFile()
	c.checkCollectUpload()
	c.checkBadArgs()
	c.checkAuth()
	c.platformExtras()
}

func (c *checker) checkHelp() {
	r := c.run(nil, "--help")
	if !c.check("help/root", r.code == 0 && strings.Contains(r.stdout, cli.BinaryName+" [command]"), "%s", r) {
		return
	}
	listed := map[string]bool{}
	inCmds := false
	for _, line := range strings.Split(r.stdout, "\n") {
		if strings.HasPrefix(line, "Available Commands:") {
			inCmds = true
			continue
		}
		if inCmds {
			f := strings.Fields(line)
			if len(f) == 0 {
				break
			}
			if f[0] != "help" && f[0] != "completion" {
				listed[f[0]] = true
			}
		}
	}
	known := map[string]bool{}
	for _, cmd := range commands {
		known[cmd] = true
	}
	missing := setDiff(known, listed)
	extra := setDiff(listed, known)
	c.check("help/command-list", len(missing) == 0 && len(extra) == 0,
		"listed=%d missing=%v untested=%v", len(listed), missing, extra)
	for _, cmd := range commands {
		h := c.run(nil, cmd, "--help")
		c.check("help/"+cmd, h.code == 0 && strings.Contains(h.stdout, "Usage:"), "exit=%d", h.code)
	}
}

func (c *checker) checkVersion() {
	r := c.run(nil, "version")
	want := fmt.Sprintf("%s %s schema=%s", cli.BinaryName, version.SemVer(), schema.SchemaVersion)
	c.check("version", r.code == 0 && strings.TrimSpace(r.stdout) == want, "got %q want %q", strings.TrimSpace(r.stdout), want)
}

func (c *checker) checkModules() {
	r := c.run(nil, "modules")
	if !c.check("modules/exit", r.code == 0, "%s", r) {
		return
	}
	listed := map[string]bool{}
	re := regexp.MustCompile(`^(\S+) (\S+) platforms=(\S+)$`)
	bad := 0
	for _, line := range strings.Split(strings.TrimSpace(r.stdout), "\n") {
		m := re.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			bad++
			continue
		}
		listed[m[1]] = true
		if !strings.Contains(m[3], runtime.GOOS) {
			bad++
		}
	}
	want := map[string]bool{}
	for _, id := range expectedModules {
		want[id] = true
	}
	missing := setDiff(want, listed)
	extra := setDiff(listed, want)
	c.check("modules/list", len(missing) == 0 && len(extra) == 0 && bad == 0,
		"listed=%d missing=%v unexpected=%v malformed=%d", len(listed), missing, extra, bad)
}

func (c *checker) checkSelfTest() {
	r := c.run(nil, "self-test")
	ok := r.code == 0 && strings.Contains(r.stdout, "self-test OK platform="+runtime.GOOS)
	c.check("self-test", ok, "%s", r)
}

func (c *checker) load(path string) (*schema.Document, error) {
	return evidencefile.Load(path)
}

func (c *checker) checkFullCollect(out string) *schema.Document {
	r := c.run(nil, "collect",
		"--output", out,
		"--timeout", fmt.Sprint(c.opts.timeout),
		"--module-timeout", fmt.Sprint(c.opts.moduleTimeout),
		"--build-id", "hostcheck-full",
		"--log-level", "debug",
	)
	if !c.check("collect/full", r.code == 0 && strings.Contains(r.stderr, "wrote "), "%s", r) {
		return nil
	}
	doc, err := c.load(out)
	if !c.check("collect/full-load", err == nil, "load %s: %v", out, err) {
		return nil
	}
	c.note("collect took %s, status=%s, privilege=%s", r.elapsed.Round(time.Second), doc.Collection.Status, doc.Collection.PrivilegeLevel)
	for _, m := range doc.Modules {
		msgs := []string{}
		for _, e := range m.Errors {
			msgs = append(msgs, e.Message)
		}
		c.note("module %-24s %-18s records=%-5d %dms %s", m.ModuleID, m.Status, m.Records, m.DurationMs, clip(strings.Join(msgs, "; "), 160))
	}
	return doc
}

func (c *checker) checkValidate(full string) {
	r := c.run(nil, "validate", full)
	c.check("validate/ok", r.code == 0 && strings.TrimSpace(r.stdout) == "OK", "%s", r)

	// A changed byte in the payload must break the integrity hash.
	raw, err := os.ReadFile(full)
	if err != nil {
		c.check("validate/tampered", false, "read: %v", err)
		return
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		c.check("validate/tampered", false, "json: %v", err)
		return
	}
	asMap(m["asset"])["hostname"] = "tampered-by-hostcheck"
	b, _ := json.Marshal(m)
	tampered := c.path("tampered.openness")
	_ = os.WriteFile(tampered, b, 0o600)
	t := c.run(nil, "validate", tampered)
	c.check("validate/tampered", t.code != 0 && strings.Contains(t.stdout, "FAIL:"), "%s", t)

	n := c.run(nil, "validate", c.path("does-not-exist.openness"))
	c.check("validate/missing-file", n.code != 0, "%s", n)
	a := c.run(nil, "validate")
	c.check("validate/no-arg", a.code != 0, "exit=%d", a.code)
}

func (c *checker) checkInspect(full string, doc *schema.Document) {
	r := c.run(nil, "inspect", full)
	if !c.check("inspect/exit", r.code == 0, "%s", r) {
		return
	}
	var s map[string]any
	if err := json.Unmarshal([]byte(r.stdout), &s); err != nil {
		c.check("inspect/json", false, "%v", err)
		return
	}
	type pair struct {
		key  string
		want string
	}
	pairs := []pair{
		{"schema_version", doc.SchemaVersion},
		{"hostname", doc.Asset.Hostname},
		{"platform", doc.Asset.Platform},
		{"privilege_level", doc.Collection.PrivilegeLevel},
		{"status", doc.Collection.Status},
		{"modules", fmt.Sprint(len(doc.Modules))},
		{"packages", fmt.Sprint(len(doc.Packages))},
		{"applications", fmt.Sprint(len(doc.Applications))},
		{"services", fmt.Sprint(len(doc.Services))},
		{"processes", fmt.Sprint(len(doc.Processes))},
		{"integrity", doc.Integrity.PayloadHash},
	}
	var bad []string
	for _, p := range pairs {
		if got := str(s, p.key); got != p.want {
			bad = append(bad, fmt.Sprintf("%s=%q want %q", p.key, got, p.want))
		}
	}
	c.check("inspect/summary", len(bad) == 0, "fields=%d mismatches=%v", len(pairs), bad)
}

// moduleStatuses are the allowed module status values (see README).
var moduleStatuses = map[string]bool{"success": true, "partial": true, "error": true, "unavailable": true, "permission_denied": true}

func (c *checker) checkDocument(doc *schema.Document) {
	issues := evidencefile.Validate(doc)
	c.check("evidence/schema-validate", len(issues) == 0, "issues=%d %s", len(issues), sample(issues, 5))
	c.check("evidence/schema-version", doc.SchemaVersion == schema.SchemaVersion, "got %s want %s", doc.SchemaVersion, schema.SchemaVersion)
	c.check("evidence/collector", doc.Collector.Name == schema.CollectorName && doc.Collector.Version == version.SemVer() && doc.Collector.BuildID == "hostcheck-full",
		"name=%s version=%s build_id=%s", doc.Collector.Name, doc.Collector.Version, doc.Collector.BuildID)
	c.check("evidence/integrity", doc.Integrity.Algorithm == "SHA-256" && len(doc.Integrity.PayloadHash) == 64,
		"algorithm=%s hash_len=%d", doc.Integrity.Algorithm, len(doc.Integrity.PayloadHash))
	c.check("evidence/platform", doc.Asset.Platform == runtime.GOOS && doc.Asset.Architecture == runtime.GOARCH,
		"platform=%s arch=%s want %s/%s", doc.Asset.Platform, doc.Asset.Architecture, runtime.GOOS, runtime.GOARCH)
	c.check("evidence/execution-mode", doc.Collection.ExecutionMode == "local", "got %q", doc.Collection.ExecutionMode)

	ran := map[string]bool{}
	var bad []string
	for _, m := range doc.Modules {
		ran[m.ModuleID] = true
		if !moduleStatuses[m.Status] {
			bad = append(bad, m.ModuleID+" status="+m.Status)
		}
		if m.Records != len(m.Evidence) {
			bad = append(bad, fmt.Sprintf("%s records=%d evidence=%d", m.ModuleID, m.Records, len(m.Evidence)))
		}
	}
	want := map[string]bool{}
	for _, id := range expectedModules {
		want[id] = true
	}
	missing := setDiff(want, ran)
	c.check("evidence/modules-ran", len(missing) == 0 && len(bad) == 0, "ran=%d missing=%v problems=%v", len(ran), missing, bad)

	partial := false
	for _, m := range doc.Modules {
		if m.Status != "success" {
			partial = true
		}
	}
	wantStatus := "complete"
	if partial {
		wantStatus = "partial"
	}
	c.check("evidence/collection-status", doc.Collection.Status == wantStatus && doc.Collection.Partial == partial,
		"status=%s partial=%v (from module statuses: %s)", doc.Collection.Status, doc.Collection.Partial, wantStatus)
}

func (c *checker) checkUpload(full string, doc *schema.Document) {
	file, _ := os.ReadFile(full)
	c.stub.takeUploads()

	r := c.run(nil, "upload", "--output", full, "--api-url", c.stub.URL("/ingest"), "--allow-insecure-upload", "--token", goodToken)
	ups := c.stub.takeUploads()
	ok := r.code == 0 && len(ups) == 1 && ups[0].err == "" && bytes.Equal(ups[0].body, file) &&
		strings.EqualFold(ups[0].header.Get("Content-Encoding"), "gzip") &&
		ups[0].header.Get("Authorization") == "Bearer "+goodToken &&
		strings.Contains(r.stderr, "token_source=flag")
	c.check("upload/gzip-default", ok, "%s uploads=%d", r, len(ups))

	r = c.run([]string{"HOSTCHECK_KEY=" + goodToken}, "upload", "--output", full, "--api-url", c.stub.URL("/ingest"),
		"--allow-insecure-upload", "--api-key-env", "HOSTCHECK_KEY", "--upload-gzip=false")
	ups = c.stub.takeUploads()
	ok = r.code == 0 && len(ups) == 1 && bytes.Equal(ups[0].raw, file) && ups[0].header.Get("Content-Encoding") == "" &&
		strings.Contains(r.stderr, "token_source=env:HOSTCHECK_KEY")
	c.check("upload/plain-env-key", ok, "%s uploads=%d", r, len(ups))

	r = c.run(nil, "upload", "--output", full, "--api-url", c.stub.URL("/ingest"), "--token", goodToken)
	ups = c.stub.takeUploads()
	c.check("upload/refuses-http", r.code != 0 && len(ups) == 0 && strings.Contains(r.stderr, "https"), "%s", r)

	r = c.run(nil, "upload", "--output", full, "--allow-insecure-upload", "--token", goodToken)
	c.check("upload/needs-api-url", r.code != 0 && strings.Contains(r.stderr, "--api-url"), "%s", r)

	r = c.run(nil, "upload", "--output", full, "--api-url", c.stub.URL("/ingest"), "--allow-insecure-upload")
	c.check("upload/needs-token", r.code != 0 && len(c.stub.takeUploads()) == 0, "%s", r)
	_ = doc
}

func noRawValue(doc *schema.Document) int {
	n := 0
	for _, m := range doc.Modules {
		for _, ev := range m.Evidence {
			if ev.RawValue != nil {
				n++
			}
		}
	}
	return n
}

func moduleIDs(doc *schema.Document) []string {
	var ids []string
	for _, m := range doc.Modules {
		ids = append(ids, m.ModuleID)
	}
	sort.Strings(ids)
	return ids
}

func (c *checker) checkCollectVariants() {
	// --modules, --compress, --keep-raw-evidence=false, --osquery-path
	out := c.path("small.openness")
	r := c.run(nil, "collect", "--output", out, "--modules", "os_inventory,users", "--compress",
		"--keep-raw-evidence=false", "--osquery-path", c.path("no-such-osqueryi"), "--build-id", "hostcheck-small")
	gz := out + ".gz"
	doc, err := c.load(gz)
	if c.check("collect/modules+compress", r.code == 0 && err == nil, "%s load=%v", r, err) {
		ids := moduleIDs(doc)
		c.check("collect/modules-allowlist", strings.Join(ids, ",") == "os_inventory,users", "modules=%v", ids)
		c.check("collect/keep-raw-evidence=false", noRawValue(doc) == 0, "records with raw_value=%d", noRawValue(doc))
		c.check("collect/build-id", doc.Collector.BuildID == "hostcheck-small", "build_id=%s", doc.Collector.BuildID)
		v := c.run(nil, "validate", gz)
		c.check("validate/gzip-file", v.code == 0 && strings.TrimSpace(v.stdout) == "OK", "%s", v)
	}

	// --exclude-modules wins over --modules.
	out = c.path("exclude.openness")
	r = c.run(nil, "collect", "--output", out, "--modules", "os_inventory,users", "--exclude-modules", "users")
	if doc, err := c.load(out); c.check("collect/exclude-modules", r.code == 0 && err == nil, "%s load=%v", r, err) {
		ids := moduleIDs(doc)
		c.check("collect/exclude-result", strings.Join(ids, ",") == "os_inventory", "modules=%v", ids)
	}

	// --force-fail-modules marks the collection partial.
	out = c.path("forcefail.openness")
	r = c.run(nil, "collect", "--output", out, "--modules", "os_inventory,users", "--force-fail-modules", "users")
	if doc, err := c.load(out); c.check("collect/force-fail-modules", r.code == 0 && err == nil, "%s load=%v", r, err) {
		st := ""
		for _, m := range doc.Modules {
			if m.ModuleID == "users" {
				st = m.Status
			}
		}
		c.check("collect/force-fail-result", st != "" && st != "success" && doc.Collection.Status == "partial" && doc.Collection.Partial,
			"users status=%s collection=%s partial=%v", st, doc.Collection.Status, doc.Collection.Partial)
	}

	// --timeout and --module-timeout are accepted with small values.
	out = c.path("timeouts.openness")
	r = c.run(nil, "collect", "--output", out, "--modules", "os_inventory", "--timeout", "120", "--module-timeout", "60")
	c.check("collect/timeouts", r.code == 0, "%s", r)
}

func (c *checker) checkConfigFile() {
	out := c.path("from-config.openness")
	cfg := fmt.Sprintf(`config_version: "1.0"
collection:
  timeout_seconds: 300
  module_timeout_seconds: 90
  keep_raw_evidence: true
modules:
  os_inventory: true
  users: false
output:
  path: %q
  compression: "gzip"
upload:
  enabled: false
`, filepath.ToSlash(out))
	path := c.path("config.yaml")
	_ = os.WriteFile(path, []byte(cfg), 0o600)
	r := c.run(nil, "collect", "--config", path)
	doc, err := c.load(out + ".gz")
	if c.check("collect/config", r.code == 0 && err == nil, "%s load=%v", r, err) {
		ids := moduleIDs(doc)
		c.check("collect/config-result", strings.Join(ids, ",") == "os_inventory", "modules=%v (want os_inventory only)", ids)
	}
}

func (c *checker) checkCollectUpload() {
	c.stub.takeUploads()
	out := c.path("upload.openness")
	r := c.run([]string{"OPENNESS_API_KEY=" + goodToken}, "collect", "--output", out, "--modules", "os_inventory",
		"--upload", "--api-url", c.stub.URL("/ingest"), "--allow-insecure-upload", "--upload-gzip")
	ups := c.stub.takeUploads()
	doc, err := c.load(out)
	ok := r.code == 0 && err == nil && len(ups) == 1
	if ok {
		file, _ := os.ReadFile(out)
		ok = bytes.Equal(ups[0].body, file) && ups[0].header.Get("Idempotency-Key") == doc.Collection.CollectionID &&
			strings.Contains(r.stderr, "token_source=env:OPENNESS_API_KEY")
	}
	c.check("collect/upload", ok, "%s uploads=%d", r, len(ups))

	r = c.run(nil, "collect", "--output", c.path("upload2.openness"), "--modules", "os_inventory",
		"--upload", "--api-url", c.stub.URL("/ingest"), "--allow-insecure-upload", "--token", goodToken, "--api-key-env", "UNUSED_ENV")
	ups = c.stub.takeUploads()
	c.check("collect/upload-token-flag", r.code == 0 && len(ups) == 1 && strings.Contains(r.stderr, "token_source=flag"), "%s", r)
}

func (c *checker) checkBadArgs() {
	r := c.run(nil, "collect", "--output", c.path("bad.openness"), "--registry-values", "%%%not-base64%%%")
	c.check("collect/bad-registry-values", r.code != 0 && strings.Contains(r.stderr, "registry values"), "%s", r)
	r = c.run(nil, "collect", "--output", c.path("bad.openness"), "--file-probes", "%%%not-base64%%%")
	c.check("collect/bad-file-probes", r.code != 0 && strings.Contains(r.stderr, "file probes"), "%s", r)
	r = c.run(nil, "collect", "--no-such-flag")
	c.check("collect/unknown-flag", r.code != 0, "exit=%d", r.code)
}

func (c *checker) checkAuth() {
	credPath := filepath.Join(c.configDir(), "credentials.json")
	_ = os.Remove(credPath)

	r := c.run(nil, "login", "--token", badTokenPrefix+goodToken, "--check-url", c.stub.URL("/check"), "--no-browser")
	_, statErr := os.Stat(credPath)
	c.check("login/rejected-token", r.code != 0 && os.IsNotExist(statErr) && strings.Contains(r.stderr, "token rejected by stub"), "%s", r)

	r = c.run(nil, "login", "--token", goodToken, "--check-url", c.stub.URL("/check"), "--token-page", c.stub.URL("/page"), "--no-browser")
	raw, err := os.ReadFile(credPath)
	var creds map[string]any
	_ = json.Unmarshal(raw, &creds)
	ok := r.code == 0 && err == nil && str(creds, "token") == goodToken && str(creds, "token_page") == c.stub.URL("/page")
	c.check("login/saves-token", ok, "%s file=%v", r, err)
	if runtime.GOOS != "windows" && err == nil {
		st, _ := os.Stat(credPath)
		c.check("login/file-mode", st.Mode().Perm() == 0o600, "mode=%v", st.Mode().Perm())
	}

	// login reads the token from stdin when --token is not given.
	r = c.runStdin(goodToken+"\n", "login", "--check-url", c.stub.URL("/check"), "--no-browser")
	c.check("login/stdin", r.code == 0 && strings.Contains(r.stderr, "login OK"), "%s", r)

	r = c.run(nil, "whoami", "--check-url", c.stub.URL("/check"))
	c.check("whoami/credentials", r.code == 0 && strings.Contains(r.stdout, "ok source=credentials"), "%s", r)

	r = c.run([]string{"OPENNESS_API_KEY=" + goodToken}, "whoami", "--check-url", c.stub.URL("/check"))
	c.check("whoami/env", r.code == 0 && strings.Contains(r.stdout, "ok source=env:OPENNESS_API_KEY"), "%s", r)

	r = c.run(nil, "logout")
	_, statErr = os.Stat(credPath)
	c.check("logout", r.code == 0 && os.IsNotExist(statErr), "%s", r)

	r = c.run(nil, "whoami", "--check-url", c.stub.URL("/check"))
	c.check("whoami/after-logout", r.code != 0 && strings.Contains(r.stderr, "not logged in"), "%s", r)
}

func (c *checker) runStdin(stdin string, args ...string) cmdResult {
	cmd := exec.Command(c.opts.bin, args...)
	cmd.Env = c.env()
	cmd.Dir = c.opts.work
	cmd.Stdin = strings.NewReader(stdin)
	var so, se bytes.Buffer
	cmd.Stdout = &so
	cmd.Stderr = &se
	err := cmd.Run()
	res := cmdResult{stdout: so.String(), stderr: se.String(), err: err, code: -1}
	if cmd.ProcessState != nil {
		res.code = cmd.ProcessState.ExitCode()
	}
	fmt.Printf("---- %s %s <stdin> (exit %d)\n", cli.BinaryName, strings.Join(args, " "), res.code)
	return res
}

func b64json(v any) string {
	b, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(b)
}
