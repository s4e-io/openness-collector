package linux

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/s4e-io/openness-collector/internal/modules/common"
	"github.com/s4e-io/openness-collector/internal/procutil"
	"github.com/s4e-io/openness-collector/internal/schema"
)

// maxPackages caps package records per host and per container. Parsing stops
// at the cap, so a hostile or corrupt package database cannot exhaust memory
// or push the evidence file past its size limit.
const maxPackages = 20000

// hostPackageLimit is maxPackages; a variable so tests can lower it.
var hostPackageLimit = maxPackages

// dpkgStatusDDir holds one stanza file per package on distroless Debian
// images (no dpkg binary, no /var/lib/dpkg/status). Overridable in tests.
var dpkgStatusDDir = "/var/lib/dpkg/status.d"

// dpkgStanzaFields are the only stanza fields the collector reads; others
// (Description, Conffiles, ...) are skipped without being stored.
var dpkgStanzaFields = map[string]bool{
	"Package": true, "Status": true, "Version": true, "Architecture": true, "Source": true,
}

// scanDpkgStanzas streams dpkg status stanzas from r and calls fn for each
// one with a Package field. fn returns false to stop reading.
func scanDpkgStanzas(r io.Reader, fn func(fields map[string]string) bool) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	fields := map[string]string{}
	flush := func() bool {
		if fields["Package"] == "" {
			clear(fields)
			return true
		}
		ok := fn(fields)
		fields = map[string]string{}
		return ok
	}
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			if !flush() {
				return nil
			}
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			// Continuation of a multi-line field.
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok || !dpkgStanzaFields[k] {
			continue
		}
		fields[k] = strings.TrimSpace(v)
	}
	if err := sc.Err(); err != nil {
		return err
	}
	flush()
	return nil
}

// dpkgStanzaInstalled applies the dpkg installed rule. status.d stanzas
// usually have no Status field; their presence means installed.
func dpkgStanzaInstalled(fields map[string]string, statusD bool) bool {
	st, ok := fields["Status"]
	if !ok && statusD {
		return true
	}
	return dpkgStatusInstalled(st)
}

// dpkgStatusDFiles lists the stanza files in a status.d directory, skipping
// the per-package *.md5sums files and anything that is not a regular file.
func dpkgStatusDFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if !e.Type().IsRegular() || strings.HasSuffix(e.Name(), ".md5sums") {
			continue
		}
		out = append(out, filepath.Join(dir, e.Name()))
	}
	sort.Strings(out)
	return out, nil
}

// scanDpkgStatusD runs scanDpkgStanzas over every stanza file in dir.
// installed is called with fields already filtered by the installed rule.
func scanDpkgStatusD(dir string, installed func(fields map[string]string) bool) error {
	files, err := dpkgStatusDFiles(dir)
	if err != nil {
		return err
	}
	for _, p := range files {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		stop := false
		err = scanDpkgStanzas(f, func(fields map[string]string) bool {
			if !dpkgStanzaInstalled(fields, true) {
				return true
			}
			if !installed(fields) {
				stop = true
				return false
			}
			return true
		})
		_ = f.Close()
		if stop {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%s: %w", filepath.Base(p), err)
		}
	}
	return nil
}

// streamCommandLines runs a command and hands each stdout line to fn without
// buffering the whole output. When fn returns false the command is killed and
// stopped is true; the command's own exit error is then ignored.
func streamCommandLines(ctx context.Context, fn func(line string) bool, name string, args ...string) (stopped bool, err error) {
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := procutil.Command(cctx, name, args...)
	out, err := cmd.StdoutPipe()
	if err != nil {
		return false, err
	}
	if err := cmd.Start(); err != nil {
		return false, err
	}
	sc := bufio.NewScanner(out)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		if !fn(sc.Text()) {
			stopped = true
			break
		}
	}
	scanErr := sc.Err()
	if stopped || scanErr != nil {
		cancel()
	}
	waitErr := cmd.Wait()
	if stopped {
		return true, nil
	}
	if scanErr != nil {
		return false, scanErr
	}
	if waitErr == nil && ctx.Err() != nil {
		waitErr = ctx.Err()
	}
	return false, waitErr
}

// hostPackageRoom reports whether one more host package record fits. At the
// limit it records package_limit_truncated once and marks the module result
// truncated.
func hostPackageRoom(res *schema.ModuleResult, moduleID string) bool {
	if len(res.Evidence) < hostPackageLimit {
		return true
	}
	if !res.Truncated {
		res.Truncated = true
		res.Errors = append(res.Errors, common.Err(moduleID, "package_limit_truncated",
			fmt.Sprintf("package records capped at %d; remaining packages not collected", hostPackageLimit)))
	}
	return false
}
