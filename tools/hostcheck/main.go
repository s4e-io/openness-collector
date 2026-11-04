// Command hostcheck is the end-to-end test of the openness-collector binary on a real host.
//
// It runs every openness-collector command against the machine it runs on and then
// compares the evidence with what the host itself reports (os-release, uname,
// the package database, Get-CimInstance, Get-HotFix, the uninstall registry).
// It opens a TCP listener on a fixed port so the listening_ports module has a
// known socket to find, and it serves a local HTTP stub for the upload and
// login commands, so nothing leaves the machine.
//
// It is used by CI on ubuntu-latest, windows-latest and inside distro
// containers. Exit status is 0 only when every check passed.
//
//	go build -o hostcheck ./tools/hostcheck
//	go build -o openness-collector ./cmd/openness-collector
//	sudo ./hostcheck -bin ./openness-collector -user "$USER"
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type options struct {
	bin           string
	work          string
	port          int
	user          string
	timeout       int
	moduleTimeout int
	summary       string
	label         string
}

func main() {
	var o options
	flag.StringVar(&o.bin, "bin", "", "path to the openness-collector binary under test (required)")
	flag.StringVar(&o.work, "work", "", "work directory for evidence files (default: a new temp dir)")
	flag.IntVar(&o.port, "port", 47123, "TCP port the checker listens on during collect")
	flag.StringVar(&o.user, "user", "", "local user that must appear in users (default: current user)")
	flag.IntVar(&o.timeout, "timeout", 600, "collect --timeout seconds for the full run")
	flag.IntVar(&o.moduleTimeout, "module-timeout", 240, "collect --module-timeout seconds for the full run")
	flag.StringVar(&o.summary, "summary", "", "append a markdown result table to this file (for GITHUB_STEP_SUMMARY)")
	flag.StringVar(&o.label, "label", "", "name for this run in the summary (default: GOOS)")
	flag.Parse()

	if o.bin == "" {
		fmt.Fprintln(os.Stderr, "hostcheck: -bin is required")
		os.Exit(2)
	}
	abs, err := filepath.Abs(o.bin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "hostcheck:", err)
		os.Exit(2)
	}
	o.bin = abs
	if o.work == "" {
		if o.work, err = os.MkdirTemp("", "hostcheck-*"); err != nil {
			fmt.Fprintln(os.Stderr, "hostcheck:", err)
			os.Exit(2)
		}
	}
	if err := os.MkdirAll(o.work, 0o700); err != nil {
		fmt.Fprintln(os.Stderr, "hostcheck:", err)
		os.Exit(2)
	}
	if o.user == "" {
		o.user = currentUser()
	}
	if o.label == "" {
		o.label = runtime.GOOS
	}

	c := &checker{opts: o, started: time.Now()}

	// The listener stays open for the whole run so every collect can see it.
	ln, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", o.port))
	if err != nil {
		fmt.Fprintf(os.Stderr, "hostcheck: listen on %d: %v\n", o.port, err)
		os.Exit(2)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	stub := newStub()
	defer stub.Close()
	c.stub = stub

	c.runCommands()
	c.writeSummary()
	fmt.Printf("\nhostcheck %s: %d passed, %d failed, %s\n", o.label, c.passed, len(c.failed), time.Since(c.started).Round(time.Second))
	if len(c.failed) > 0 {
		fmt.Println("failed checks:")
		for _, f := range c.failed {
			fmt.Println("  -", f)
		}
		os.Exit(1)
	}
}

func currentUser() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		name := u.Username
		// Windows returns DOMAIN\name.
		if i := strings.LastIndex(name, `\`); i >= 0 {
			name = name[i+1:]
		}
		return name
	}
	for _, k := range []string{"USER", "USERNAME"} {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}

type result struct {
	name   string
	ok     bool
	detail string
}

type checker struct {
	opts    options
	stub    *stub
	started time.Time
	passed  int
	failed  []string
	results []result
}

// check records one assertion. detail explains what was compared.
func (c *checker) check(name string, ok bool, format string, args ...any) bool {
	detail := fmt.Sprintf(format, args...)
	c.results = append(c.results, result{name: name, ok: ok, detail: detail})
	if ok {
		c.passed++
		fmt.Printf("PASS %-38s %s\n", name, detail)
	} else {
		c.failed = append(c.failed, name+": "+detail)
		fmt.Printf("FAIL %-38s %s\n", name, detail)
	}
	return ok
}

func (c *checker) note(format string, args ...any) {
	fmt.Printf("     %s\n", fmt.Sprintf(format, args...))
}

func (c *checker) writeSummary() {
	if c.opts.summary == "" {
		return
	}
	f, err := os.OpenFile(c.opts.summary, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		fmt.Fprintln(os.Stderr, "hostcheck: summary:", err)
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "## hostcheck %s: %d passed, %d failed\n\n", c.opts.label, c.passed, len(c.failed))
	fmt.Fprintln(f, "| check | result | detail |")
	fmt.Fprintln(f, "|---|---|---|")
	for _, r := range c.results {
		status := "pass"
		if !r.ok {
			status = "**FAIL**"
		}
		d := strings.ReplaceAll(r.detail, "|", "/")
		if len(d) > 200 {
			d = d[:200] + "..."
		}
		fmt.Fprintf(f, "| %s | %s | %s |\n", r.name, status, d)
	}
	fmt.Fprintln(f)
}
