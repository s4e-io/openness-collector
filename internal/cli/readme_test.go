package cli

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/spf13/pflag"
)

// readmeUsage returns the "## Usage" section of README.md split by
// "### <command>" heading. A command section runs until the next "### " or "## ".
func readmeUsage(t *testing.T) map[string]string {
	t.Helper()
	b, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(b), "\n")
	sections := map[string]string{}
	inUsage := false
	current := ""
	heading := regexp.MustCompile("^### `?([a-z][a-z-]*)`?\\s*$")
	for _, line := range lines {
		switch {
		case strings.HasPrefix(line, "## "):
			inUsage = strings.TrimSpace(line) == "## Usage"
			current = ""
			continue
		case !inUsage:
			continue
		case strings.HasPrefix(line, "### "):
			current = ""
			if m := heading.FindStringSubmatch(line); m != nil {
				current = m[1]
				sections[current] = ""
			}
			continue
		}
		if current != "" {
			sections[current] += line + "\n"
		}
	}
	if len(sections) == 0 {
		t.Fatal("README.md has no \"## Usage\" section with \"### <command>\" headings")
	}
	return sections
}

// TestREADMEDocumentsEveryFlag fails when a command or flag defined in code is
// not documented in the Usage section of README.md (doc drift guard).
func TestREADMEDocumentsEveryFlag(t *testing.T) {
	sections := readmeUsage(t)
	root := NewRoot()
	for _, cmd := range root.Commands() {
		if cmd.Hidden || cmd.Name() == "help" || cmd.Name() == "completion" {
			continue
		}
		body, ok := sections[cmd.Name()]
		if !ok {
			t.Errorf("README.md Usage has no \"### %s\" section", cmd.Name())
			continue
		}
		cmd.LocalFlags().VisitAll(func(f *pflag.Flag) {
			if f.Name == "help" {
				return
			}
			if !strings.Contains(body, "`--"+f.Name+"`") {
				t.Errorf("README.md \"### %s\" does not document `--%s` (%s)", cmd.Name(), f.Name, f.Usage)
			}
		})
	}
	// A documented command that no longer exists is drift too.
	for name := range sections {
		if c, _, err := root.Find([]string{name}); err != nil || c == root {
			t.Errorf("README.md documents \"### %s\" but there is no such command", name)
		}
	}
}

// TestREADMEDocumentsFlagDefaults checks that each non-empty default value in
// code appears in the flag's README row.
func TestREADMEDocumentsFlagDefaults(t *testing.T) {
	sections := readmeUsage(t)
	for _, cmd := range NewRoot().Commands() {
		body := sections[cmd.Name()]
		cmd.LocalFlags().VisitAll(func(f *pflag.Flag) {
			if f.Name == "help" || f.DefValue == "" {
				return
			}
			for _, line := range strings.Split(body, "\n") {
				if strings.HasPrefix(line, "| `--"+f.Name+"`") {
					if !strings.Contains(line, "`"+f.DefValue+"`") {
						t.Errorf("README.md %s `--%s`: default %q not shown in %q", cmd.Name(), f.Name, f.DefValue, line)
					}
					return
				}
			}
		})
	}
}
