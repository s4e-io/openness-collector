package windows

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

// File probes (collect --file-probes): files the consumer's application catalog wants
// checked to confirm a match, so a renamed program cannot pass for a product by its
// Add/Remove Programs name alone. A probe names the applications it applies to (name and
// publisher regular expressions, case-insensitive) and one file relative to a base folder.
// Only the files of applications whose name matches are looked at: no disk walk.

// FileProbe is one requested file check.
type FileProbe struct {
	// ID names the catalog entry the probe belongs to; it is copied to the result.
	ID        string `json:"id"`
	Name      string `json:"name"`
	Publisher string `json:"publisher,omitempty"`
	// Path is relative to Base ("Microsoft Silverlight\\sllauncher.exe").
	Path string `json:"path"`
	// Base is install_location (the entry's InstallLocation), program_files (both
	// Program Files folders) or display_icon_dir (the folder of the entry's DisplayIcon).
	Base string `json:"base"`

	name, publisher *regexp.Regexp
}

// Limits of file probes.
const (
	MaxFileProbes          = 2000
	maxFileProbeFileBytes  = 1 << 20
	maxFileProbeChecks     = 300 // files checked per run
	maxFileProbePathLength = 260
)

var fileProbeBases = map[string]bool{"install_location": true, "program_files": true, "display_icon_dir": true}

// ParseFileProbesArg parses collect --file-probes: base64url (padding optional) of a JSON
// array of FileProbe, or @<path> to a file holding that array (plain or base64url).
func ParseFileProbesArg(arg string) ([]FileProbe, error) {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return nil, nil
	}
	var payload []byte
	if strings.HasPrefix(arg, "@") {
		p := arg[1:]
		st, err := os.Stat(p)
		if err != nil {
			return nil, fmt.Errorf("file probes file: %w", err)
		}
		if st.Size() > maxFileProbeFileBytes {
			return nil, fmt.Errorf("file probes file is %d bytes, limit %d", st.Size(), maxFileProbeFileBytes)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("file probes file: %w", err)
		}
		payload = []byte(strings.TrimSpace(strings.TrimPrefix(string(b), "\ufeff")))
		if len(payload) > 0 && payload[0] != '[' {
			if payload, err = decodeBase64URL(string(payload)); err != nil {
				return nil, fmt.Errorf("file probes: %w", err)
			}
		}
	} else {
		if len(arg) > MaxRegistryValuesArgLen {
			return nil, fmt.Errorf("file probes argument is %d characters, limit %d; pass @<file> instead", len(arg), MaxRegistryValuesArgLen)
		}
		var err error
		if payload, err = decodeBase64URL(arg); err != nil {
			return nil, fmt.Errorf("file probes: %w", err)
		}
	}
	var probes []FileProbe
	if err := json.Unmarshal(payload, &probes); err != nil {
		return nil, fmt.Errorf("file probes: %w", err)
	}
	if len(probes) > MaxFileProbes {
		return nil, fmt.Errorf("file probes: %d entries, limit %d", len(probes), MaxFileProbes)
	}
	for i := range probes {
		if err := probes[i].compile(); err != nil {
			return nil, fmt.Errorf("file probe %d (%s): %w", i, probes[i].ID, err)
		}
	}
	return probes, nil
}

func (p *FileProbe) compile() error {
	if p.ID == "" || p.Name == "" {
		return fmt.Errorf("id and name are required")
	}
	if !fileProbeBases[p.Base] {
		return fmt.Errorf("base %q: want install_location, program_files or display_icon_dir", p.Base)
	}
	if !relativeWindowsPath(p.Path) {
		return fmt.Errorf("path %q must be a relative path without '..'", p.Path)
	}
	var err error
	if p.name, err = regexp.Compile("(?i)" + p.Name); err != nil {
		return fmt.Errorf("name: %w", err)
	}
	if p.Publisher != "" {
		if p.publisher, err = regexp.Compile("(?i)" + p.Publisher); err != nil {
			return fmt.Errorf("publisher: %w", err)
		}
	}
	return nil
}

// relativeWindowsPath accepts "Folder\\file.exe" and refuses drives, UNC, rooted paths
// and parent references.
func relativeWindowsPath(p string) bool {
	if p == "" || len(p) > maxFileProbePathLength || strings.ContainsAny(p, ":*?\"<>|\x00") {
		return false
	}
	if strings.HasPrefix(p, `\`) || strings.HasPrefix(p, "/") {
		return false
	}
	for _, part := range strings.FieldsFunc(p, func(r rune) bool { return r == '\\' || r == '/' }) {
		if part == ".." || part == "." {
			return false
		}
	}
	return true
}

// FileCheck is the result for one probed file of one application.
type FileCheck struct {
	ProbeID string `json:"probe_id"`
	Base    string `json:"base"`
	Path    string `json:"path"`
	Exists  bool   `json:"exists"`
	// FileVersion is the VS_FIXEDFILEINFO file version (FileMajorPart.Minor.Build.Private);
	// FileVersionString the version resource string; ProductVersion likewise.
	FileVersion       string `json:"file_version,omitempty"`
	FileVersionString string `json:"file_version_string,omitempty"`
	ProductVersion    string `json:"product_version,omitempty"`
	// SignatureStatus is valid, not_signed, invalid (hash mismatch), not_trusted,
	// unknown_error, not_supported or error (could not be read).
	SignatureStatus string `json:"signature_status,omitempty"`
	SignerSubject   string `json:"signer_subject,omitempty"`
	SignerCN        string `json:"signer_cn,omitempty"`
	Error           string `json:"error,omitempty"`
}

type probeTarget struct {
	row   int
	probe *FileProbe
	path  string
}

// probeTargets lists the files to check: for each application row whose name (and
// publisher) a probe matches, that probe's file under the row's base folder.
func probeTargets(rows []map[string]any, probes []FileProbe, programFiles []string) []probeTarget {
	var out []probeTarget
	for i, row := range rows {
		name, _ := row["product_name"].(string)
		if name == "" {
			continue
		}
		pub, _ := row["publisher"].(string)
		for j := range probes {
			p := &probes[j]
			if !p.name.MatchString(name) || (p.publisher != nil && !p.publisher.MatchString(pub)) {
				continue
			}
			for _, dir := range probeBases(row, p.Base, programFiles) {
				out = append(out, probeTarget{row: i, probe: p, path: joinWindows(dir, p.Path)})
			}
		}
	}
	return out
}

func probeBases(row map[string]any, base string, programFiles []string) []string {
	switch base {
	case "install_location":
		if s, _ := row["install_location"].(string); strings.TrimSpace(s) != "" {
			return []string{strings.Trim(strings.TrimSpace(s), `"`)}
		}
	case "display_icon_dir":
		if s, _ := row["display_icon"].(string); strings.TrimSpace(s) != "" {
			return []string{iconDir(s)}
		}
	case "program_files":
		return programFiles
	}
	return nil
}

// iconDir is the folder of a DisplayIcon value such as "C:\\App\\app.exe,0" or a quoted path.
func iconDir(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, `"`) {
		if end := strings.Index(s[1:], `"`); end >= 0 {
			s = s[1 : end+1]
		}
	} else if comma := strings.LastIndex(s, ","); comma > 0 {
		s = s[:comma]
	}
	s = strings.ReplaceAll(s, "/", `\`)
	if i := strings.LastIndex(s, `\`); i > 0 {
		return s[:i]
	}
	return ""
}

func joinWindows(dir, rel string) string {
	dir = strings.TrimRight(strings.ReplaceAll(dir, "/", `\`), `\`)
	rel = strings.TrimLeft(strings.ReplaceAll(rel, "/", `\`), `\`)
	if dir == "" {
		return ""
	}
	return dir + `\` + rel
}

var cnPattern = regexp.MustCompile(`(?:^|,\s*)CN=("(?:[^"]|"")*"|[^,]*)`)

// signerCN is the CN of an X.500 subject ("CN=Microsoft Corporation, O=...").
func signerCN(subject string) string {
	m := cnPattern.FindStringSubmatch(subject)
	if m == nil {
		return ""
	}
	v := strings.TrimSpace(m[1])
	if strings.HasPrefix(v, `"`) && strings.HasSuffix(v, `"`) && len(v) >= 2 {
		v = strings.ReplaceAll(v[1:len(v)-1], `""`, `"`)
	}
	return v
}

// signatureStatus maps Get-AuthenticodeSignature's Status to the evidence words.
func signatureStatus(ps string) string {
	switch strings.ToLower(ps) {
	case "valid":
		return "valid"
	case "notsigned":
		return "not_signed"
	case "hashmismatch":
		return "invalid"
	case "nottrusted":
		return "not_trusted"
	case "unknownerror":
		return "unknown_error"
	case "notsupportedfileformat":
		return "not_supported"
	case "":
		return ""
	}
	return "error"
}

const fileProbeScript = `
$ErrorActionPreference = 'SilentlyContinue'
$paths = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%s')) | ConvertFrom-Json
$out = @()
foreach ($p in $paths) {
  $r = [ordered]@{ path = $p; exists = $false }
  try {
    if (Test-Path -LiteralPath $p -PathType Leaf) {
      $r.exists = $true
      $vi = [Diagnostics.FileVersionInfo]::GetVersionInfo($p)
      $r.file_version = ('{0}.{1}.{2}.{3}' -f $vi.FileMajorPart, $vi.FileMinorPart, $vi.FileBuildPart, $vi.FilePrivatePart)
      $r.file_version_string = $vi.FileVersion
      $r.product_version = $vi.ProductVersion
      try {
        $sig = Get-AuthenticodeSignature -LiteralPath $p -ErrorAction Stop
        $r.signature_status = [string]$sig.Status
        if ($sig.SignerCertificate) { $r.signer_subject = $sig.SignerCertificate.Subject }
      } catch { $r.signature_status = 'error'; $r.error = $_.Exception.Message }
    }
  } catch { $r.error = $_.Exception.Message }
  $out += [PSCustomObject]$r
}
ConvertTo-Json -InputObject @($out) -Compress -Depth 3
`

// checkFiles runs the probes on the application rows and attaches each row's file_checks.
// A file that could not be checked is a file_checks entry with error set, never a module
// error: an unchecked file only means the catalog's confirmation did not hold.
func checkFiles(ctx context.Context, rows []map[string]any, probes []FileProbe, run func(context.Context, string) (string, error)) (checked int) {
	if len(probes) == 0 || len(rows) == 0 {
		return 0
	}
	targets := probeTargets(rows, probes, programFilesDirs())
	var paths []string
	seen := map[string]bool{}
	for _, t := range targets {
		key := strings.ToLower(t.path)
		if t.path == "" || seen[key] {
			continue
		}
		seen[key] = true
		paths = append(paths, t.path)
	}
	if len(paths) == 0 {
		return 0
	}
	sort.Strings(paths)
	if len(paths) > maxFileProbeChecks {
		paths = paths[:maxFileProbeChecks]
	}
	byPath := map[string]FileCheck{}
	fail := func(msg string) {
		for _, p := range paths {
			byPath[strings.ToLower(p)] = FileCheck{Path: p, Error: msg}
		}
	}
	b, _ := json.Marshal(paths)
	if out, err := run(ctx, fmt.Sprintf(fileProbeScript, base64.StdEncoding.EncodeToString(b))); err != nil {
		fail("not checked: " + err.Error())
	} else {
		var results []FileCheck
		if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &results); err != nil {
			fail("unreadable check result: " + err.Error())
		}
		for _, r := range results {
			byPath[strings.ToLower(r.Path)] = r
		}
	}
	for _, t := range targets {
		r, ok := byPath[strings.ToLower(t.path)]
		if !ok {
			if t.path == "" {
				continue
			}
			r = FileCheck{Path: t.path, Error: fmt.Sprintf("not checked: over the limit of %d files per run", maxFileProbeChecks)}
		}
		r.ProbeID, r.Base = t.probe.ID, t.probe.Base
		r.SignatureStatus = signatureStatus(r.SignatureStatus)
		r.SignerCN = signerCN(r.SignerSubject)
		list, _ := rows[t.row]["file_checks"].([]FileCheck)
		rows[t.row]["file_checks"] = append(list, r)
		checked++
	}
	return checked
}

func programFilesDirs() []string {
	var out []string
	for _, v := range []string{"ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"} {
		if d := os.Getenv(v); d != "" && !contains(out, d) {
			out = append(out, d)
		}
	}
	if len(out) == 0 {
		out = []string{`C:\Program Files`, `C:\Program Files (x86)`}
	}
	return out
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}
