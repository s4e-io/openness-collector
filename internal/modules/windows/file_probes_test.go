package windows

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func probesArg(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

var silverlight = map[string]string{"id": "microsoft.silverlight", "name": "^Microsoft Silverlight", "publisher": "Microsoft",
	"path": `Microsoft Silverlight\sllauncher.exe`, "base": "program_files"}

func TestParseFileProbesArg(t *testing.T) {
	ps, err := ParseFileProbesArg(probesArg(t, []any{silverlight}))
	if err != nil || len(ps) != 1 || ps[0].ID != "microsoft.silverlight" || ps[0].name == nil {
		t.Fatalf("%+v %v", ps, err)
	}
	f := filepath.Join(t.TempDir(), "p.json")
	b, _ := json.Marshal([]any{silverlight})
	os.WriteFile(f, b, 0o600)
	if ps, err := ParseFileProbesArg("@" + f); err != nil || len(ps) != 1 {
		t.Fatalf("@file: %v", err)
	}
	if ps, err := ParseFileProbesArg(""); err != nil || ps != nil {
		t.Fatal("empty argument")
	}
	for name, bad := range map[string]map[string]string{
		"absolute": {"id": "x", "name": "x", "path": `C:\Windows\notepad.exe`, "base": "program_files"},
		"unc":      {"id": "x", "name": "x", "path": `\\server\share\a.exe`, "base": "program_files"},
		"parent":   {"id": "x", "name": "x", "path": `..\..\Windows\notepad.exe`, "base": "install_location"},
		"base":     {"id": "x", "name": "x", "path": `a.exe`, "base": "system32"},
		"regex":    {"id": "x", "name": "(", "path": `a.exe`, "base": "program_files"},
		"noname":   {"id": "x", "path": `a.exe`, "base": "program_files"},
	} {
		if _, err := ParseFileProbesArg(probesArg(t, []any{bad})); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func compiled(t *testing.T, raw ...map[string]string) []FileProbe {
	t.Helper()
	ps, err := ParseFileProbesArg(probesArg(t, raw))
	if err != nil {
		t.Fatal(err)
	}
	return ps
}

func TestProbeTargets(t *testing.T) {
	ps := compiled(t, silverlight,
		map[string]string{"id": "acme", "name": "^Acme", "path": `bin\acme.exe`, "base": "install_location"},
		map[string]string{"id": "icon", "name": "^Icon App", "path": `iconapp.exe`, "base": "display_icon_dir"})
	rows := []map[string]any{
		{"product_name": "Microsoft Silverlight", "publisher": "Microsoft Corporation"},
		{"product_name": "Microsoft Silverlight", "publisher": "Someone Else"},
		{"product_name": "Acme Tool", "install_location": `"C:\Acme\"`},
		{"product_name": "Acme Without Location"},
		{"product_name": "Icon App", "display_icon": `"C:\Program Files\Icon App\iconapp.exe",0`},
		{"product_name": "Notepad++"},
	}
	got := probeTargets(rows, ps, []string{`C:\Program Files`, `C:\Program Files (x86)`})
	var lines []string
	for _, x := range got {
		lines = append(lines, x.probe.ID+" "+x.path)
	}
	want := []string{
		`microsoft.silverlight C:\Program Files\Microsoft Silverlight\sllauncher.exe`,
		`microsoft.silverlight C:\Program Files (x86)\Microsoft Silverlight\sllauncher.exe`,
		`acme C:\Acme\bin\acme.exe`,
		`icon C:\Program Files\Icon App\iconapp.exe`,
	}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Fatalf("targets:\n%s", strings.Join(lines, "\n"))
	}
}

func TestIconDirAndSignerCN(t *testing.T) {
	for in, want := range map[string]string{
		`C:\App\app.exe,0`:         `C:\App`,
		`"C:\Some App\a.exe"`:      `C:\Some App`,
		`C:\App\app.exe`:           `C:\App`,
		`app.exe`:                  ``,
		`C:/Mixed/Slashes/app.exe`: `C:\Mixed\Slashes`,
	} {
		if got := iconDir(in); got != want {
			t.Errorf("iconDir(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{
		"CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US": "Microsoft Corporation",
		`CN="Oracle America, Inc.", O="Oracle America, Inc.", C=US`:                        "Oracle America, Inc.",
		"O=No Common Name, C=US": "",
	} {
		if got := signerCN(in); got != want {
			t.Errorf("signerCN(%q) = %q, want %q", in, got, want)
		}
	}
	if signatureStatus("Valid") != "valid" || signatureStatus("HashMismatch") != "invalid" || signatureStatus("NotSigned") != "not_signed" {
		t.Error("signature status words")
	}
}

var b64arg = regexp.MustCompile(`FromBase64String\('([^']*)'\)`)

// checkFiles sends each distinct file once and attaches the result to every row it was
// asked for; a failed run marks the files with the reason instead of failing the module.
func TestCheckFiles(t *testing.T) {
	ps := compiled(t, silverlight)
	rows := []map[string]any{
		{"product_name": "Microsoft Silverlight", "publisher": "Microsoft Corporation"},
		{"product_name": "Microsoft Silverlight 5", "publisher": "Microsoft"},
		{"product_name": "Notepad++"},
	}
	var asked []string
	run := func(_ context.Context, script string) (string, error) {
		m := b64arg.FindStringSubmatch(script)
		b, _ := base64.StdEncoding.DecodeString(m[1])
		json.Unmarshal(b, &asked)
		return `[{"path":"C:\\Program Files\\Microsoft Silverlight\\sllauncher.exe","exists":true,"file_version":"5.1.50918.0",
		  "signature_status":"Valid","signer_subject":"CN=Microsoft Corporation, O=Microsoft Corporation, C=US"},
		 {"path":"C:\\Program Files (x86)\\Microsoft Silverlight\\sllauncher.exe","exists":false}]`, nil
	}
	t.Setenv("ProgramFiles", `C:\Program Files`)
	t.Setenv("ProgramFiles(x86)", `C:\Program Files (x86)`)
	t.Setenv("ProgramW6432", `C:\Program Files`)
	if n := checkFiles(context.Background(), rows, ps, run); n != 4 {
		t.Fatalf("checked %d", n)
	}
	if len(asked) != 2 {
		t.Fatalf("asked %v, want each file once", asked)
	}
	fc := rows[0]["file_checks"].([]FileCheck)
	if len(fc) != 2 || !fc[0].Exists || fc[0].SignatureStatus != "valid" || fc[0].SignerCN != "Microsoft Corporation" ||
		fc[0].FileVersion != "5.1.50918.0" || fc[0].ProbeID != "microsoft.silverlight" || fc[0].Base != "program_files" {
		t.Fatalf("checks %+v", fc)
	}
	if _, ok := rows[2]["file_checks"]; ok {
		t.Fatal("an application no probe names got file checks")
	}

	rows = []map[string]any{{"product_name": "Microsoft Silverlight", "publisher": "Microsoft"}}
	checkFiles(context.Background(), rows, ps, func(context.Context, string) (string, error) { return "", errors.New("powershell failed") })
	fc = rows[0]["file_checks"].([]FileCheck)
	if len(fc) != 2 || fc[0].Exists || !strings.Contains(fc[0].Error, "powershell failed") {
		t.Fatalf("failed run: %+v", fc)
	}
}
