package windows

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func findSpec(specs []RegistryValueSpec, key, name string) (RegistryValueSpec, bool) {
	for _, s := range specs {
		if strings.EqualFold(s.Key, key) && strings.EqualFold(s.Name, name) {
			return s, true
		}
	}
	return RegistryValueSpec{}, false
}

func TestSecurityRegistryTableShape(t *testing.T) {
	seen := map[string]bool{}
	for _, s := range securityRegistrySpecs {
		if s.Key == "" || s.Name == "" {
			t.Fatalf("empty key or name: %+v", s)
		}
		up := strings.ToUpper(s.Key)
		if strings.HasPrefix(up, "HK") || strings.HasPrefix(s.Key, `\`) || strings.HasSuffix(s.Key, `\`) {
			t.Fatalf("key must be relative to HKLM without hive prefix: %q", s.Key)
		}
		if strings.Contains(s.Key, "*") && !s.wildcard() {
			t.Fatalf("* only allowed as trailing wildcard: %q", s.Key)
		}
		id := strings.ToLower(s.Key + "|" + s.Name)
		if seen[id] {
			t.Fatalf("duplicate entry %q", id)
		}
		seen[id] = true
		if _, err := validateRegistryRequest(registryValueRequest{Key: s.Key, Name: s.Name}); err != nil {
			t.Fatalf("built-in entry fails run-time validation: %v", err)
		}
	}
	// 8 Lsa + 1 + 2 + 2 + 1 + 1 + 3 + 3 + 2 + 2 IE + 2 + 3 + 1 + 5 + 2 + 1
	// + 12 protocols + 7 ciphers + 1 + 1 + 1 + 4 .NET + 3 Winlogon + 2 + 3 + 2 + 1
	if got, want := len(securityRegistrySpecs), 76; got != want {
		t.Fatalf("table has %d entries, want %d", got, want)
	}
	for _, c := range []struct{ key, name string }{
		{`SYSTEM\CurrentControlSet\Control\Lsa`, "RunAsPPL"},
		{`SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\*`, "NetbiosOptions"},
		{`SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128`, "Enabled"},
		{`SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server`, "DisabledByDefault"},
		{`SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319`, "SchUseStrongCrypto"},
		{`SOFTWARE\Wow6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING`, "iexplore.exe"},
		{`SYSTEM\CurrentControlSet\Services\Spooler`, "Start"},
	} {
		if _, ok := findSpec(securityRegistrySpecs, c.key, c.name); !ok {
			t.Fatalf("missing %s\\%s", c.key, c.name)
		}
	}
	dp, ok := findSpec(securityRegistrySpecs, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, "DefaultPassword")
	if !ok || !dp.PresenceOnly {
		t.Fatalf("DefaultPassword must be presence-only: %+v", dp)
	}
	for _, s := range securityRegistrySpecs {
		if s.PresenceOnly && s.Name != "DefaultPassword" {
			t.Fatalf("unexpected presence-only entry %+v", s)
		}
	}
}

func TestSecurityConfigurationScriptReadsSpecFile(t *testing.T) {
	script := securityConfigurationScript(`C:\Temp\it's.json`)
	if strings.Contains(script, registrySpecPathPlaceholder) {
		t.Fatal("placeholder not replaced")
	}
	if !strings.Contains(script, `$registrySpecPath = 'C:\Temp\it''s.json'`) {
		t.Fatal("spec path not quoted as a PowerShell literal")
	}
	if !strings.Contains(script, "registry = $registry") {
		t.Fatal("registry not in output object")
	}
	// Read-only: the script must never write or delete registry data.
	for _, bad := range []string{"SetValue", "DeleteValue", "CreateSubKey", "DeleteSubKey", "Set-ItemProperty", "New-ItemProperty", "Remove-Item", "OpenSubKey($key, $true)"} {
		if strings.Contains(script, bad) {
			t.Fatalf("script contains write operation %q", bad)
		}
	}
	// Presence-only values are skipped before GetValue.
	if !strings.Contains(script, "if (-not $presenceOnly) {") {
		t.Fatal("presence-only guard missing")
	}
	if len(script) > 24000 {
		t.Fatalf("script is %d characters; keep well under the 32767 command line limit", len(script))
	}
}

func TestRegistrySpecFileRoundTrip(t *testing.T) {
	path, err := writeRegistrySpecFile(securityRegistrySpecs)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(path)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got []map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != len(securityRegistrySpecs) {
		t.Fatalf("got %d entries", len(got))
	}
	if got[0]["key"] != `SYSTEM\CurrentControlSet\Control\Lsa` || got[0]["name"] != "RunAsPPL" {
		t.Fatalf("first entry %+v", got[0])
	}
}

const winlogonKey = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`
const netbtPattern = `SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\*`

func normalizeFromJSON(t *testing.T, raw string, specs []RegistryValueSpec) []map[string]any {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	for _, e := range normalizeRegistryEntries(v, specs) {
		out = append(out, e.(map[string]any))
	}
	return out
}

func TestNormalizeRegistryEntries(t *testing.T) {
	specs := []RegistryValueSpec{
		{Key: `SYSTEM\CurrentControlSet\Control\Lsa`, Name: "RunAsPPL"},
		{Key: `SYSTEM\CurrentControlSet\Control\Lsa`, Name: "NoLMHash"},
		{Key: netbtPattern, Name: "NetbiosOptions"},
		{Key: winlogonKey, Name: "DefaultPassword", PresenceOnly: true},
		{Key: `SYSTEM\CurrentControlSet\Services\Spooler`, Name: "Start"},
		{Key: `SYSTEM\CurrentControlSet\Services\mrxsmb10`, Name: "Start"},
	}
	raw := `[
	 {"key":"SYSTEM\\CurrentControlSet\\Control\\Lsa","name":"RunAsPPL","hive":"HKLM","present":true,"type":"DWord","value":1},
	 {"key":"SYSTEM\\CurrentControlSet\\Control\\Lsa","name":"RunAsPPL","hive":"HKLM","present":true,"type":"DWord","value":9},
	 {"key":"SYSTEM\\CurrentControlSet\\Control\\Lsa","name":"NoLMHash","hive":"HKLM","present":false,"type":null,"value":null},
	 {"key":"SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces\\Tcpip_{A}","name":"NetbiosOptions","hive":"HKLM","present":true,"type":"DWord","value":2,"pattern":"SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces\\*"},
	 {"key":"SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces\\Tcpip_{B}","name":"NetbiosOptions","hive":"HKLM","present":false,"type":null,"value":null,"pattern":"SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces\\*"},
	 {"key":"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon","name":"DefaultPassword","hive":"HKLM","present":true,"type":"String","value":"hunter2"},
	 {"key":"SYSTEM\\CurrentControlSet\\Services\\Spooler","name":"Start","hive":"HKLM","present":false,"type":null,"value":null,"error":"access_denied"},
	 {"key":"SOFTWARE\\Not\\Listed","name":"X","hive":"HKLM","present":true,"type":"DWord","value":1}
	]`
	out := normalizeFromJSON(t, raw, specs)
	if len(out) != 7 {
		b, _ := json.Marshal(out)
		t.Fatalf("got %d entries: %s", len(out), b)
	}
	// normal
	if out[0]["value"] != float64(1) || out[0]["present"] != true || out[0]["type"] != "DWord" {
		t.Fatalf("normal entry: %+v", out[0])
	}
	// absent
	if out[1]["present"] != false || out[1]["value"] != nil {
		t.Fatalf("absent entry: %+v", out[1])
	}
	if _, has := out[1]["error"]; has {
		t.Fatalf("absent entry must not carry an error: %+v", out[1])
	}
	// wildcard: one per concrete subkey
	if !strings.HasSuffix(out[2]["key"].(string), `Tcpip_{A}`) || out[2]["pattern"] != netbtPattern || out[2]["value"] != float64(2) {
		t.Fatalf("wildcard entry: %+v", out[2])
	}
	if !strings.HasSuffix(out[3]["key"].(string), `Tcpip_{B}`) || out[3]["present"] != false {
		t.Fatalf("wildcard entry 2: %+v", out[3])
	}
	// presence-only
	if out[4]["present"] != true || out[4]["value"] != nil {
		t.Fatalf("DefaultPassword entry: %+v", out[4])
	}
	// read error
	if out[5]["error"] != "access_denied" || out[5]["present"] != false {
		t.Fatalf("error entry: %+v", out[5])
	}
	// not reported by the script: collected=false must be explicit
	if out[6]["error"] != "not_reported" || out[6]["key"] != `SYSTEM\CurrentControlSet\Services\mrxsmb10` {
		t.Fatalf("missing entry: %+v", out[6])
	}
}

// The DefaultPassword value must never reach the evidence, whatever the script returns.
func TestDefaultPasswordValueNeverEmitted(t *testing.T) {
	const secret = "S3cretValue!"
	raw := fmt.Sprintf(`[{"key":%q,"name":"DefaultPassword","hive":"HKLM","present":true,"type":"String","value":%q},
	  {"key":%q,"name":"AltDefaultPassword","hive":"HKLM","present":true,"type":"String","value":%q}]`,
		winlogonKey, secret, winlogonKey, secret)
	specs := mergeRegistrySpecs(securityRegistrySpecs, []RegistryValueSpec{{Key: winlogonKey, Name: "AltDefaultPassword"}})
	out := normalizeFromJSON(t, raw, specs)
	b, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), secret) {
		t.Fatalf("secret leaked into registry output: %s", b)
	}
	found := 0
	for _, e := range out {
		if n := e["name"]; n == "DefaultPassword" || n == "AltDefaultPassword" {
			found++
			if e["present"] != true || e["value"] != nil {
				t.Fatalf("presence-only entry: %+v", e)
			}
		}
	}
	if found != 2 {
		t.Fatalf("found %d password entries", found)
	}
}

func TestNormalizeRegistryWildcardWithoutSubkeys(t *testing.T) {
	specs := []RegistryValueSpec{{Key: netbtPattern, Name: "NetbiosOptions"}}
	raw := `{"key":"SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces\\*","name":"NetbiosOptions","hive":"HKLM","present":false,"type":null,"value":null,"pattern":"SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces\\*"}`
	out := normalizeFromJSON(t, raw, specs)
	if len(out) != 1 || out[0]["key"] != netbtPattern || out[0]["present"] != false {
		t.Fatalf("placeholder: %+v", out)
	}
	if _, has := out[0]["error"]; has {
		t.Fatalf("no subkeys is not an error: %+v", out[0])
	}
}

func TestNormalizeRegistryMissingField(t *testing.T) {
	out := normalizeRegistryEntries(nil, securityRegistrySpecs)
	if len(out) != len(securityRegistrySpecs) {
		t.Fatalf("got %d", len(out))
	}
	for _, e := range out {
		if e.(map[string]any)["error"] != "not_reported" {
			t.Fatalf("entry %+v", e)
		}
	}
}

func encodeArg(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func TestParseRegistryValuesArg(t *testing.T) {
	arg := encodeArg(t, []map[string]any{
		{"key": `HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security`, "name": "MaxSize"},
		{"key": `SYSTEM\CurrentControlSet\Control\Lsa\`, "name": "RunAsPPL", "hive": "HKLM"},
		{"key": `system\currentcontrolset\control\lsa`, "name": "runasppl"},
		{"key": winlogonKey, "name": "DefaultPassword"},
		{"key": winlogonKey, "name": "SomeKeyBlob"},
		{"key": `SOFTWARE\Vendor\App`, "name": "AdminPassword"},
		{"key": `SECURITY\Policy\Secrets\X`, "name": "CurrVal"},
		{"key": `SOFTWARE\Vendor\App`, "name": "LicenseKey"},
		{"key": `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\*`, "name": "EnableDHCP"},
	})
	specs, err := ParseRegistryValuesArg(arg)
	if err != nil {
		t.Fatal(err)
	}
	if len(specs) != 8 {
		t.Fatalf("expected dedupe to 8 entries, got %d: %+v", len(specs), specs)
	}
	if specs[0].Key != `SOFTWARE\Policies\Microsoft\Windows\EventLog\Security` {
		t.Fatalf("HKLM prefix not stripped: %q", specs[0].Key)
	}
	if specs[1].Key != `SYSTEM\CurrentControlSet\Control\Lsa` {
		t.Fatalf("trailing backslash not trimmed: %q", specs[1].Key)
	}
	want := map[string]bool{"MaxSize": false, "RunAsPPL": false, "DefaultPassword": true, "SomeKeyBlob": true, "AdminPassword": true, "CurrVal": true, "LicenseKey": false, "EnableDHCP": false}
	for _, s := range specs {
		if w, ok := want[s.Name]; !ok || w != s.PresenceOnly {
			t.Fatalf("%s presence_only=%v", s.Name, s.PresenceOnly)
		}
	}

	// Padded and plain base64 are accepted too.
	b, _ := json.Marshal([]map[string]string{{"key": `SOFTWARE\A`, "name": "B"}})
	for _, enc := range []*base64.Encoding{base64.URLEncoding, base64.StdEncoding} {
		if got, err := ParseRegistryValuesArg(enc.EncodeToString(b)); err != nil || len(got) != 1 {
			t.Fatalf("encoding: %v %+v", err, got)
		}
	}
}

func TestParseRegistryValuesMergeWithBuiltin(t *testing.T) {
	extra, err := ParseRegistryValuesArg(encodeArg(t, []map[string]string{
		{"key": `SYSTEM\CurrentControlSet\Control\Lsa`, "name": "RunAsPPL"},
		{"key": `SOFTWARE\Policies\Microsoft\Windows\EventLog\Security`, "name": "MaxSize"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	merged := mergeRegistrySpecs(securityRegistrySpecs, extra)
	if len(merged) != len(securityRegistrySpecs)+1 {
		t.Fatalf("merged %d", len(merged))
	}
	if merged[len(merged)-1].Name != "MaxSize" {
		t.Fatalf("extra not appended: %+v", merged[len(merged)-1])
	}
}

func TestParseRegistryValuesRejects(t *testing.T) {
	cases := map[string]any{
		"other hive field":   []map[string]string{{"hive": "HKCU", "key": `Software\X`, "name": "A"}},
		"HKCU prefix":        []map[string]string{{"key": `HKCU\Software\X`, "name": "A"}},
		"HKEY_USERS prefix":  []map[string]string{{"key": `HKEY_USERS\S-1-5-18\X`, "name": "A"}},
		"provider path":      []map[string]string{{"key": `HKCU:\Software\X`, "name": "A"}},
		"dotdot":             []map[string]string{{"key": `SOFTWARE\..\SAM`, "name": "A"}},
		"empty key":          []map[string]string{{"key": "", "name": "A"}},
		"empty name":         []map[string]string{{"key": `SOFTWARE\X`, "name": ""}},
		"empty segment":      []map[string]string{{"key": `SOFTWARE\\X`, "name": "A"}},
		"mid wildcard":       []map[string]string{{"key": `SOFTWARE\*\X`, "name": "A"}},
		"control char":       []map[string]string{{"key": "SOFTWARE\\X\n", "name": "A\x00"}},
		"not an array":       map[string]string{"key": `SOFTWARE\X`, "name": "A"},
		"long key":           []map[string]string{{"key": `SOFTWARE\` + strings.Repeat("a", 600), "name": "A"}},
		"too many entries":   make([]map[string]string, MaxExtraRegistryValues+1),
		"hklm alone as path": []map[string]string{{"key": `HKLM`, "name": "A"}},
	}
	for name, v := range cases {
		if name == "too many entries" {
			list := v.([]map[string]string)
			for i := range list {
				list[i] = map[string]string{"key": fmt.Sprintf(`SOFTWARE\K%d`, i), "name": "V"}
			}
		}
		b, _ := json.Marshal(v)
		arg := base64.RawURLEncoding.EncodeToString(b)
		if name == "too many entries" {
			// Too long for the inline form; use the file form to hit the count limit.
			p := filepath.Join(t.TempDir(), "values.json")
			if err := os.WriteFile(p, b, 0o600); err != nil {
				t.Fatal(err)
			}
			arg = "@" + p
		}
		if _, err := ParseRegistryValuesArg(arg); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if _, err := ParseRegistryValuesArg("!!!not base64!!!"); err == nil {
		t.Error("bad base64 accepted")
	}
	if _, err := ParseRegistryValuesArg(strings.Repeat("A", MaxRegistryValuesArgLen+1)); err == nil || !strings.Contains(err.Error(), "@<file>") {
		t.Errorf("long inline arg: %v", err)
	}
	if _, err := ParseRegistryValuesArg("@" + filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Error("missing file accepted")
	}
}

func TestParseRegistryValuesFile(t *testing.T) {
	list := make([]map[string]string, MaxExtraRegistryValues)
	for i := range list {
		list[i] = map[string]string{"key": fmt.Sprintf(`SOFTWARE\Policies\Microsoft\Windows\K%d`, i), "name": "V"}
	}
	b, _ := json.Marshal(list)
	dir := t.TempDir()
	plain := filepath.Join(dir, "plain.json")
	encoded := filepath.Join(dir, "encoded.txt")
	if err := os.WriteFile(plain, append([]byte("\ufeff"), b...), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(encoded, []byte(base64.RawURLEncoding.EncodeToString(b)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{plain, encoded} {
		specs, err := ParseRegistryValuesArg("@" + p)
		if err != nil || len(specs) != MaxExtraRegistryValues {
			t.Fatalf("%s: %v (%d)", p, err, len(specs))
		}
	}
	big := filepath.Join(dir, "big.json")
	if err := os.WriteFile(big, make([]byte, maxRegistryValuesFileBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseRegistryValuesArg("@" + big); err == nil {
		t.Fatal("oversized file accepted")
	}
}

func TestRequirePowerShell3(t *testing.T) {
	oldFn, oldMajor := probePSMajorFn, psVersionMajor
	t.Cleanup(func() { probePSMajorFn, psVersionMajor = oldFn, oldMajor })

	psVersionMajor = 0
	probePSMajorFn = func(context.Context) (int, error) { return 2, nil }
	_, err := runPowerShell(context.Background(), "'x' | ConvertTo-Json")
	if !errors.Is(err, errPowerShellTooOld) || !strings.Contains(err.Error(), "PowerShell 3.0 or later required") {
		t.Fatalf("PS 2.0: %v", err)
	}

	psVersionMajor = 0
	probePSMajorFn = func(context.Context) (int, error) { return 5, nil }
	if err := requirePowerShell3(context.Background()); err != nil {
		t.Fatalf("PS 5: %v", err)
	}

	// A failed probe does not block (the real call reports its own error) and is retried.
	psVersionMajor = 0
	calls := 0
	probePSMajorFn = func(context.Context) (int, error) { calls++; return 0, errors.New("no powershell") }
	_ = requirePowerShell3(context.Background())
	_ = requirePowerShell3(context.Background())
	if calls != 2 {
		t.Fatalf("probe calls=%d", calls)
	}
}

func TestParsePSMajor(t *testing.T) {
	for in, want := range map[string]int{"5\r\n": 5, "2": 2, " 1 ": 1} {
		if got, err := parsePSMajor(in); err != nil || got != want {
			t.Fatalf("%q: %d %v", in, got, err)
		}
	}
	if _, err := parsePSMajor(""); err == nil {
		t.Fatal("empty accepted")
	}
}
