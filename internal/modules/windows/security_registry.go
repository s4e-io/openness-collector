package windows

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"unicode"
)

// RegistryValueSpec is one HKLM value the security_configuration module reads.
//
// Key is the path under HKLM without the hive prefix. A key ending in `\*`
// is a subkey wildcard: one entry is emitted per existing subkey, with the
// concrete key path and `pattern` set to Key.
//
// PresenceOnly values (secrets) are never read: only their existence is
// recorded and `value` is always null.
type RegistryValueSpec struct {
	Key          string `json:"key"`
	Name         string `json:"name"`
	PresenceOnly bool   `json:"presence_only,omitempty"`
}

const registryWildcardSuffix = `\*`

func (s RegistryValueSpec) wildcard() bool {
	return strings.HasSuffix(s.Key, registryWildcardSuffix)
}

func regValues(key string, names ...string) []RegistryValueSpec {
	out := make([]RegistryValueSpec, 0, len(names))
	for _, n := range names {
		out = append(out, RegistryValueSpec{Key: key, Name: n})
	}
	return out
}

const schannelRoot = `SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL`

// securityRegistrySpecs is the single table of registry values emitted under
// security_configuration.registry. Extend it here; the PowerShell receives it
// as data and has no list of its own.
var securityRegistrySpecs = buildSecurityRegistrySpecs()

func buildSecurityRegistrySpecs() []RegistryValueSpec {
	var s []RegistryValueSpec
	add := func(specs ...RegistryValueSpec) { s = append(s, specs...) }

	add(regValues(`SYSTEM\CurrentControlSet\Control\Lsa`,
		"RunAsPPL", "LmCompatibilityLevel", "NoLMHash", "RestrictAnonymous", "RestrictAnonymousSAM",
		"EveryoneIncludesAnonymous", "DisableDomainCreds", "LsaCfgFlags")...)
	add(regValues(`SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest`, "UseLogonCredential")...)
	add(regValues(`SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management`,
		"FeatureSettingsOverride", "FeatureSettingsOverrideMask")...)
	add(regValues(`SYSTEM\CurrentControlSet\Control\Session Manager`, "CWDIllegalInDllSearch", "SafeDllSearchMode")...)
	add(regValues(`SOFTWARE\Policies\Microsoft\Windows NT\DNSClient`, "EnableMulticast")...)
	add(regValues(`SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\*`, "NetbiosOptions")...)
	add(regValues(`SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint`,
		"RestrictDriverInstallationToAdministrators", "NoWarningNoElevationOnInstall", "UpdatePromptSettings")...)
	add(regValues(`SYSTEM\CurrentControlSet\Services\Netlogon\Parameters`,
		"FullSecureChannelProtection", "RequireSignOrSeal", "VulnerableChannelAllowList")...)
	add(regValues(`SYSTEM\CurrentControlSet\Services\NTDS\Parameters`, "LDAPServerIntegrity", "LdapEnforceChannelBinding")...)
	for _, root := range []string{`SOFTWARE\Microsoft`, `SOFTWARE\Wow6432Node\Microsoft`} {
		add(regValues(root+`\Internet Explorer\Main\FeatureControl\FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING`, "iexplore.exe")...)
	}
	add(regValues(`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer`, "NoDriveTypeAutoRun", "NoAutorun")...)
	add(regValues(`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`,
		"EnableLUA", "LocalAccountTokenFilterPolicy", "ConsentPromptBehaviorAdmin")...)
	add(regValues(`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters`, "AllowEncryptionOracle")...)
	add(regValues(`SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`,
		"RequireSecuritySignature", "EnableSecuritySignature", "SMB1", "RestrictNullSessAccess", "NullSessionShares")...)
	add(regValues(`SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters`,
		"RequireSecuritySignature", "EnablePlainTextPassword")...)
	add(regValues(`SYSTEM\CurrentControlSet\Services\mrxsmb10`, "Start")...)
	for _, proto := range []string{"SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"} {
		add(regValues(schannelRoot+`\Protocols\`+proto+`\Server`, "Enabled", "DisabledByDefault")...)
	}
	for _, cipher := range []string{"RC4 128/128", "RC4 64/128", "RC4 56/128", "RC4 40/128", "Triple DES 168", "DES 56/56", "NULL"} {
		add(regValues(schannelRoot+`\Ciphers\`+cipher, "Enabled")...)
	}
	add(regValues(schannelRoot+`\Hashes\MD5`, "Enabled")...)
	add(regValues(schannelRoot+`\KeyExchangeAlgorithms\Diffie-Hellman`, "ServerMinKeyBitLength")...)
	add(regValues(`SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002`, "Functions")...)
	for _, root := range []string{`SOFTWARE\Microsoft`, `SOFTWARE\Wow6432Node\Microsoft`} {
		add(regValues(root+`\.NETFramework\v4.0.30319`, "SchUseStrongCrypto", "SystemDefaultTlsVersions")...)
	}
	winlogon := `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`
	add(regValues(winlogon, "AutoAdminLogon")...)
	add(RegistryValueSpec{Key: winlogon, Name: "DefaultPassword", PresenceOnly: true})
	add(regValues(winlogon, "CachedLogonsCount")...)
	add(regValues(`SOFTWARE\Policies\Microsoft\Windows\WinRM\Service`, "AllowBasic", "AllowUnencryptedTraffic")...)
	add(regValues(`SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`,
		"SecurityLayer", "MinEncryptionLevel", "UserAuthentication")...)
	for _, root := range []string{`SOFTWARE\Microsoft`, `SOFTWARE\Wow6432Node\Microsoft`} {
		add(regValues(root+`\Cryptography\Wintrust\Config`, "EnableCertPaddingCheck")...)
	}
	add(regValues(`SYSTEM\CurrentControlSet\Services\Spooler`, "Start")...)
	return s
}

const registrySpecPathPlaceholder = "__OPENNESS_REGISTRY_SPEC_PATH__"

// registrySpecJSON is the list as compact JSON. The script reads it from a
// temp file: inlined, a large --registry-values list would push the
// powershell.exe command line past the 32767 character CreateProcess limit.
func registrySpecJSON(specs []RegistryValueSpec) string {
	b, err := json.Marshal(specs)
	if err != nil {
		// A slice of plain structs cannot fail to marshal.
		panic(err)
	}
	return string(b)
}

// psSingleQuote quotes s as a PowerShell single-quoted string literal.
func psSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// registryNotReported is the entry used when the script did not report a
// listed value at all. It carries an error so it reads as "not collected",
// never as "not set".
func registryNotReported(spec RegistryValueSpec) map[string]any {
	e := map[string]any{
		"key":     spec.Key,
		"name":    spec.Name,
		"hive":    "HKLM",
		"present": false,
		"type":    nil,
		"value":   nil,
		"error":   "not_reported",
	}
	if spec.wildcard() {
		e["pattern"] = spec.Key
	}
	return e
}

// normalizeRegistryEntries turns the raw `registry` array from PowerShell into
// the emitted list: table order, every listed value exactly once (wildcards:
// once per concrete subkey, or one placeholder), presence-only values with
// value forced to null, and rows that are not in the table dropped.
func normalizeRegistryEntries(raw any, specs []RegistryValueSpec) []any {
	var rows []map[string]any
	switch t := raw.(type) {
	case []any:
		for _, r := range t {
			if m, ok := r.(map[string]any); ok {
				rows = append(rows, m)
			}
		}
	case map[string]any:
		// ConvertTo-Json may collapse a one-element array into an object.
		rows = append(rows, t)
	}

	out := make([]any, 0, len(specs))
	for _, spec := range specs {
		var matched []map[string]any
		seen := map[string]bool{}
		for _, r := range rows {
			if !strings.EqualFold(asString(r["name"]), spec.Name) {
				continue
			}
			key := asString(r["key"])
			if spec.wildcard() {
				pattern := asString(r["pattern"])
				if !strings.EqualFold(pattern, spec.Key) && !strings.EqualFold(key, spec.Key) {
					continue
				}
			} else if !strings.EqualFold(key, spec.Key) {
				continue
			}
			lk := strings.ToLower(key)
			if seen[lk] {
				continue
			}
			seen[lk] = true
			matched = append(matched, r)
			if !spec.wildcard() {
				break
			}
		}
		if len(matched) == 0 {
			out = append(out, registryNotReported(spec))
			continue
		}
		for _, r := range matched {
			out = append(out, cleanRegistryEntry(r, spec))
		}
	}
	return out
}

func cleanRegistryEntry(r map[string]any, spec RegistryValueSpec) map[string]any {
	e := map[string]any{
		"key":     asString(r["key"]),
		"name":    spec.Name,
		"hive":    "HKLM",
		"present": asBool(r["present"]),
		"type":    nullIfEmpty(asString(r["type"])),
		"value":   r["value"],
	}
	if spec.wildcard() {
		e["pattern"] = spec.Key
	}
	if msg := asString(r["error"]); msg != "" {
		e["error"] = msg
		e["present"] = false
		e["value"] = nil
	}
	if e["present"] == false {
		e["value"] = nil
	}
	if spec.PresenceOnly {
		e["value"] = nil
	}
	return e
}

// Limits for run-time registry requests (collect --registry-values).
const (
	// MaxExtraRegistryValues caps the number of requested entries.
	MaxExtraRegistryValues = 1000
	// MaxRegistryValuesArgLen caps the inline base64url argument. cmd.exe
	// rejects command lines over 8191 characters; remote shells usually go
	// through it, so longer lists must be passed as @<file>.
	MaxRegistryValuesArgLen = 7000
	// maxRegistryValuesFileBytes caps the @<file> form.
	maxRegistryValuesFileBytes = 1 << 20
	maxRegistryKeyLen          = 512
	maxRegistryNameLen         = 256
)

var otherHiveNames = map[string]bool{"HKLM": true, "HKCU": true, "HKU": true, "HKCR": true, "HKCC": true}

var hklmPrefixes = []string{`HKLM:\`, `HKLM\`, `HKEY_LOCAL_MACHINE\`}

// ParseRegistryValuesArg parses the collect --registry-values argument: either
// base64url (padding optional) of a JSON array, or @<path> to a file holding
// that JSON array (plain or base64url). Each element is
// {"key": "SYSTEM\\...", "name": "Value"} with optional "hive": "HKLM" and
// "presence_only": true. HKLM only. Sensitive names are forced presence-only.
func ParseRegistryValuesArg(arg string) ([]RegistryValueSpec, error) {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return nil, nil
	}
	var payload []byte
	if strings.HasPrefix(arg, "@") {
		path := arg[1:]
		st, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("registry values file: %w", err)
		}
		if st.Size() > maxRegistryValuesFileBytes {
			return nil, fmt.Errorf("registry values file is %d bytes, limit %d", st.Size(), maxRegistryValuesFileBytes)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("registry values file: %w", err)
		}
		payload = []byte(strings.TrimSpace(strings.TrimPrefix(string(b), "\ufeff")))
		if len(payload) > 0 && payload[0] != '[' {
			if payload, err = decodeBase64URL(string(payload)); err != nil {
				return nil, err
			}
		}
	} else {
		if len(arg) > MaxRegistryValuesArgLen {
			return nil, fmt.Errorf("registry values argument is %d characters, limit %d; pass @<file> instead", len(arg), MaxRegistryValuesArgLen)
		}
		var err error
		if payload, err = decodeBase64URL(arg); err != nil {
			return nil, err
		}
	}
	return parseRegistryValuesJSON(payload)
}

func decodeBase64URL(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("registry values: not valid base64url")
}

type registryValueRequest struct {
	Hive         string `json:"hive"`
	Key          string `json:"key"`
	Name         string `json:"name"`
	PresenceOnly bool   `json:"presence_only"`
}

func parseRegistryValuesJSON(b []byte) ([]RegistryValueSpec, error) {
	var reqs []registryValueRequest
	if err := json.Unmarshal(b, &reqs); err != nil {
		return nil, fmt.Errorf("registry values: JSON array expected: %w", err)
	}
	if len(reqs) > MaxExtraRegistryValues {
		return nil, fmt.Errorf("registry values: %d entries, limit %d", len(reqs), MaxExtraRegistryValues)
	}
	out := make([]RegistryValueSpec, 0, len(reqs))
	for i, r := range reqs {
		spec, err := validateRegistryRequest(r)
		if err != nil {
			return nil, fmt.Errorf("registry values[%d]: %w", i, err)
		}
		out = append(out, spec)
	}
	return mergeRegistrySpecs(nil, out), nil
}

func validateRegistryRequest(r registryValueRequest) (RegistryValueSpec, error) {
	if h := strings.TrimSpace(r.Hive); h != "" && !strings.EqualFold(h, "HKLM") && !strings.EqualFold(h, "HKEY_LOCAL_MACHINE") {
		return RegistryValueSpec{}, fmt.Errorf("hive %q not allowed, HKLM only", h)
	}
	key := strings.TrimSpace(r.Key)
	for _, p := range hklmPrefixes {
		if len(key) >= len(p) && strings.EqualFold(key[:len(p)], p) {
			key = key[len(p):]
			break
		}
	}
	first := strings.ToUpper(strings.SplitN(strings.TrimLeft(key, `\`), `\`, 2)[0])
	if strings.HasPrefix(first, "HKEY_") || strings.Contains(first, ":") || otherHiveNames[first] {
		return RegistryValueSpec{}, fmt.Errorf("key %q: HKLM only", r.Key)
	}
	key = strings.Trim(key, `\`)
	name := r.Name
	switch {
	case key == "":
		return RegistryValueSpec{}, errors.New("key is empty")
	case len(key) > maxRegistryKeyLen:
		return RegistryValueSpec{}, fmt.Errorf("key longer than %d characters", maxRegistryKeyLen)
	case strings.Contains(key, ".."):
		return RegistryValueSpec{}, fmt.Errorf("key %q must not contain ..", r.Key)
	case strings.Contains(key, `\\`):
		return RegistryValueSpec{}, fmt.Errorf("key %q has an empty path segment", r.Key)
	case hasControlChar(key) || hasControlChar(name):
		return RegistryValueSpec{}, errors.New("control characters are not allowed")
	case name == "":
		return RegistryValueSpec{}, errors.New("name is empty")
	case len(name) > maxRegistryNameLen:
		return RegistryValueSpec{}, fmt.Errorf("name longer than %d characters", maxRegistryNameLen)
	}
	if i := strings.Index(key, "*"); i >= 0 && !(i == len(key)-1 && strings.HasSuffix(key, registryWildcardSuffix)) {
		return RegistryValueSpec{}, fmt.Errorf("key %q: * is only allowed as the last path segment", r.Key)
	}
	return RegistryValueSpec{Key: key, Name: name, PresenceOnly: r.PresenceOnly}, nil
}

func hasControlChar(s string) bool {
	for _, c := range s {
		if unicode.IsControl(c) {
			return true
		}
	}
	return false
}

// Keys whose secret-looking values are recorded as presence only.
var sensitiveRegistryKeyPrefixes = []string{
	`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`,
	`SECURITY\Policy\Secrets`,
	`SYSTEM\CurrentControlSet\Control\Lsa`,
}

// isSensitiveRegistryValue reports whether a value must never be read: any
// name containing "password", anything under the SECURITY hive key, and names
// containing "secret" or "key" under Winlogon / LSA.
func isSensitiveRegistryValue(key, name string) bool {
	k := strings.ToLower(key)
	n := strings.ToLower(name)
	if strings.Contains(n, "password") {
		return true
	}
	if k == "security" || strings.HasPrefix(k, `security\`) {
		return true
	}
	for _, p := range sensitiveRegistryKeyPrefixes {
		lp := strings.ToLower(p)
		if k == lp || strings.HasPrefix(k, lp+`\`) {
			if strings.Contains(n, "secret") || strings.Contains(n, "key") {
				return true
			}
		}
	}
	return false
}

// mergeRegistrySpecs returns base followed by the extras not already listed
// (key and name compared case-insensitively). Sensitive values are forced
// presence-only; a duplicate that asks for presence-only wins.
func mergeRegistrySpecs(base, extra []RegistryValueSpec) []RegistryValueSpec {
	out := make([]RegistryValueSpec, 0, len(base)+len(extra))
	idx := map[string]int{}
	for _, list := range [][]RegistryValueSpec{base, extra} {
		for _, s := range list {
			s.PresenceOnly = s.PresenceOnly || isSensitiveRegistryValue(s.Key, s.Name)
			id := strings.ToLower(s.Key) + "\x00" + strings.ToLower(s.Name)
			if i, ok := idx[id]; ok {
				out[i].PresenceOnly = out[i].PresenceOnly || s.PresenceOnly
				continue
			}
			idx[id] = len(out)
			out = append(out, s)
		}
	}
	return out
}
