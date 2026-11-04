//go:build windows

package windows

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows/registry"
)

// readOSIdentityFromRegistry reads HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion
// without PowerShell/CIM. Used when both PowerShell collection paths fail.
func readOSIdentityFromRegistry() (map[string]any, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return nil, fmt.Errorf("open CurrentVersion: %w", err)
	}
	defer k.Close()

	get := func(name string) string {
		v, _, err := k.GetStringValue(name)
		if err != nil {
			// Some values are DWORD (UBR).
			if n, _, err2 := k.GetIntegerValue(name); err2 == nil {
				return fmt.Sprintf("%d", n)
			}
			return ""
		}
		return v
	}

	product := get("ProductName")
	if product == "" {
		product = get("EditionID")
	}
	out := map[string]any{
		"product_name": product,
		// CurrentVersion (e.g. "6.3") is not a real OS version on modern Windows; leave null.
		"version":           nil,
		"build_number":      get("CurrentBuild"),
		"ubr":               get("UBR"),
		"display_version":   get("DisplayVersion"),
		"release_id":        get("ReleaseId"),
		"installation_type": get("InstallationType"),
		"architecture":      os.Getenv("PROCESSOR_ARCHITECTURE"),
		"hostname":          os.Getenv("COMPUTERNAME"),
		"fqdn":              os.Getenv("COMPUTERNAME"),
	}

	if ck, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE); err == nil {
		if guid, _, err := ck.GetStringValue("MachineGuid"); err == nil {
			out["machine_id"] = guid
		}
		_ = ck.Close()
	}

	if !hasWindowsOSSignal(out) {
		return out, fmt.Errorf("CurrentVersion registry keys empty")
	}
	return out, nil
}
