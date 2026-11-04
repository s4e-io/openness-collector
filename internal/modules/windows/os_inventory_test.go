package windows

import (
	"context"
	"fmt"
	"testing"
)

func TestNormalizeWindowsOSIdentityServer2022(t *testing.T) {
	raw := map[string]any{
		"product_name":      "Microsoft Windows Server 2022 Datacenter",
		"version":           "10.0.20348",
		"build_number":      "20348",
		"ubr":               float64(169),
		"display_version":   "21H2",
		"release_id":        "2009",
		"installation_type": "Server",
		"architecture":      "AMD64",
		"hostname":          "TESTHOST",
	}
	got := normalizeWindowsOSIdentity(raw)
	if got["distribution_id"] != "windows" {
		t.Fatalf("distribution_id=%v", got["distribution_id"])
	}
	if got["version_id"] != "21H2" {
		t.Fatalf("version_id=%v", got["version_id"])
	}
	if got["pretty_name"] != "Microsoft Windows Server 2022 Datacenter" {
		t.Fatalf("pretty_name=%v", got["pretty_name"])
	}
	if got["architecture"] != "amd64" {
		t.Fatalf("architecture=%v", got["architecture"])
	}
	if got["os_build"] != "20348.169" {
		t.Fatalf("os_build=%v", got["os_build"])
	}
	if got["variant"] != "Server" {
		t.Fatalf("variant=%v", got["variant"])
	}
	// Preserve original Windows fields.
	if got["product_name"] != raw["product_name"] || got["build_number"] != raw["build_number"] {
		t.Fatalf("lost original fields: %v", got)
	}
}

func TestNormalizeWindowsOSIdentityFallsBackWithoutDisplayVersion(t *testing.T) {
	got := normalizeWindowsOSIdentity(map[string]any{
		"product_name": "Windows 10 Pro",
		"version":      "10.0.19041",
		"build_number": "19041",
		"release_id":   "2009",
		"architecture": "x86",
	})
	if got["version_id"] != "2009" {
		t.Fatalf("version_id=%v want release_id", got["version_id"])
	}
	if got["architecture"] != "386" {
		t.Fatalf("architecture=%v", got["architecture"])
	}
}

func TestNormalizeWindowsOSIdentityVersionOnlyLeavesVersionIDNull(t *testing.T) {
	got := normalizeWindowsOSIdentity(map[string]any{
		"version": "10.0.22621",
	})
	if got["distribution_id"] != "windows" {
		t.Fatalf("distribution_id=%v", got["distribution_id"])
	}
	if got["version_id"] != nil {
		t.Fatalf("version_id=%v want null (do not invent 10.0)", got["version_id"])
	}
	if got["pretty_name"] != nil {
		t.Fatalf("pretty_name=%v want null without product_name", got["pretty_name"])
	}
}

func TestWindowsOSIdentityComplete(t *testing.T) {
	if windowsOSIdentityComplete(map[string]any{"version": "10.0.20348", "build_number": "20348"}) {
		t.Fatal("missing product_name must be incomplete")
	}
	if !windowsOSIdentityComplete(map[string]any{
		"product_name": "Microsoft Windows Server 2022 Datacenter", "build_number": "20348",
	}) {
		t.Fatal("product+build should be complete")
	}
}

func TestMergeOSIdentityLayersFillsProductName(t *testing.T) {
	merged := map[string]any{}
	for k, v := range map[string]any{"version": "10.0.20348", "build_number": "20348", "display_version": "21H2"} {
		if isEmptyOSValue(merged[k]) && !isEmptyOSValue(v) {
			merged[k] = v
		}
	}
	for k, v := range map[string]any{"product_name": "Microsoft Windows Server 2022 Datacenter", "build_number": "20348"} {
		if isEmptyOSValue(merged[k]) && !isEmptyOSValue(v) {
			merged[k] = v
		}
	}
	if !windowsOSIdentityComplete(merged) {
		t.Fatalf("merged incomplete: %#v", merged)
	}
	got := normalizeWindowsOSIdentity(merged)
	if got["pretty_name"] != "Microsoft Windows Server 2022 Datacenter" {
		t.Fatalf("%v", got["pretty_name"])
	}
}

func TestNormalizeWindowsArch(t *testing.T) {
	cases := map[string]string{
		"AMD64": "amd64",
		"x64":   "amd64",
		"ARM64": "arm64",
		"x86":   "386",
		"":      "",
	}
	for in, want := range cases {
		if got := normalizeWindowsArch(in); got != want {
			t.Fatalf("%q -> %q want %q", in, got, want)
		}
	}
}

func TestOSInventoryRunUsesNativeRegistryFallback(t *testing.T) {
	oldID, oldPS := collectOSIdentity, collectOSViaPowerShellFn
	collectOSViaPowerShellFn = func(context.Context, string) (map[string]any, error) {
		return nil, fmt.Errorf("powershell disabled in hermetic test")
	}
	collectOSIdentity = func() (map[string]any, error) {
		return map[string]any{
			"product_name":    "Microsoft Windows Server 2022 Datacenter",
			"version":         "10.0.20348",
			"build_number":    "20348",
			"ubr":             "169",
			"display_version": "21H2",
			"architecture":    "AMD64",
			"hostname":        "FALLBACKHOST",
		}, nil
	}
	t.Cleanup(func() {
		collectOSIdentity = oldID
		collectOSViaPowerShellFn = oldPS
	})

	res := (&OSInventory{}).Run(context.Background())
	if len(res.Evidence) != 1 {
		t.Fatalf("evidence=%d status=%s errors=%v", len(res.Evidence), res.Status, res.Errors)
	}
	v := res.Evidence[0].Value.(map[string]any)
	if v["distribution_id"] != "windows" || v["version_id"] != "21H2" {
		t.Fatalf("%v", v)
	}
	raw := res.Evidence[0].RawValue.(map[string]string)
	if raw["source"] != "native_registry" {
		t.Fatalf("source=%q want native_registry", raw["source"])
	}
	if res.Status != "partial" {
		t.Fatalf("status=%s want partial for fallback", res.Status)
	}
}
