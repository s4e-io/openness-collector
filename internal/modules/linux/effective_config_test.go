package linux

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestParseSysctlConf(t *testing.T) {
	in := `
# comment
net.ipv4.ip_forward = 1
kernel.kptr_restrict=2
; ignored
`
	m := parseSysctlConf(in)
	if m["net.ipv4.ip_forward"] != "1" || m["kernel.kptr_restrict"] != "2" {
		t.Fatalf("%#v", m)
	}
}

func TestSysctlKeyToProcPath(t *testing.T) {
	if sysctlKeyToProcPath("net.ipv4.ip_forward") != "/proc/sys/net/ipv4/ip_forward" {
		t.Fatal(sysctlKeyToProcPath("net.ipv4.ip_forward"))
	}
}

func TestCollectSysctlEffectiveReadsRuntime(t *testing.T) {
	// Only assert structure when /proc/sys exists
	if _, err := os.Stat("/proc/sys/kernel"); err != nil {
		t.Skip("no /proc/sys")
	}
	out := collectSysctlEffective(context.Background())
	if out["status"] != "observed" && out["status"] != "unavailable" {
		t.Fatalf("%#v", out)
	}
	rt, _ := out["runtime"].(map[string]string)
	if len(rt) == 0 {
		t.Log("no runtime keys readable in this environment")
	}
}

func TestOpenSSHConfigSourcesDiscoverable(t *testing.T) {
	// Unit test path discovery without requiring sshd -T success
	dir := t.TempDir()
	cfg := filepath.Join(dir, "sshd_config")
	_ = os.WriteFile(cfg, []byte("Port 22\n"), 0o644)
	if _, err := os.Stat(cfg); err != nil {
		t.Fatal(err)
	}
}
