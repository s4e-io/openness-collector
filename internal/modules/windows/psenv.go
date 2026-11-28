package windows

import (
	"os"
	"strings"
)

// powerShellEnv is the environment of a powershell.exe child: the collector's own, with the
// PowerShell 7 module folders taken out of PSModulePath. Started from PowerShell 7 (pwsh, or
// an SSH session whose shell is pwsh), the collector inherits a PSModulePath that lists
// PowerShell 7's modules first; Windows PowerShell 5.1 then finds the PowerShell 7 copy of
// Microsoft.PowerShell.Security, cannot load it, and Get-AuthenticodeSignature fails
// ("found in the module ... but the module could not be loaded"). Windows PowerShell's
// own module folder is always kept.
func powerShellEnv() []string {
	return withWindowsPSModulePath(os.Environ(), os.Getenv("SystemRoot"))
}

func withWindowsPSModulePath(env []string, systemRoot string) []string {
	if systemRoot == "" {
		systemRoot = `C:\Windows`
	}
	system := systemRoot + `\system32\WindowsPowerShell\v1.0\Modules`
	out := make([]string, 0, len(env)+1)
	var cur string
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok && strings.EqualFold(k, "PSModulePath") {
			cur = v
			continue
		}
		out = append(out, kv)
	}
	keep := []string{system}
	seen := map[string]bool{strings.ToLower(system): true}
	for _, p := range strings.Split(cur, ";") {
		p = strings.TrimSpace(p)
		low := strings.ToLower(strings.TrimRight(p, `\`))
		if p == "" || seen[low] || isPowerShell7Modules(low) {
			continue
		}
		seen[low] = true
		keep = append(keep, p)
	}
	return append(out, "PSModulePath="+strings.Join(keep, ";"))
}

// isPowerShell7Modules says a (lower case) PSModulePath entry is a PowerShell 7 folder:
// %ProgramFiles%\PowerShell\Modules, %ProgramFiles%\PowerShell\7\Modules, the user's
// Documents\PowerShell\Modules. Windows PowerShell uses WindowsPowerShell in the name.
func isPowerShell7Modules(p string) bool {
	if strings.Contains(p, `\windowspowershell\`) || strings.HasSuffix(p, `\windowspowershell`) {
		return false
	}
	return strings.Contains(p, `\powershell\`)
}
