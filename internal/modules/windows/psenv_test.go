package windows

import (
	"strings"
	"testing"
)

func TestWindowsPSModulePath(t *testing.T) {
	env := []string{"PATH=C:\\x", `PSModulePath=C:\Users\runneradmin\Documents\PowerShell\Modules;C:\Program Files\PowerShell\Modules;c:\program files\powershell\7\Modules;C:\Program Files\WindowsPowerShell\Modules;C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules;C:\Modules\az`}
	got := withWindowsPSModulePath(env, `C:\WINDOWS`)
	var mp string
	for _, kv := range got {
		if strings.HasPrefix(kv, "PSModulePath=") {
			mp = strings.TrimPrefix(kv, "PSModulePath=")
		}
	}
	want := `C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules;C:\Program Files\WindowsPowerShell\Modules;C:\Modules\az`
	if mp != want {
		t.Fatalf("PSModulePath\n got %s\nwant %s", mp, want)
	}
	if got[0] != `PATH=C:\x` || len(got) != 2 {
		t.Fatalf("env %v", got)
	}
	// Without a PSModulePath, Windows PowerShell's own folder is set.
	if got := withWindowsPSModulePath([]string{"A=1"}, ""); got[1] != `PSModulePath=C:\Windows\system32\WindowsPowerShell\v1.0\Modules` {
		t.Fatalf("empty: %v", got)
	}
}
