package linux

import "testing"

func TestIsInterestingLibrary(t *testing.T) {
	if !isInterestingLibrary("/lib/aarch64-linux-gnu/libc.so.6") {
		t.Fatal("libc")
	}
	if !isInterestingLibrary("/usr/lib/libssl.so.3") {
		t.Fatal("ssl")
	}
	if !isInterestingLibrary("/usr/lib/libcrypto.so.3 (deleted)") {
		t.Fatal("deleted crypto")
	}
	if isInterestingLibrary("/usr/lib/libobscurething.so.1") {
		t.Fatal("should not flag obscure")
	}
}

func TestParseProcMapsFromString(t *testing.T) {
	in := `
7ffff7dd6000-7ffff7dfd000 r--p 00000000 fe:01 123 /usr/lib/libc.so.6
7ffff7dfd000-7ffff7f52000 r-xp 00027000 fe:01 123 /usr/lib/libc.so.6
7ffff7f52000-7ffff7fa8000 r--p 0017c000 fe:01 123 /usr/lib/libc.so.6
7ffff7fc5000-7ffff7fc7000 r--p 00000000 00:00 0  [vvar]
7ffff8000000-7ffff8200000 rw-p 00000000 00:00 0  [heap]
7ffff8300000-7ffff8400000 r-xp 00000000 fe:01 999 /usr/lib/libssl.so.3 (deleted)
`
	paths, meta := parseProcMapsContent(in)
	if len(paths) != 2 {
		t.Fatalf("unique paths %#v meta %#v", paths, meta)
	}
	if paths[1] != "/usr/lib/libssl.so.3 (deleted)" {
		t.Fatalf("%#v", paths)
	}
	if meta["so_count"] != 4 {
		t.Fatalf("so_count %#v", meta["so_count"])
	}
}

func TestParseProcMapsStaticHeuristic(t *testing.T) {
	in := `
00400000-00401000 r-xp 00000000 fe:01 1 /usr/bin/staticbin
00600000-00601000 rw-p 00000000 fe:01 1 /usr/bin/staticbin
`
	paths, meta := parseProcMapsContent(in)
	if len(paths) != 0 {
		t.Fatalf("%#v", paths)
	}
	if meta["statically_linked"] != true {
		t.Fatalf("%#v", meta)
	}
}
