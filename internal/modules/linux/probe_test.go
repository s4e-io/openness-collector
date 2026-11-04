package linux

import "testing"

func TestLooksLikePermissionDenied(t *testing.T) {
	cases := map[string]bool{
		"ERROR: You need to be root to run this script\n": true,
		"permission denied":       true,
		"active":                  false,
		"inactive":                false,
		"Operation not permitted": true,
	}
	for in, want := range cases {
		if got := looksLikePermissionDenied(in); got != want {
			t.Fatalf("%q: got %v want %v", in, got, want)
		}
	}
}
