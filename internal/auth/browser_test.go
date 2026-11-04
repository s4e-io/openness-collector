package auth

import (
	"os/user"
	"testing"
)

func TestDesktopUserPrefersSudoUser(t *testing.T) {
	t.Setenv("SUDO_USER", "nobody")
	t.Setenv("PKEXEC_UID", "")
	u, err := desktopUser()
	if err != nil {
		// "nobody" may not exist on all systems; accept lookup failure only if user missing
		if _, lerr := user.Lookup("nobody"); lerr != nil {
			t.Skip("nobody user not present")
		}
		t.Fatal(err)
	}
	if u.Username != "nobody" {
		t.Fatalf("got %q", u.Username)
	}
}

func TestDesktopUserSkipsRootName(t *testing.T) {
	t.Setenv("SUDO_USER", "root")
	// Without another candidate this should fail rather than return root.
	if u, err := desktopUser(); err == nil && u.Username == "root" {
		t.Fatal("must not return root as desktop user")
	}
}
