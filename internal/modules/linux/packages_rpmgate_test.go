package linux

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRPMDatabasePresent(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "rpmdb.sqlite")
	if rpmDatabasePresent([]string{db}) {
		t.Fatal("missing database must not enable rpm")
	}
	if err := os.Mkdir(db, 0o755); err != nil {
		t.Fatal(err)
	}
	if rpmDatabasePresent([]string{db}) {
		t.Fatal("a directory is not a database")
	}
	other := filepath.Join(dir, "Packages")
	if err := os.WriteFile(other, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !rpmDatabasePresent([]string{db, other}) {
		t.Fatal("an existing database file enables rpm")
	}
}
