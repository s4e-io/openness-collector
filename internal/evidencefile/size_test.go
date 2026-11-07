package evidencefile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/s4e-io/openness-collector/internal/schema"
)

func TestWriteTooLargeIsTypedAndWritesNothing(t *testing.T) {
	old := maxOutputBytes
	maxOutputBytes = 64
	t.Cleanup(func() { maxOutputBytes = old })
	path := filepath.Join(t.TempDir(), "x.openness")
	doc := &schema.Document{SchemaVersion: "1", Modules: []schema.ModuleResult{}}
	if _, err := Write(path, doc, false); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err=%v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("file written: %v", err)
	}
}
