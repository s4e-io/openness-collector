package collect_test

import (
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/s4e-io/openness-collector/internal/collect"
)

func TestForceFailProducesPartial(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" && runtime.GOOS != "darwin" {
		t.Skip("unsupported GOOS")
	}
	mods := []string{"os_inventory"}
	fail := "os_inventory"
	if runtime.GOOS == "darwin" {
		// darwin may have no native modules without osquery; skip if empty registry
		eng := collect.New(collect.Options{})
		if len(eng.ListModules()) == 0 {
			t.Skip("no modules on darwin without osquery")
		}
		mods = nil
		fail = eng.ListModules()[0].ID()
	}
	opts := collect.Options{
		Modules:          mods,
		ForceFailModules: []string{fail},
		Timeout:          30 * time.Second,
		ModuleTimeout:    15 * time.Second,
		KeepRawEvidence:  true,
	}
	doc, err := collect.New(opts).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !doc.Collection.Partial || doc.Collection.Status != "partial" {
		t.Fatalf("expected partial collection, got status=%s partial=%v", doc.Collection.Status, doc.Collection.Partial)
	}
	found := false
	for _, m := range doc.Modules {
		if m.ModuleID == fail && m.Status == "error" {
			found = true
		}
	}
	if !found {
		t.Fatalf("forced module %s not marked error: %+v", fail, doc.Modules)
	}
}
