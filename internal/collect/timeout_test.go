package collect

import (
	"context"
	"testing"
	"time"

	"github.com/s4e-io/openness-collector/internal/modules/common"
	"github.com/s4e-io/openness-collector/internal/schema"
)

// stuckModule ignores its context, like a module blocked on a read that
// cannot be interrupted.
type stuckModule struct{ id string }

func (m *stuckModule) ID() string          { return m.id }
func (m *stuckModule) Version() string     { return "0" }
func (m *stuckModule) Platforms() []string { return []string{"all"} }
func (m *stuckModule) Run(ctx context.Context) schema.ModuleResult {
	time.Sleep(time.Hour)
	return common.NewResult(m.id, "0")
}

type okModule struct{ id string }

func (m *okModule) ID() string          { return m.id }
func (m *okModule) Version() string     { return "0" }
func (m *okModule) Platforms() []string { return []string{"all"} }
func (m *okModule) Run(ctx context.Context) schema.ModuleResult {
	res := common.NewResult(m.id, "0")
	common.Finish(&res, time.Now(), "success")
	return res
}

func withGrace(t *testing.T, d time.Duration) {
	old := moduleGrace
	moduleGrace = d
	t.Cleanup(func() { moduleGrace = old })
}

func moduleByID(doc *schema.Document, id string) *schema.ModuleResult {
	for i := range doc.Modules {
		if doc.Modules[i].ModuleID == id {
			return &doc.Modules[i]
		}
	}
	return nil
}

func TestModuleTimeoutIsHard(t *testing.T) {
	withGrace(t, 100*time.Millisecond)
	e := &Engine{opts: Options{ModuleTimeout: 200 * time.Millisecond, Timeout: 10 * time.Second}}
	e.modules = []common.Module{&stuckModule{"stuck"}, &okModule{"after"}}
	start := time.Now()
	doc, err := e.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("run took %s", d)
	}
	stuck := moduleByID(doc, "stuck")
	if stuck == nil || stuck.Status != "error" || len(stuck.Errors) == 0 || stuck.Errors[0].Code != "timeout" {
		t.Fatalf("stuck module: %#v", stuck)
	}
	if after := moduleByID(doc, "after"); after == nil || after.Status != "success" {
		t.Fatalf("next module should still run: %#v", after)
	}
	if !doc.Collection.Partial || doc.Collection.Status != "partial" {
		t.Fatalf("collection %#v", doc.Collection)
	}
}

func TestGlobalTimeoutIsHard(t *testing.T) {
	withGrace(t, 100*time.Millisecond)
	// Module timeout longer than the global one: the global deadline wins.
	e := &Engine{opts: Options{ModuleTimeout: time.Hour, Timeout: 300 * time.Millisecond}}
	e.modules = []common.Module{&stuckModule{"stuck"}, &okModule{"never"}}
	start := time.Now()
	doc, err := e.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("run took %s", d)
	}
	for _, id := range []string{"stuck", "never"} {
		m := moduleByID(doc, id)
		if m == nil || m.Status != "error" || m.Errors[0].Code != "timeout" {
			t.Fatalf("%s: %#v", id, m)
		}
	}
	if doc.Collection.Status != "partial" {
		t.Fatalf("status %s", doc.Collection.Status)
	}
}

func TestShrinkLargestModule(t *testing.T) {
	e := &Engine{}
	pk := common.NewResult("packages", "0")
	for i := 0; i < 8; i++ {
		pk.Evidence = append(pk.Evidence, common.Evidence("native", "packages", "observed", map[string]any{"i": i}, nil))
	}
	common.Finish(&pk, time.Now(), "success")
	osr := common.NewResult("os_inventory", "0")
	osr.Evidence = append(osr.Evidence, common.Evidence("native", "os_inventory", "observed", map[string]any{}, nil))
	common.Finish(&osr, time.Now(), "success")
	doc := &schema.Document{Modules: []schema.ModuleResult{osr, pk}, Collection: schema.CollectionInfo{Status: "complete"}}
	e.mergeModule(doc, pk)

	if !e.ShrinkLargestModule(doc) || !e.ShrinkLargestModule(doc) {
		t.Fatal("expected shrink")
	}
	m := doc.Modules[1]
	if len(m.Evidence) != 2 || m.Records != 2 || !m.Truncated || m.Status != "partial" || len(doc.Packages) != 2 {
		t.Fatalf("module %d records=%d truncated=%v status=%s packages=%d", len(m.Evidence), m.Records, m.Truncated, m.Status, len(doc.Packages))
	}
	n := 0
	for _, er := range doc.Errors {
		if er.Code == "output_size_truncated" && er.ModuleID == "packages" {
			n++
		}
	}
	if n != 1 || !doc.Collection.Partial || doc.Collection.Status != "partial" {
		t.Fatalf("errors=%v collection=%#v", doc.Errors, doc.Collection)
	}
	e.ShrinkLargestModule(doc) // packages 2 -> 1
	if e.ShrinkLargestModule(doc) {
		t.Fatal("nothing left to shrink, want false")
	}
}
